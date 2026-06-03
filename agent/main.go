package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	cgroupBase = "/sys/fs/cgroup/net_cls/wgtunnel"
	classID    = "0x100001"
)

var (
	serverURL = envOr("SERVER_URL", "")
	agentToken = envOr("AGENT_TOKEN", "")
	wgIface   = envOr("WG_IFACE", "wg0")
	vpsWGIP   = envOr("VPS_WG_IP", "10.10.0.1")
	rtTable   = envOr("RT_TABLE", "200")
	fwmark    = envOr("FWMARK", "0x64")
	pollSecs  = envOrInt("POLL_INTERVAL", 10)
)

type agentConfig struct {
	ExposeProcesses []string `json:"expose_processes"`
	WGIface         string   `json:"wg_iface"`
	VPSWgIP         string   `json:"vps_wg_ip"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "daemon":
		runDaemon()
	case "setup":
		must(setup(), "setup")
		fmt.Println("✓ Policy routing configurado")
	case "teardown":
		teardown()
		fmt.Println("✓ Policy routing removido")
	case "status":
		printStatus()
	default:
		usage()
		os.Exit(1)
	}
}

// ── Daemon ───────────────────────────────────────────────────────────────────

func runDaemon() {
	if serverURL == "" || agentToken == "" {
		log.Fatal("SERVER_URL e AGENT_TOKEN são obrigatórios para o modo daemon")
	}

	log.Printf("wgtunnel-agent daemon iniciado — server: %s, poll: %ds", serverURL, pollSecs)

	if err := setup(); err != nil {
		log.Printf("aviso: setup do policy routing: %v", err)
	}

	for {
		if err := syncExpose(); err != nil {
			log.Printf("erro ao sincronizar: %v", err)
		}
		time.Sleep(time.Duration(pollSecs) * time.Second)
	}
}

func fetchConfig() (*agentConfig, error) {
	req, err := http.NewRequest("GET", serverURL+"/api/agent/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+agentToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server retornou %d", resp.StatusCode)
	}

	var cfg agentConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func syncExpose() error {
	cfg, err := fetchConfig()
	if err != nil {
		return fmt.Errorf("fetchConfig: %w", err)
	}

	// Processos que o server quer expor
	desired := map[string]bool{}
	for _, name := range cfg.ExposeProcesses {
		desired[name] = true
	}

	// PIDs atualmente no cgroup wgtunnel, indexados por nome de processo
	current, err := currentExposed()
	if err != nil {
		// cgroup pode não existir ainda — ok
		current = map[int]string{}
	}

	// Expor novos processos
	for name := range desired {
		pids, err := pgrep(name)
		if err != nil || len(pids) == 0 {
			log.Printf("processo '%s' não encontrado, aguardando...", name)
			continue
		}
		for _, pid := range pids {
			if _, alreadyExposed := current[pid]; !alreadyExposed {
				if err := addToExposeCgroup(pid); err != nil {
					log.Printf("erro ao expor PID %d (%s): %v", pid, name, err)
				} else {
					log.Printf("exposto: %s (PID %d)", name, pid)
				}
			}
		}
	}

	// Remover processos que não devem mais ser expostos
	for pid, name := range current {
		if !desired[name] {
			if err := removeFromExposeCgroup(pid); err != nil {
				log.Printf("erro ao remover PID %d (%s): %v", pid, name, err)
			} else {
				log.Printf("removido da exposição: %s (PID %d)", name, pid)
			}
		}
	}

	return nil
}

// currentExposed retorna map[pid]processName de todos os PIDs no cgroup wgtunnel
func currentExposed() (map[int]string, error) {
	data, err := os.ReadFile(cgroupBase + "/cgroup.procs")
	if err != nil {
		return nil, err
	}
	result := map[int]string{}
	for _, line := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		result[pid] = strings.TrimSpace(string(comm))
	}
	return result, nil
}

func pgrep(name string) ([]int, error) {
	out, err := exec.Command("pgrep", "-x", name).Output()
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, s := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(s); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func addToExposeCgroup(pid int) error {
	if err := os.MkdirAll(cgroupBase, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(cgroupBase+"/net_cls.classid", []byte(classID), 0644); err != nil {
		return err
	}
	return os.WriteFile(cgroupBase+"/cgroup.procs", []byte(strconv.Itoa(pid)), 0644)
}

func removeFromExposeCgroup(pid int) error {
	// Move de volta para o cgroup raiz
	return os.WriteFile("/sys/fs/cgroup/net_cls/cgroup.procs",
		[]byte(strconv.Itoa(pid)), 0644)
}

// ── Setup / Teardown ─────────────────────────────────────────────────────────

func setup() error {
	run("ip", "route", "add", "default", "dev", wgIface, "via", vpsWGIP, "table", rtTable)
	run("ip", "rule", "add", "fwmark", fwmark, "table", rtTable)

	if err := os.MkdirAll(cgroupBase, 0755); err != nil {
		return fmt.Errorf("cgroup mkdir: %w", err)
	}
	if err := os.WriteFile(cgroupBase+"/net_cls.classid", []byte(classID), 0644); err != nil {
		return fmt.Errorf("set classid: %w", err)
	}

	// Remove antes de adicionar para não duplicar
	run("iptables", "-t", "mangle", "-D", "OUTPUT",
		"-m", "cgroup", "--cgroup", classID, "-j", "MARK", "--set-mark", fwmark)

	out, err := exec.Command("iptables", "-t", "mangle", "-A", "OUTPUT",
		"-m", "cgroup", "--cgroup", classID, "-j", "MARK", "--set-mark", fwmark).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables: %s", out)
	}
	return nil
}

func teardown() {
	run("ip", "rule", "del", "fwmark", fwmark, "table", rtTable)
	run("ip", "route", "del", "default", "dev", wgIface, "table", rtTable)
	run("iptables", "-t", "mangle", "-D", "OUTPUT",
		"-m", "cgroup", "--cgroup", classID, "-j", "MARK", "--set-mark", fwmark)
}

// ── Status ───────────────────────────────────────────────────────────────────

func printStatus() {
	fmt.Printf("Servidor     : %s\n", serverURL)
	fmt.Printf("Interface WG : %s\n", wgIface)
	fmt.Printf("VPS WG IP    : %s\n", vpsWGIP)

	fmt.Println("\n── wg show ──────────────────────────────────")
	out, _ := exec.Command("wg", "show", wgIface).Output()
	if len(out) > 0 {
		fmt.Print(string(out))
	} else {
		fmt.Println("(interface não ativa)")
	}

	fmt.Println("\n── Processos expostos ───────────────────────")
	exposed, err := currentExposed()
	if err != nil || len(exposed) == 0 {
		fmt.Println("(nenhum)")
		return
	}
	for pid, name := range exposed {
		fmt.Printf("  PID %-6d %s\n", pid, name)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func run(name string, args ...string) {
	exec.Command(name, args...).Run()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func must(err error, ctx string) {
	if err != nil {
		log.Fatalf("%s: %v", ctx, err)
	}
}

func usage() {
	fmt.Print(`wgtunnel-agent — agente do homelab para WG Tunnel

Uso:
  wgtunnel-agent daemon     Inicia o daemon (recomendado, via systemd)
  wgtunnel-agent setup      Configura policy routing manualmente
  wgtunnel-agent teardown   Remove policy routing
  wgtunnel-agent status     Exibe estado atual

Variáveis de ambiente:
  SERVER_URL      URL do servidor WG Tunnel (ex: http://1.2.3.4:8080)
  AGENT_TOKEN     Token do peer gerado no painel
  WG_IFACE        Interface WireGuard (padrão: wg0)
  VPS_WG_IP       IP da VPS no túnel (padrão: 10.10.0.1)
  RT_TABLE        Tabela de roteamento (padrão: 200)
  FWMARK          Fwmark para policy routing (padrão: 0x64)
  POLL_INTERVAL   Segundos entre polls do servidor (padrão: 10)
`)
}
