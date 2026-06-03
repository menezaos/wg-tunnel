package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

const serverConfTpl = `[Interface]
Address = 10.10.0.1/24
ListenPort = {{.Port}}
PrivateKey = {{.PrivateKey}}
PostUp   = iptables -A FORWARD -i {{.Iface}} -j ACCEPT; iptables -A FORWARD -o {{.Iface}} -j ACCEPT; iptables -t nat -A POSTROUTING -o {{.NetIface}} -j MASQUERADE
PostDown = iptables -D FORWARD -i {{.Iface}} -j ACCEPT; iptables -D FORWARD -o {{.Iface}} -j ACCEPT; iptables -t nat -D POSTROUTING -o {{.NetIface}} -j MASQUERADE
{{range .Peers}}
[Peer]
# {{.Name}}
PublicKey  = {{.PublicKey}}
AllowedIPs = {{.IP}}/32
{{end}}`

const peerConfTpl = `[Interface]
Address    = {{.PeerIP}}/24
PrivateKey = {{.PrivateKey}}
DNS        = 1.1.1.1

[Peer]
PublicKey  = {{.ServerPublicKey}}
Endpoint   = {{.Endpoint}}
AllowedIPs = {{.AllowedIPs}}
PersistentKeepalive = 25
`

type WireGuard struct {
	cfg *Config
	ds  *DataStore
}

func NewWireGuard(cfg *Config, ds *DataStore) *WireGuard {
	return &WireGuard{cfg: cfg, ds: ds}
}

func (w *WireGuard) EnsureKeys() error {
	store := w.ds.Get()
	if store.ServerPrivateKey != "" {
		return nil
	}

	priv, err := runOutput("wg", "genkey")
	if err != nil {
		return fmt.Errorf("genkey: %w", err)
	}
	priv = strings.TrimSpace(priv)

	pub, err := runOutputStdin("wg", "pubkey", priv)
	if err != nil {
		return fmt.Errorf("pubkey: %w", err)
	}
	pub = strings.TrimSpace(pub)

	return w.ds.SetKeys(priv, pub)
}

func (w *WireGuard) GenerateKeypair() (priv, pub string, err error) {
	priv, err = runOutput("wg", "genkey")
	if err != nil {
		return "", "", fmt.Errorf("genkey: %w", err)
	}
	priv = strings.TrimSpace(priv)
	pub, err = runOutputStdin("wg", "pubkey", priv)
	if err != nil {
		return "", "", fmt.Errorf("pubkey: %w", err)
	}
	pub = strings.TrimSpace(pub)
	return
}

func (w *WireGuard) WriteConf() error {
	store := w.ds.Get()

	tpl, err := template.New("server").Parse(serverConfTpl)
	if err != nil {
		return err
	}

	type peerData struct {
		Name      string
		PublicKey string
		IP        string
	}
	var peers []peerData
	for _, p := range store.Peers {
		peers = append(peers, peerData{Name: p.Name, PublicKey: p.PublicKey, IP: p.IP})
	}

	data := map[string]interface{}{
		"Port":       w.cfg.WGPort,
		"PrivateKey": store.ServerPrivateKey,
		"Iface":      w.cfg.WGIface,
		"NetIface":   w.cfg.NetIface,
		"Peers":      peers,
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return err
	}

	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", w.cfg.WGIface)
	return os.WriteFile(confPath, buf.Bytes(), 0600)
}

func (w *WireGuard) Up() error {
	cmd := exec.Command("wg-quick", "up", w.cfg.WGIface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// already up is fine
		if strings.Contains(string(out), "already exists") {
			return w.SyncConf()
		}
		return fmt.Errorf("wg-quick up: %s", out)
	}
	return nil
}

func (w *WireGuard) SyncConf() error {
	if err := w.WriteConf(); err != nil {
		return err
	}

	// wg-quick strip removes PostUp/PostDown lines, leaving only wg-compatible directives
	stripOut, err := exec.Command("wg-quick", "strip", w.cfg.WGIface).Output()
	if err != nil {
		return fmt.Errorf("wg-quick strip: %w", err)
	}

	tmp, err := os.CreateTemp("", "wg-strip-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err = tmp.Write(stripOut); err != nil {
		return err
	}
	tmp.Close()

	out, err := exec.Command("wg", "syncconf", w.cfg.WGIface, tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg syncconf: %s", out)
	}
	return nil
}

func (w *WireGuard) PeerConfig(p Peer) string {
	store := w.ds.Get()

	allowedIPs := "10.10.0.0/24"
	if p.Gateway {
		allowedIPs = "0.0.0.0/0"
	}

	tpl, _ := template.New("peer").Parse(peerConfTpl)
	var buf bytes.Buffer
	tpl.Execute(&buf, map[string]interface{}{
		"PeerIP":          p.IP,
		"PrivateKey":      p.PrivateKey,
		"ServerPublicKey": store.ServerPublicKey,
		"Endpoint":        fmt.Sprintf("%s:%d", w.cfg.VPSPublicIP, w.cfg.WGPort),
		"AllowedIPs":      allowedIPs,
	})
	return buf.String()
}

func (w *WireGuard) Status() (string, error) {
	out, err := exec.Command("wg", "show", w.cfg.WGIface).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func runOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

func runOutputStdin(name string, arg string, stdin string) (string, error) {
	cmd := exec.Command(name, arg)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	return string(out), err
}
