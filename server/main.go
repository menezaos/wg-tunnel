package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	cfg := configFromEnv()

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	token, err := loadOrCreateToken(cfg.DataDir)
	if err != nil {
		log.Fatalf("token: %v", err)
	}
	log.Printf("🔑 Token de acesso: %s", token)

	ds, err := NewDataStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	wg := NewWireGuard(cfg, ds)

	if err := wg.EnsureKeys(); err != nil {
		log.Fatalf("wireguard keys: %v", err)
	}

	if err := wg.WriteConf(); err != nil {
		log.Printf("warning: write wg conf: %v", err)
	}

	if err := wg.Up(); err != nil {
		log.Printf("warning: wg up: %v", err)
	}

	fw := NewFirewall(cfg.NetIface, cfg.WGIface)

	// Re-apply all stored port rules on startup
	store := ds.Get()
	peerByID := map[string]Peer{}
	for _, p := range store.Peers {
		peerByID[p.ID] = p
	}
	fw.ApplyAll(store.PortRules, peerByID)

	api := NewAPI(token, wg, fw, ds)

	log.Printf("Painel web em http://0.0.0.0:8080")
	log.Fatal(http.ListenAndServe(":8080", api.Handler()))
}

func configFromEnv() *Config {
	dataDir := envOr("DATA_DIR", "/data")
	wgPort, _ := strconv.Atoi(envOr("WG_PORT", "51820"))
	if wgPort == 0 {
		wgPort = 51820
	}
	return &Config{
		VPSPublicIP: envOr("VPS_PUBLIC_IP", ""),
		WGPort:      wgPort,
		WGSubnet:    envOr("WG_SUBNET", "10.10.0.0/24"),
		WGIface:     envOr("WG_IFACE", "wg0"),
		NetIface:    envOr("NET_IFACE", "eth0"),
		DataDir:     dataDir,
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadOrCreateToken(dataDir string) (string, error) {
	path := dataDir + "/token.txt"
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		return string(data), nil
	}
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(token)
	if err := os.WriteFile(path, []byte(tok), 0600); err != nil {
		return "", fmt.Errorf("save token: %w", err)
	}
	return tok, nil
}
