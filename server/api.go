package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type API struct {
	token string
	wg    *WireGuard
	fw    *Firewall
	ds    *DataStore
	mux   *http.ServeMux
}

func NewAPI(token string, wg *WireGuard, fw *Firewall, ds *DataStore) *API {
	a := &API{token: token, wg: wg, fw: fw, ds: ds, mux: http.NewServeMux()}
	a.routes()
	return a
}

func (a *API) Handler() http.Handler {
	return a.mux
}

func (a *API) routes() {
	a.mux.Handle("/", http.FileServer(http.Dir("web")))

	a.mux.HandleFunc("/api/peers", a.auth(a.handlePeers))
	a.mux.HandleFunc("/api/peers/", a.auth(a.handlePeer))
	a.mux.HandleFunc("/api/ports", a.auth(a.handlePorts))
	a.mux.HandleFunc("/api/ports/", a.auth(a.handlePort))
	a.mux.HandleFunc("/api/status", a.auth(a.handleStatus))
	a.mux.HandleFunc("/api/config", a.auth(a.handleConfig))

	// Endpoints do agente — autenticados pelo agent_token do peer
	a.mux.HandleFunc("/api/agent/config", a.handleAgentConfig)
	a.mux.HandleFunc("/api/agent/wgconfig", a.handleAgentWGConfig)
}

func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token != a.token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			return
		}
		next(w, r)
	}
}

func (a *API) handlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		store := a.ds.Get()
		out := make([]PeerPublic, len(store.Peers))
		for i, p := range store.Peers {
			out[i] = p.Public()
		}
		jsonResp(w, out)

	case http.MethodPost:
		var body struct {
			Name    string `json:"name"`
			Gateway bool   `json:"gateway"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}

		ip, err := a.ds.NextPeerIP("")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		priv, pub, err := a.wg.GenerateKeypair()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		peer := Peer{
			ID:              newID(),
			Name:            body.Name,
			PublicKey:       pub,
			PrivateKey:      priv,
			IP:              ip,
			Gateway:         body.Gateway,
			AgentToken:      newID() + newID(),
			ExposeProcesses: []string{},
			CreatedAt:       time.Now(),
		}

		if err := a.ds.AddPeer(peer); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := a.wg.SyncConf(); err != nil {
			fmt.Printf("syncconf warning: %v\n", err)
		}

		w.WriteHeader(http.StatusCreated)
		jsonResp(w, peer.Public())

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handlePeer(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// /api/peers/<id>          → parts: [api, peers, id]
	// /api/peers/<id>/config   → parts: [api, peers, id, config]
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}
	id := parts[2]

	if len(parts) == 4 && parts[3] == "config" {
		a.handlePeerConfig(w, r, id)
		return
	}
	if len(parts) == 4 && parts[3] == "expose" {
		a.handlePeerExpose(w, r, id)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		// Capture peer IP before removal for iptables cleanup
		peer, ok := a.ds.FindPeer(id)
		if !ok {
			http.Error(w, "peer not found", http.StatusNotFound)
			return
		}

		removedRules, err := a.ds.RemovePeer(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		for _, rule := range removedRules {
			a.fw.RemovePortRule(rule, peer.IP)
		}

		if err := a.wg.SyncConf(); err != nil {
			fmt.Printf("syncconf warning: %v\n", err)
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handlePeerExpose(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Processes []string `json:"processes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if body.Processes == nil {
		body.Processes = []string{}
	}
	if err := a.ds.UpdatePeerExpose(id, body.Processes); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	peer, _ := a.ds.FindPeer(id)
	jsonResp(w, peer.Public())
}

func (a *API) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	peer, ok := a.ds.FindPeerByAgentToken(token)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	jsonResp(w, map[string]interface{}{
		"expose_processes": peer.ExposeProcesses,
		"wg_iface":         a.wg.cfg.WGIface,
		"vps_wg_ip":        "10.10.0.1",
	})
}

func (a *API) handlePeerConfig(w http.ResponseWriter, r *http.Request, id string) {
	peer, ok := a.ds.FindPeer(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	conf := a.wg.PeerConfig(peer)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, peer.Name))
	fmt.Fprint(w, conf)
}

func (a *API) handlePorts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		store := a.ds.Get()
		jsonResp(w, store.PortRules)

	case http.MethodPost:
		var body struct {
			PeerID   string `json:"peer_id"`
			Proto    string `json:"proto"`
			Port     int    `json:"port"`
			DestPort int    `json:"dest_port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if body.PeerID == "" || body.Proto == "" || body.Port == 0 {
			http.Error(w, "peer_id, proto, and port are required", http.StatusBadRequest)
			return
		}
		if body.Proto != "tcp" && body.Proto != "udp" {
			http.Error(w, "proto must be tcp or udp", http.StatusBadRequest)
			return
		}

		peer, ok := a.ds.FindPeer(body.PeerID)
		if !ok {
			http.Error(w, "peer not found", http.StatusBadRequest)
			return
		}

		rule := PortRule{
			ID:        newID(),
			PeerID:    body.PeerID,
			Proto:     body.Proto,
			Port:      body.Port,
			DestPort:  body.DestPort,
			CreatedAt: time.Now(),
		}

		if err := a.fw.AddPortRule(rule, peer.IP); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := a.ds.AddPortRule(rule); err != nil {
			a.fw.RemovePortRule(rule, peer.IP)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		jsonResp(w, rule)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handlePort(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		http.NotFound(w, r)
		return
	}
	id := parts[2]

	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rule, err := a.ds.RemovePortRule(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	peer, ok := a.ds.FindPeer(rule.PeerID)
	if ok {
		a.fw.RemovePortRule(rule, peer.IP)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	status, err := a.wg.Status()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	store := a.ds.Get()
	jsonResp(w, map[string]interface{}{
		"wg_output":  status,
		"peer_count": len(store.Peers),
		"rule_count": len(store.PortRules),
	})
}

// handleAgentWGConfig retorna o arquivo .conf do WireGuard do peer, autenticado pelo agent_token.
// Usado pelo cliente Windows para baixar a config sem precisar do token de admin.
func (a *API) handleAgentWGConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	peer, ok := a.ds.FindPeerByAgentToken(token)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, a.wg.PeerConfig(peer))
}

func (a *API) handleConfig(w http.ResponseWriter, r *http.Request) {
	store := a.ds.Get()
	jsonResp(w, map[string]interface{}{
		"server_public_key": store.ServerPublicKey,
		"wg_iface":          a.wg.cfg.WGIface,
		"wg_port":           a.wg.cfg.WGPort,
		"vps_ip":            a.wg.cfg.VPSPublicIP,
		"wg_subnet":         a.wg.cfg.WGSubnet,
	})
}

func jsonResp(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
