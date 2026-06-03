package main

import "time"

type Peer struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	PublicKey       string    `json:"public_key"`
	PrivateKey      string    `json:"private_key"`
	IP              string    `json:"ip"`
	Gateway         bool      `json:"gateway"`
	AgentToken      string    `json:"agent_token"`
	ExposeProcesses []string  `json:"expose_processes"`
	CreatedAt       time.Time `json:"created_at"`
}

type PortRule struct {
	ID        string    `json:"id"`
	PeerID    string    `json:"peer_id"`
	Proto     string    `json:"proto"`
	Port      int       `json:"port"`
	DestPort  int       `json:"dest_port"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	ServerPrivateKey string     `json:"server_private_key"`
	ServerPublicKey  string     `json:"server_public_key"`
	Peers            []Peer     `json:"peers"`
	PortRules        []PortRule `json:"port_rules"`
}

// PeerPublic é o que a API retorna — nunca expõe a chave privada.
type PeerPublic struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	PublicKey       string    `json:"public_key"`
	IP              string    `json:"ip"`
	Gateway         bool      `json:"gateway"`
	AgentToken      string    `json:"agent_token"`
	ExposeProcesses []string  `json:"expose_processes"`
	CreatedAt       time.Time `json:"created_at"`
}

func (p Peer) Public() PeerPublic {
	return PeerPublic{
		ID:              p.ID,
		Name:            p.Name,
		PublicKey:       p.PublicKey,
		IP:              p.IP,
		Gateway:         p.Gateway,
		AgentToken:      p.AgentToken,
		ExposeProcesses: p.ExposeProcesses,
		CreatedAt:       p.CreatedAt,
	}
}

type Config struct {
	VPSPublicIP string
	WGPort      int
	WebPort     int
	WGSubnet    string
	WGIface     string
	NetIface    string
	DataDir     string
}
