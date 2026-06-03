package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type DataStore struct {
	mu   sync.RWMutex
	path string
	data Store
}

func NewDataStore(dataDir string) (*DataStore, error) {
	ds := &DataStore{path: filepath.Join(dataDir, "store.json")}
	if err := ds.load(); err != nil {
		return nil, err
	}
	return ds, nil
}

func (ds *DataStore) load() error {
	data, err := os.ReadFile(ds.path)
	if os.IsNotExist(err) {
		ds.data = Store{}
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &ds.data)
}

func (ds *DataStore) save() error {
	data, err := json.MarshalIndent(ds.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := ds.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, ds.path)
}

func (ds *DataStore) Get() Store {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.data
}

func (ds *DataStore) SetKeys(priv, pub string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.data.ServerPrivateKey = priv
	ds.data.ServerPublicKey = pub
	return ds.save()
}

func (ds *DataStore) AddPeer(p Peer) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.data.Peers = append(ds.data.Peers, p)
	return ds.save()
}

func (ds *DataStore) RemovePeer(id string) ([]PortRule, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	var removed []PortRule
	newRules := ds.data.PortRules[:0]
	for _, r := range ds.data.PortRules {
		if r.PeerID == id {
			removed = append(removed, r)
		} else {
			newRules = append(newRules, r)
		}
	}
	ds.data.PortRules = newRules

	newPeers := ds.data.Peers[:0]
	found := false
	for _, p := range ds.data.Peers {
		if p.ID == id {
			found = true
		} else {
			newPeers = append(newPeers, p)
		}
	}
	if !found {
		return nil, fmt.Errorf("peer not found")
	}
	ds.data.Peers = newPeers
	return removed, ds.save()
}

func (ds *DataStore) FindPeer(id string) (Peer, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for _, p := range ds.data.Peers {
		if p.ID == id {
			return p, true
		}
	}
	return Peer{}, false
}

func (ds *DataStore) FindPeerByAgentToken(token string) (Peer, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for _, p := range ds.data.Peers {
		if p.AgentToken == token {
			return p, true
		}
	}
	return Peer{}, false
}

func (ds *DataStore) UpdatePeerExpose(id string, processes []string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for i, p := range ds.data.Peers {
		if p.ID == id {
			ds.data.Peers[i].ExposeProcesses = processes
			return ds.save()
		}
	}
	return fmt.Errorf("peer not found")
}

func (ds *DataStore) AddPortRule(r PortRule) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.data.PortRules = append(ds.data.PortRules, r)
	return ds.save()
}

func (ds *DataStore) RemovePortRule(id string) (PortRule, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for i, r := range ds.data.PortRules {
		if r.ID == id {
			ds.data.PortRules = append(ds.data.PortRules[:i], ds.data.PortRules[i+1:]...)
			return r, ds.save()
		}
	}
	return PortRule{}, fmt.Errorf("rule not found")
}

func (ds *DataStore) FindPortRule(id string) (PortRule, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for _, r := range ds.data.PortRules {
		if r.ID == id {
			return r, true
		}
	}
	return PortRule{}, false
}

func (ds *DataStore) NextPeerIP(subnet string) (string, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	used := map[string]bool{"10.10.0.1": true}
	for _, p := range ds.data.Peers {
		used[p.IP] = true
	}
	for i := 2; i < 255; i++ {
		ip := fmt.Sprintf("10.10.0.%d", i)
		if !used[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no available IPs in subnet")
}
