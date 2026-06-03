package main

import (
	"fmt"
	"os/exec"
	"strconv"
)

type Firewall struct {
	netIface string
	wgIface  string
}

func NewFirewall(netIface, wgIface string) *Firewall {
	return &Firewall{netIface: netIface, wgIface: wgIface}
}

func (f *Firewall) AddPortRule(r PortRule, peerIP string) error {
	destPort := r.DestPort
	if destPort == 0 {
		destPort = r.Port
	}
	comment := "wgtunnel:" + r.ID

	// PREROUTING DNAT: incoming traffic on VPS port → peer
	if err := iptables("-t", "nat", "-A", "PREROUTING",
		"-p", r.Proto,
		"--dport", strconv.Itoa(r.Port),
		"-j", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%d", peerIP, destPort),
		"-m", "comment", "--comment", comment,
	); err != nil {
		return fmt.Errorf("DNAT rule: %w", err)
	}

	// Allow forwarded traffic from wg to peer
	if err := iptables("-A", "FORWARD",
		"-p", r.Proto,
		"-d", peerIP,
		"--dport", strconv.Itoa(destPort),
		"-j", "ACCEPT",
		"-m", "comment", "--comment", comment,
	); err != nil {
		return fmt.Errorf("FORWARD rule: %w", err)
	}

	return nil
}

func (f *Firewall) RemovePortRule(r PortRule, peerIP string) error {
	destPort := r.DestPort
	if destPort == 0 {
		destPort = r.Port
	}
	comment := "wgtunnel:" + r.ID

	iptables("-t", "nat", "-D", "PREROUTING",
		"-p", r.Proto,
		"--dport", strconv.Itoa(r.Port),
		"-j", "DNAT",
		"--to-destination", fmt.Sprintf("%s:%d", peerIP, destPort),
		"-m", "comment", "--comment", comment,
	)

	iptables("-D", "FORWARD",
		"-p", r.Proto,
		"-d", peerIP,
		"--dport", strconv.Itoa(destPort),
		"-j", "ACCEPT",
		"-m", "comment", "--comment", comment,
	)

	return nil
}

func (f *Firewall) ApplyAll(rules []PortRule, peerByID map[string]Peer) {
	for _, r := range rules {
		p, ok := peerByID[r.PeerID]
		if !ok {
			continue
		}
		f.AddPortRule(r, p.IP)
	}
}

func iptables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, out)
	}
	return nil
}
