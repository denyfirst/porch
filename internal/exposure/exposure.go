// Package exposure asks whether a host answers on the ports of services that
// should never face the internet.
//
// Remote desktop, file sharing, databases, a container engine's API: each is
// how a small organisation is most often broken into, and each is found by
// whoever looks, because looking is a connection and nothing more. This looks
// the same way, at the operator's own host, so they find it first.
//
// # What it does, and nothing else
//
// A fixed list of twenty-one ports, at most two addresses of the host — the
// ones the scan already reached — and for each, one TCP connection, closed the
// moment it opens. Nothing is sent over it: no banner is read, no protocol is
// spoken, no login is tried. A port that answers is open; one that refuses or
// says nothing in time is not, and the two are not told apart, because a
// firewall that drops is doing its job.
//
// It is not a port sweep. The list is written here, it names services rather
// than ranges, and no flag widens it. Connections go through safedial, which
// refuses private, loopback and reserved addresses, so a name that resolves
// inward is not a way to look at somebody's internal network. And it runs
// only where a scan may reach the host at all: a proven domain, the command
// line, or the demonstration's own.
package exposure

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/denyfirst/porch/internal/safedial"
)

// Service is one port that should not answer the internet, and why.
type Service struct {
	Port int    `json:"port"`
	Name string `json:"name"`

	// Why is the sentence a report gives for it.
	Why string `json:"-"`
}

// Services is the list. Fixed, and the whole of what is asked.
var Services = []Service{
	{21, "FTP", "it sends passwords unencrypted"},
	{23, "Telnet", "it sends passwords unencrypted"},
	{139, "NetBIOS", "Windows file sharing is not meant for the internet"},
	{445, "SMB", "Windows file sharing is not meant for the internet, and is how WannaCry spread"},
	{873, "rsync", "an rsync daemon often serves whole directories to anybody who asks, with no password"},
	{1433, "Microsoft SQL Server", "a database should be reached from the application, not the internet"},
	{1521, "Oracle Database", "a database should be reached from the application, not the internet"},
	{2049, "NFS", "a network file system hands out disks, and is not meant for the internet"},
	{2375, "Docker API", "without TLS it hands control of the host to anybody who connects"},
	{2379, "etcd", "it holds a cluster's configuration and secrets, and often answers without authentication"},
	{3306, "MySQL", "a database should be reached from the application, not the internet"},
	{3389, "Remote Desktop", "it is the most common way into a small organisation's network"},
	{5432, "PostgreSQL", "a database should be reached from the application, not the internet"},
	{5900, "VNC", "remote control of a desktop, often with a weak password or none"},
	{5984, "CouchDB", "older versions have no password by default, and open ones are copied and wiped"},
	{5985, "WinRM", "remote administration of Windows is not meant for the internet"},
	{6379, "Redis", "it often has no password, and an open one is taken over in minutes"},
	{9200, "Elasticsearch", "it often has no password, and open ones are copied and wiped"},
	{10250, "Kubernetes kubelet", "with anonymous access left on, it runs commands in any container on the node"},
	{11211, "Memcached", "it has no authentication and is used to amplify attacks"},
	{27017, "MongoDB", "it often has no password, and open ones are copied and wiped"},
}

const (
	// maxAddresses bounds how many of the host's addresses are asked.
	maxAddresses = 2

	// connectTimeout is how long one connection may take to open. A port
	// that says nothing in that time is not open to this scan.
	connectTimeout = 2 * time.Second
)

// Open is one service that answered.
type Open struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Name    string `json:"name"`
}

// Result is what was found.
type Result struct {
	// Asked is false when nothing was asked.
	Asked bool `json:"asked"`

	// Addresses are the addresses asked, and Ports how many ports each.
	Addresses []string `json:"addresses,omitempty"`
	Ports     int      `json:"ports"`

	// Open are the services that answered, by port.
	Open []Open `json:"open,omitempty"`

	// Reason says why nothing was established.
	Reason string `json:"reason,omitempty"`
}

// Prober asks.
type Prober struct {
	// Dial opens connections. Nil selects safedial, restricted to the ports
	// on the list.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Probe asks each port on the list at up to two of the addresses given: the
// first IPv4 and the first IPv6.
func (p *Prober) Probe(ctx context.Context, addresses []string) Result {
	picked := pick(addresses)
	if len(picked) == 0 {
		return Result{Asked: true, Reason: "no address of the host was reached to ask"}
	}

	dial := p.Dial
	if dial == nil {
		ports := make([]string, 0, len(Services))
		for _, s := range Services {
			ports = append(ports, strconv.Itoa(s.Port))
		}
		d := &safedial.Dialer{Timeout: connectTimeout, TotalTimeout: connectTimeout, MaxAddrs: 1, AllowedPorts: ports}
		dial = d.DialContext
	}

	out := Result{Asked: true, Ports: len(Services)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, addr := range picked {
		out.Addresses = append(out.Addresses, addr.String())
		for _, s := range Services {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cctx, cancel := context.WithTimeout(ctx, connectTimeout)
				defer cancel()
				conn, err := dial(cctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(s.Port)))
				if err != nil {
					return
				}
				_ = conn.Close()
				mu.Lock()
				out.Open = append(out.Open, Open{Address: addr.String(), Port: s.Port, Name: s.Name})
				mu.Unlock()
			}()
		}
	}
	wg.Wait()

	sort.Slice(out.Open, func(i, j int) bool {
		if out.Open[i].Port != out.Open[j].Port {
			return out.Open[i].Port < out.Open[j].Port
		}
		return out.Open[i].Address < out.Open[j].Address
	})
	return out
}

// pick takes the first IPv4 and the first IPv6 address, from addresses that
// may carry a port.
func pick(addresses []string) []netip.Addr {
	var v4, v6 netip.Addr
	for _, a := range addresses {
		host := a
		if h, _, err := net.SplitHostPort(a); err == nil {
			host = h
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		switch {
		case addr.Is4() && !v4.IsValid():
			v4 = addr
		case addr.Is6() && !v6.IsValid():
			v6 = addr
		}
	}
	var out []netip.Addr
	for _, a := range []netip.Addr{v4, v6} {
		if a.IsValid() && len(out) < maxAddresses {
			out = append(out, a)
		}
	}
	return out
}

// WhyOpen is the sentence for a service on the list.
func WhyOpen(port int) string {
	for _, s := range Services {
		if s.Port == port {
			return s.Why
		}
	}
	return ""
}
