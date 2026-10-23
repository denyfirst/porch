package policy

import (
	"fmt"
	"slices"
	"strings"
)

// Services on the host that should not face the internet.
//
// Described and not graded until porch-tls-v9, on the argument that a TLS
// verdict moving because a database answers on another port is a verdict
// about something else. The argument was about the page and not the host: a
// report reading strong over a host with Remote Desktop open to everybody
// tells its reader the host is in good order, and it is not. CISA's
// performance goals name exactly this as a goal of its own. So an open
// service is a weak finding beside the transport's, on the line it always had.
//
// A connection that opens is the whole of the evidence, and one thing makes
// it worth nothing: a host, or a firewall in front of it, that completes every
// connection whatever the port. A SYN proxy under load does that, and so do
// tarpits. Twenty-one services on one machine is not a configuration anybody
// runs, so an address where every port asked answered is said to accept
// everything, and none of its ports is graded or named as a service.

var (
	cisaCPG = Reference{"CISA Cross-Sector Cybersecurity Performance Goals — 2.W, no exploitable services on the internet",
		"https://www.cisa.gov/cross-sector-cybersecurity-performance-goals"}
	nist80041 = Reference{"NIST SP 800-41 Rev. 1 — Guidelines on Firewalls and Firewall Policy",
		"https://csrc.nist.gov/pubs/sp/800/41/r1/final"}
)

// ExposedService is one service that answered.
type ExposedService struct {
	Address string
	Port    int
	Name    string
	Why     string
}

// splitExposure separates the services that answered from the addresses at
// which everything did.
//
// One port is not "everything": a list of one would make every open service
// an address that accepts everything, and nothing would ever be graded.
func splitExposure(open []ExposedService, ports int) (services []ExposedService, everything []string) {
	count := map[string]map[int]bool{}
	for _, o := range open {
		if count[o.Address] == nil {
			count[o.Address] = map[int]bool{}
		}
		count[o.Address][o.Port] = true
	}
	for _, o := range open {
		if ports > 1 && len(count[o.Address]) >= ports {
			if !slices.Contains(everything, o.Address) {
				everything = append(everything, o.Address)
			}
			continue
		}
		services = append(services, o)
	}
	return services, everything
}

// ExposureLine says what answered, in one line.
func ExposureLine(asked bool, ports int, open []ExposedService, reason string) string {
	switch {
	case !asked:
		return ""
	case reason != "":
		return "not established: " + reason
	case len(open) == 0:
		return fmt.Sprintf("none of the %d services checked answers", ports)
	}
	services, everything := splitExposure(open, ports)
	var parts []string
	if names := serviceNames(services); len(names) > 0 {
		verb := " answers"
		if len(names) > 1 {
			verb = " answer"
		}
		parts = append(parts, list(names)+verb+" to anybody on the internet")
	}
	if len(everything) > 0 {
		parts = append(parts, fmt.Sprintf("every one of the %d ports checked accepts a connection at %s, so "+
			"which services are there is not established", ports, list(everything)))
	}
	return strings.Join(parts, "; ")
}

func serviceNames(services []ExposedService) []string {
	var names []string
	seen := map[int]bool{}
	for _, o := range services {
		if !seen[o.Port] {
			seen[o.Port] = true
			names = append(names, fmt.Sprintf("%s (%d)", o.Name, o.Port))
		}
	}
	return names
}

// GradeExposure is the finding for the services that answered, or nothing.
//
// One finding for all of them, naming each: findings are kept once per rule,
// and a second open service is not a second kind of problem.
func GradeExposure(open []ExposedService, ports int) []Finding {
	services, _ := splitExposure(open, ports)
	names := serviceNames(services)
	if len(names) == 0 {
		return nil
	}
	verb := " answers"
	if len(names) > 1 {
		verb = " answer"
	}
	return []Finding{{
		RuleID:  "exposure.service-open",
		Verdict: Weak,
		Title:   list(names) + verb + " to anybody on the internet",
		Rationale: "Databases, remote desktops, file shares and administration ports facing the internet are how " +
			"small organisations are most often broken into, and they are found by anybody who looks. CISA's " +
			"performance goals ask that no such service be reachable from the internet, and NIST SP 800-41 " +
			"says to deny inbound traffic that is not explicitly needed. Close the port at the firewall, or " +
			"reach the service over a VPN.",
		References: []Reference{cisaCPG, nist80041},
		Policy:     TLSVersion,
	}}
}

// DescribeExposure is one note per service that answered, and one per
// address that accepted every connection.
func DescribeExposure(open []ExposedService, ports int) []Note {
	services, everything := splitExposure(open, ports)
	var out []Note
	seen := map[int]bool{}
	for _, o := range services {
		if seen[o.Port] {
			continue
		}
		seen[o.Port] = true
		var at []string
		for _, p := range services {
			if p.Port == o.Port {
				at = append(at, p.Address)
			}
		}
		out = append(out, Observed(fmt.Sprintf("%s answers on port %d at %s: %s. Close the port at the "+
			"firewall, or reach the service over a VPN.", o.Name, o.Port, strings.Join(at, " and "), o.Why)))
	}
	for _, addr := range everything {
		out = append(out, Unsettled(fmt.Sprintf("Every one of the %d ports checked accepted a connection at %s. "+
			"That is what a host or firewall completing every connection does, whatever is behind it, so which "+
			"of these services really answers there is not established and none is graded.", ports, addr)))
	}
	return out
}
