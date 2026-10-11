package policy

import (
	"fmt"
	"strings"
)

// Services on the host that should not face the internet, described rather
// than graded.
//
// They are not part of the transport this check grades, and a verdict about
// TLS that moved because a database answers on another port would be a
// verdict about something else. So they are said on a line of their own, and
// every one that answers gets a note saying what it is and what to do.

// ExposedService is one service that answered.
type ExposedService struct {
	Address string
	Port    int
	Name    string
	Why     string
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
	var names []string
	seen := map[int]bool{}
	for _, o := range open {
		if !seen[o.Port] {
			seen[o.Port] = true
			names = append(names, fmt.Sprintf("%s (%d)", o.Name, o.Port))
		}
	}
	verb := " answers"
	if len(names) > 1 {
		verb = " answer"
	}
	return list(names) + verb + " to anybody on the internet"
}

// DescribeExposure is one note per service that answered.
func DescribeExposure(open []ExposedService) []Note {
	var out []Note
	seen := map[int]bool{}
	for _, o := range open {
		if seen[o.Port] {
			continue
		}
		seen[o.Port] = true
		var at []string
		for _, p := range open {
			if p.Port == o.Port {
				at = append(at, p.Address)
			}
		}
		out = append(out, Observed(fmt.Sprintf("%s answers on port %d at %s: %s. Close the port at the "+
			"firewall, or reach the service over a VPN.", o.Name, o.Port, strings.Join(at, " and "), o.Why)))
	}
	return out
}
