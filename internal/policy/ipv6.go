package policy

import "strconv"

// Whether the names a domain depends on can be reached over IPv6: the name
// itself and its name servers on the DNS check, the mail exchangers on the
// mail check. Each publishes an IPv6 address or it does not.
//
// Reported and never graded. RFC 3901 asks that every zone stay reachable
// over IPv4 and leaves IPv6 to the operator, so no document draws a line here
// (R21). The line is built once, here, so the page and the terminal say the
// same words (R16).

// DNSIPv6Line says it for the name and its name servers, and is empty where
// neither was read.
func DNSIPv6Line(f DNSFacts) string {
	name := ""
	if f.AddressReason == "" {
		name = "the name has no IPv6 address"
		if len(f.IPv6) > 0 {
			name = "the name has an IPv6 address"
		}
	}

	servers, verb := "", "have"
	if f.NSReason == "" {
		read, have := 0, 0
		for _, ns := range f.NameServers {
			if ns.Reason != "" {
				continue
			}
			read++
			if hasIPv6(ns.Addresses) {
				have++
			}
		}
		if read > 0 {
			servers = strconv.Itoa(have) + " of " + strconv.Itoa(read) + " name servers"
			if read == 1 {
				servers, verb = strconv.Itoa(have)+" of 1 name server", "has"
			}
		}
	}

	switch {
	case name != "" && servers != "":
		return name + "; " + servers + " " + verb + " one"
	case name != "":
		return name
	case servers != "":
		return servers + " " + verb + " an IPv6 address"
	default:
		return ""
	}
}

// MailIPv6Line says it for the exchangers, and is empty where none was asked.
func MailIPv6Line(f MailFacts) string {
	if f.MXIPv6Read == 0 {
		return ""
	}
	noun := " exchangers have"
	if f.MXIPv6Read == 1 {
		noun = " exchanger has"
	}
	line := strconv.Itoa(len(f.MXIPv6)) + " of " + strconv.Itoa(f.MXIPv6Read) + noun + " an IPv6 address"
	if unread := f.MXIPv6Asked - f.MXIPv6Read; unread > 0 {
		line += "; " + strconv.Itoa(unread) + " not read"
	}
	return line
}

func hasIPv6(addresses []string) bool {
	for _, a := range addresses {
		for i := 0; i < len(a); i++ {
			if a[i] == ':' {
				return true
			}
		}
	}
	return false
}
