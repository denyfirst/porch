package policy

import "strings"

// Checked is one thing a check asked about by name, and what came back.
//
// A line like "none of the 11 checked is served" is a count, and a count says
// nothing about what it counted: a reader cannot tell whether /.env was on the
// list, or which of the ports a firewall dropped. So the report carries the
// list itself, in the words both faces print (R16), and what was not on it is
// as visible as what was (R4).
//
// Built here and nowhere else. The state is a sentence about what this scan
// measured, never a stronger claim: a port that stayed silent is "no answer
// from here", because a firewall, a network between here and the host, or a
// provider that blocks the port outbound all look the same from this side.
type Checked struct {
	// Item is what was asked for: a path, or a port.
	Item string `json:"item"`

	// What says what the item is, in a few words.
	What string `json:"what,omitempty"`

	// State is what came back.
	State string `json:"state"`

	// Found marks the one a reader has to act on: a file that was served, a
	// service that answered.
	Found bool `json:"found,omitempty"`
}

// FileAsked is one path the leaks check asked for, and what came back.
type FileAsked struct {
	Path     string
	What     string
	Answered bool
	Served   bool
}

// The states a file can be in. A path the site answered with something other
// than the file is "not served"; one that got no answer at all is said as
// that, because a timeout is not evidence the file is absent.
const (
	FileServed    = "served"
	FileNotServed = "not served"
	FileNoAnswer  = "no answer"
)

// LeaksChecked lists every path asked for, in the order asked.
func LeaksChecked(files []FileAsked) []Checked {
	out := make([]Checked, 0, len(files))
	for _, f := range files {
		c := Checked{Item: f.Path, What: f.What, State: FileNotServed}
		switch {
		case !f.Answered:
			c.State = FileNoAnswer
		case f.Served:
			c.State, c.Found = FileServed, true
		}
		out = append(out, c)
	}
	return out
}

// ServiceAsked is one port the exposure check asked, and the addresses it
// answered at.
type ServiceAsked struct {
	Port       string
	Name       string
	AnsweredAt []string
}

// ServiceNoAnswer is the state of a port that did not answer. Never "closed":
// that is a claim about the host, and this is all that was seen from here.
const ServiceNoAnswer = "no answer from here"

// ExposureChecked lists every service asked, in the order asked, and where
// each one that answered did.
func ExposureChecked(services []ServiceAsked) []Checked {
	out := make([]Checked, 0, len(services))
	for _, s := range services {
		c := Checked{Item: s.Port, What: s.Name, State: ServiceNoAnswer}
		if len(s.AnsweredAt) > 0 {
			c.State, c.Found = "answers at "+strings.Join(s.AnsweredAt, " and "), true
		}
		out = append(out, c)
	}
	return out
}
