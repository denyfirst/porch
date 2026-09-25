package webprobe

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// CounterpartFacts is what the other form of the name does — the `www` form of
// a name without one, or the name underneath a `www` that has it.
//
// The question is one an operator cannot ask of their own site, because their
// own habit answers it for them: whoever types the apex every day never finds
// out what happens to somebody who types `www`, and whoever bookmarked `www`
// never finds out what happens at the apex. Both forms are in every visitor's
// muscle memory and only one of them is ever tested.
//
// What this is not is a search for names. One name is derived from the one that
// was asked about, by adding four characters or removing them, and nothing else
// is looked up. A scanner that went hunting for `mail`, `dev`, `staging` and
// `old` would be enumerating somebody's estate, which is a different tool with
// a different argument for existing (N7).
type CounterpartFacts struct {
	// Asked reports that this was measured.
	Asked bool

	// Name is the form that was compared, so that a reader can see which
	// question was answered rather than working it out from the host.
	Name string `json:"name,omitempty"`

	// Refused reports that this deployment may not reach that name, so nothing
	// about it was measured. A demonstration build reaches a fixed list, and a
	// service reaches what it has been shown control of; the other form of a
	// name is not automatically either (N6, N9).
	Refused bool `json:"refused,omitempty"`

	// Answered reports that it returned a response.
	Answered bool `json:"answered,omitempty"`

	// Status is what it answered with, where it answered.
	Status int `json:"status,omitempty"`

	// SendsTo is the host its first response points at, where that response
	// was a redirect. Empty where it answered with content or did not answer.
	//
	// A host rather than an address: this is the one piece of somebody else's
	// response that is kept, and a path or a query from it would be kept text
	// chosen by whoever is being measured.
	SendsTo string `json:"sendsTo,omitempty"`

	// Reason says the shape of the failure, where there was one.
	Reason string `json:"reason,omitempty"`
}

// counterpartName is the other form of a name: with `www.` where it has none,
// and without where it has one.
//
// Adding and removing four characters is the whole of it. The apex of a name is
// a different question — `example.co.uk` has three labels and `example.com` has
// two, and telling them apart needs the public suffix list, which is a
// third-party list this project does not carry and will not invent a copy of.
// So nothing here claims to have found an apex. It compares the two forms
// every visitor's fingers produce, says which one it compared, and leaves the
// reader to judge whether that was the interesting pair.
func counterpartName(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if rest, ok := strings.CutPrefix(host, "www."); ok {
		return rest
	}
	return "www." + host
}

// counterpart asks the other form of the name for its root, once, and does not
// follow what it says.
//
// One response is enough for every answer this reports. A redirect names where
// it is sending a visitor in its own Location header, so following it would buy
// nothing but another connection to somebody's server — and where it answers
// with content, that is already the finding: two names serving two sites, with
// nothing joining them.
func (p *Prober) counterpart(ctx context.Context, client *http.Client, host string, w *walk) CounterpartFacts {
	name := counterpartName(host)
	out := CounterpartFacts{Asked: true, Name: name}

	if why := w.may(ctx, name); why != "" {
		// Not a failure and not a fault. This deployment was told which names
		// it may reach and that one is not among them, which the row says
		// rather than leaving a reader to read silence as agreement (R4).
		out.Refused = true
		return out
	}

	hop := p.fetch(ctx, client, "https://"+net.JoinHostPort(name, securePort)+"/")
	if hop.Err != "" {
		// Every cause gets one phrase. A name that does not exist, a
		// certificate that did not verify and a connection refused are all
		// "the other form of the name could not be reached" here, because the
		// row is about whether the two forms agree and the operator's next
		// step is to look at that name properly.
		out.Reason = "could not be reached"
		return out
	}

	out.Answered, out.Status = true, hop.Status
	var location string
	if values := hop.Headers["Location"]; len(values) > 0 {
		location = values[0]
	}
	if next, _ := nextURL(hop.Status, location, hop.URL); next != "" {
		out.SendsTo = strings.ToLower(hostOf(next))
	}
	return out
}
