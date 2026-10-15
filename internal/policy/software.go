package policy

import (
	"strings"
)

// Software is one thing a server named about itself: a product, where it was
// named, and whether a version came with it. The version is never kept; see
// internal/announce.
//
// Reported and never graded (R21). A version in a header tells anybody holding
// a list of known flaws where to start, and removing it is a setting; but a
// hidden version patches nothing, and no document sets a rule a report could
// hold a server to.
type Software struct {
	Name      string `json:"name"`
	Where     string `json:"where"`
	Versioned bool   `json:"versioned,omitempty"`
}

// hideVersion is the setting that stops each of these naming its version,
// where it is one setting. A name not here gets the sentence without one.
var hideVersion = map[string]string{
	"nginx":              "server_tokens off in nginx",
	"apache":             "ServerTokens Prod in Apache",
	"microsoft-iis":      "removeServerHeader in IIS request filtering",
	"php":                "expose_php = Off in php.ini",
	"asp.net":            `enableVersionHeader="false" on ASP.NET's httpRuntime`,
	"asp.net mvc":        "MvcHandler.DisableMvcResponseHeader in ASP.NET MVC",
	"exim":               "smtp_banner in Exim",
	"sendmail":           "SmtpGreetingMessage in Sendmail",
	"postfix":            "smtpd_banner in Postfix",
	"microsoft exchange": "the receive connector's Banner in Exchange",
}

// webSoftwareLine is the web report's row: each product, the header that
// named it, and whether its version came too.
func webSoftwareLine(s []Software) string {
	if len(s) == 0 {
		return "none named"
	}
	parts := make([]string, 0, len(s))
	for _, x := range s {
		p := x.Name + " in " + x.Where
		if x.Versioned {
			p += ", with its version"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

// MailSoftwareLine is what one exchanger's greeting named, in the words both
// faces print (R16). Empty where no greeting was read, which the exchanger's
// STARTTLS row already explains.
//
// "None this check knows" rather than "none": a greeting is free text, and a
// mail server is named only from a fixed list.
func MailSoftwareLine(x ExchangerTLS) string {
	if !x.Connected {
		return ""
	}
	if len(x.Software) == 0 {
		return "names no mail server this check knows"
	}
	parts := make([]string, 0, len(x.Software))
	for _, s := range x.Software {
		p := s.Name
		if s.Versioned {
			p += ", with its version"
		}
		parts = append(parts, p)
	}
	return "names " + strings.Join(parts, " and ")
}

// versionNote is the one sentence a report gives versions, where any was
// named: what, why it is said, and how each is turned off.
//
// whose says whose they are, and label how each is shown: "The response
// names" and "nginx (Server)", or "The greeting names" and "Exim
// (mx.example.com)".
func versionNote(whose string, s []Software, label func(Software) string) (Note, bool) {
	var named, settings []string
	seen := map[string]bool{}
	for _, x := range s {
		if !x.Versioned {
			continue
		}
		named = append(named, label(x))
		key := strings.ToLower(x.Name)
		if h, ok := hideVersion[key]; ok && !seen[key] {
			settings = append(settings, h)
			seen[key] = true
		}
	}
	if len(named) == 0 {
		return Note{}, false
	}
	text := whose + " the version of " + strings.Join(named, ", ") + ". A version tells anyone " +
		"holding a list of known flaws where to start. Reported rather than graded, because hiding it " +
		"patches nothing; keep the software current either way."
	if len(settings) > 0 {
		text += " It is turned off with " + strings.Join(settings, "; ") + "."
	}
	return Observed(text), true
}

// mailVersionNote is versionNote for the exchangers: one sentence for all of
// them rather than one each, every product shown beside the exchanger that
// named it.
func mailVersionNote(exchangers []ExchangerTLS) (Note, bool) {
	var all []Software
	hosts := map[string]bool{}
	for _, x := range exchangers {
		for _, s := range x.Software {
			s.Where = x.Host
			all = append(all, s)
			if s.Versioned {
				hosts[x.Host] = true
			}
		}
	}
	whose := "The mail greeting names"
	if len(hosts) > 1 {
		whose = "The mail greetings name"
	}
	return versionNote(whose, all, func(s Software) string { return s.Name + " (" + s.Where + ")" })
}
