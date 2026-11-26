package web

import (
	"bytes"
	"sort"
	"strings"
	"text/template"
)

// llms.txt is a page's worth of plain text that says what a site is, for a
// program that reads it rather than a person: the proposal at llmstxt.org.
// Whether a given assistant reads it is that assistant's business; offering
// it costs a few hundred bytes.
//
// It is written from the same table as the pages and the sitemap, so a page
// added to one is in the other, and its few sentences of fact are ones the
// pages or the README already say. A file for machines that said more than
// the pages would be the one place this site could overstate itself unread,
// and the thing a model repeats is the file.
//
// denyfirst.dev answers with its own, from denyfirst/site, and this one links
// to it. An installation somebody runs serves none, for the reason it asks
// robots not to index it: it is one company's instrument, not anything to
// find.

// llmsPage is one line under Pages.
type llmsPage struct {
	Title, URL, Description string
}

// llmsFile is what assets/llms-porch.txt reads.
type llmsFile struct {
	Pages   []llmsPage
	Checks  []consoleCheck
	Release string

	SiteURL, ChecksURL string
}

// llmsTemplate is the file /llms.txt is written from.
const llmsTemplate = "assets/llms-porch.txt"

// buildLLMs adds /llms.txt to the crawler files. Called by buildPlain on the
// demonstration only, after the pages are rendered.
func buildLLMs() {
	var lines []llmsPage
	for path := range rendered {
		p := pages[path]
		if p == nil {
			continue
		}
		lines = append(lines, llmsPage{Title: p.Title, URL: canonicalURL(path), Description: p.Description})
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].URL < lines[j].URL })

	source, err := assets.ReadFile(llmsTemplate)
	if err != nil {
		panic("web: " + err.Error())
	}
	t, err := template.New(llmsTemplate).Option("missingkey=error").Parse(string(source))
	if err != nil {
		panic("web: " + llmsTemplate + ": " + err.Error())
	}
	var out bytes.Buffer
	if err := t.Execute(&out, llmsFile{
		Pages:     lines,
		Checks:    consoleChecks(),
		Release:   pageRelease(),
		SiteURL:   SiteURL,
		ChecksURL: ChecksURL,
	}); err != nil {
		panic("web: " + llmsTemplate + ": " + err.Error())
	}
	plain["/llms.txt"] = plainFile{"text/plain; charset=utf-8", []byte(strings.TrimLeft(out.String(), "\n"))}
}
