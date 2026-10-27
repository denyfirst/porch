package web

import (
	"bytes"
	"sort"
	"strings"
	"text/template"

	"github.com/denyfirst/porch/internal/promises"
)

// llms.txt is a page's worth of plain text that says what a site is, for a
// program that reads it rather than a person: the proposal at llmstxt.org.
// Whether a given assistant reads it is that assistant's business; offering
// it costs a few hundred bytes. Each of the demonstration's names answers with
// its own, as each does with robots.txt.
//
// It is written from the same table as the pages and the sitemap, so a page
// added to one is in the other, and its few sentences of fact are ones the
// pages or the README already say. A file for machines that said more than
// the pages would be the one place this site could overstate itself unread,
// and the thing a model repeats is the file.
//
// An installation somebody runs serves none, for the reason it asks robots
// not to index it: it is one company's instrument, not anything to find.

// llmsPage is one line under Pages.
type llmsPage struct {
	Title, URL, Description string
}

// llmsProduct is one line under Products: the product's own address, where
// its own llms.txt is.
type llmsProduct struct {
	Name, What, URL string
}

// llmsFile is what assets/llms-*.txt read.
type llmsFile struct {
	Pages    []llmsPage
	Products []llmsProduct
	Checks   []consoleCheck
	Release  string

	SiteURL, ChecksURL string
}

// buildLLMs adds /llms.txt to each name's crawler files. Called by buildPlain
// on the demonstration only, after the pages are rendered.
func buildLLMs() {
	var organisation, porch []llmsPage
	for path := range rendered {
		p := pages[path]
		if p == nil {
			continue
		}
		line := llmsPage{Title: p.Title, URL: canonicalURL(path), Description: p.Description}
		if p.Organisation {
			organisation = append(organisation, line)
		} else {
			porch = append(porch, line)
		}
	}
	for _, list := range [][]llmsPage{organisation, porch} {
		sort.Slice(list, func(i, j int) bool { return list[i].URL < list[j].URL })
	}

	var products []llmsProduct
	for _, p := range promises.Products {
		if p.Name != promises.Porch.Name {
			// productPages stops startup over the same gap.
			panic("web: " + p.Name + " is in internal/promises with no address of its own")
		}
		products = append(products, llmsProduct{Name: p.Name, What: p.What, URL: PorchURL + "/"})
	}

	for _, f := range []struct {
		files    map[string]plainFile
		template string
		pages    []llmsPage
	}{
		{plain, "assets/llms-denyfirst.txt", organisation},
		{plainPorch, "assets/llms-porch.txt", porch},
	} {
		source, err := assets.ReadFile(f.template)
		if err != nil {
			panic("web: " + err.Error())
		}
		t, err := template.New(f.template).Option("missingkey=error").Parse(string(source))
		if err != nil {
			panic("web: " + f.template + ": " + err.Error())
		}
		var out bytes.Buffer
		if err := t.Execute(&out, llmsFile{
			Pages:     f.pages,
			Products:  products,
			Checks:    consoleChecks(),
			Release:   pageRelease(),
			SiteURL:   SiteURL,
			ChecksURL: ChecksURL,
		}); err != nil {
			panic("web: " + f.template + ": " + err.Error())
		}
		f.files["/llms.txt"] = plainFile{"text/plain; charset=utf-8", []byte(strings.TrimLeft(out.String(), "\n"))}
	}
}
