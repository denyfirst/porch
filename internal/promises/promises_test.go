package promises

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every undertaking says how to check it, and is named in a way that survives
// being reworded.
//
// The identifier is what anything else refers to: a sentence may be improved
// and the thing it promises is still the same thing. And Checked is required
// because an undertaking nobody can establish for themselves is a request to be
// trusted — which is the thing this organisation is trying not to ask for. A
// promise with no way to check it would be the most comfortable entry to add
// and the only worthless one.
func TestEveryUndertakingCanBeCheckedAndIsNamed(t *testing.T) {
	id := regexp.MustCompile(`^[a-z][a-z0-9-]*[a-z0-9]$`)

	seen := map[string]string{}
	for _, list := range all() {
		for _, p := range list.promises {
			switch {
			case !id.MatchString(p.ID):
				t.Errorf("%s: %q is not a stable identifier", list.where, p.ID)
			case p.Says == "":
				t.Errorf("%s: %s says nothing", list.where, p.ID)
			case p.Checked == "":
				t.Errorf("%s: %s gives no way to check it, which makes it a request to be trusted", list.where, p.ID)
			}
			if at, ok := seen[p.ID]; ok {
				t.Errorf("%s reuses the identifier %s, already used in %s", list.where, p.ID, at)
			}
			seen[p.ID] = list.where
		}
	}

	if len(Organisation) == 0 {
		t.Error("the organisation undertakes nothing, which cannot be what was meant")
	}
	if len(Products) == 0 {
		t.Error("no product is listed")
	}
}

// A product adds restrictions and never restates one of the organisation's.
//
// This is the whole mechanism of the split. A product may undertake to keep
// less than the organisation requires; it may not undertake more, and it may
// not reword one of these in its own words — because an addition that redefined
// an organisation undertaking is how a weaker promise arrives wearing a
// stronger promise's name, and a reader comparing the two pages would find them
// agreeing on the identifier and disagreeing on the meaning.
func TestNoProductRedefinesWhatTheOrganisationUndertakes(t *testing.T) {
	organisation := map[string]bool{}
	for _, p := range Organisation {
		organisation[p.ID] = true
	}

	for _, product := range Products {
		if product.Name == "" || product.What == "" {
			t.Errorf("a product is listed without a name or without saying what it is: %+v", product)
		}
		for _, p := range product.Adds {
			if organisation[p.ID] {
				t.Errorf("%s restates the organisation's %s in its own words", product.Name, p.ID)
			}
			// And an addition is recognisable as belonging to its product, so
			// that nothing in a product list reads as though the organisation
			// had said it.
			if !strings.HasPrefix(p.ID, strings.ToLower(product.Name)+"-") {
				t.Errorf("%s adds %s, which is not named for the product it belongs to", product.Name, p.ID)
			}
		}
	}
}

// The sentences live in one place and are not copied into the markup.
//
// The argument for splitting the organisation from the product was that a
// second product would otherwise mean the same undertakings written twice — and
// two places drift. Writing them into a page as well would be the same fault
// one layer down: the day the text here is improved and the copy in the page is
// not, a reader has two documents from the same people that do not agree, which
// is worse evidence than one vague document.
//
// So the pages range over this package, and nothing served to a visitor carries
// the sentences. What is compared is a distinctive run of words from each one
// rather than the whole, because a template wraps and re-indents whatever it
// renders.
func TestTheUndertakingsAreNotCopiedIntoAnyPage(t *testing.T) {
	root := filepath.Join("..", "..")

	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "dist", "tmp", "promises":
				return fs.SkipDir
			}
			return nil
		}
		// What a visitor is served, and the Go that serves it. Documentation is
		// left out on purpose: docs/invariants.md is where several of these
		// sentences were drawn from, it explains and cites rather than
		// promising, and forbidding the words there would make the explanations
		// worse without protecting anybody. What can drift harmfully is two
		// pages telling a reader two versions of the same undertaking.
		switch filepath.Ext(path) {
		case ".html", ".js", ".go":
			if !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reading the repository: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("nothing was read, so nothing here checked anything")
	}

	for _, list := range all() {
		for _, p := range list.promises {
			phrase := distinctive(p.Says)
			for _, file := range files {
				body, err := os.ReadFile(file)
				if err != nil {
					t.Fatalf("reading %s: %v", file, err)
				}
				if strings.Contains(string(body), phrase) {
					t.Errorf("%s carries %s in its own words (%q); the pages must range over this package instead",
						file, p.ID, phrase)
				}
			}
		}
	}
}

// distinctive is a run of words from the middle of an undertaking, long enough
// that nothing says it by coincidence and short enough to survive a sentence
// being reflowed.
func distinctive(says string) string {
	words := strings.Fields(says)
	if len(words) < 8 {
		return says
	}
	return strings.Join(words[2:8], " ")
}

// all is every list here, with somewhere to say which one a fault is in.
func all() []struct {
	where    string
	promises []Promise
} {
	out := []struct {
		where    string
		promises []Promise
	}{{"the organisation", Organisation}}
	for _, p := range Products {
		out = append(out, struct {
			where    string
			promises []Promise
		}{p.Name, p.Adds})
	}
	return out
}
