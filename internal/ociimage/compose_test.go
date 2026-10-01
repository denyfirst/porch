package ociimage

import (
	"os"
	"strings"
	"testing"
)

const digestA = "sha256:4559d2b5f26e9bce3f00a8fc63947addee3992a9d2837e1512df258602c4466b"

// The release's compose file pins every service to the image's digest, and
// the template it is written from may name nothing else.
func TestTheComposeFilePinsEveryServiceToTheDigest(t *testing.T) {
	template, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	out, err := Compose(string(template), Repository, digestA)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, Placeholder) {
		t.Error("the placeholder survived into the release's compose file")
	}
	if n := strings.Count(out, "image: "+Repository+"@"+digestA); n != 2 {
		t.Errorf("%d services start the pinned image, want both", n)
	}

	for name, bad := range map[string]string{
		"a tag":            strings.Replace(string(template), "@"+Placeholder, ":latest", 1),
		"another registry": strings.Replace(string(template), Repository, "docker.io/denyfirst/porch", 1),
		"a build":          strings.Replace(string(template), "services:\n", "services:\n  x:\n    build: .\n", 1),
	} {
		if _, err := Compose(bad, Repository, digestA); err == nil {
			t.Errorf("a template with %s was accepted", name)
		}
	}
	for _, d := range []string{"", "sha256:", "latest", digestA + "0", "sha512:" + strings.Repeat("0", 64)} {
		if _, err := Compose(string(template), Repository, d); err == nil {
			t.Errorf("%q was accepted as a digest", d)
		}
	}
}
