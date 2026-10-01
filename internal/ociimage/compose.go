package ociimage

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Placeholder is the digest the compose file in the repository carries where
// the release writes its image's. Zeros, so that a checkout run as it is
// fails to pull rather than pulling something.
const Placeholder = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imageLine     = regexp.MustCompile(`(?m)^\s*image:\s*(\S+)\s*$`)
)

// Compose writes the release's compose file: the template with every image
// pinned to digest. Refused unless every image line in the template is the
// placeholder for this repository, so that no service can start something
// other than the image the signature covers — not a tag, which a registry can
// point anywhere, and not a name some other registry answers for.
func Compose(template, repository, digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("%q is not an image digest", digest)
	}
	want := repository + "@" + Placeholder
	lines := imageLine.FindAllStringSubmatch(template, -1)
	if len(lines) == 0 {
		return "", errors.New("the compose template names no image")
	}
	for _, m := range lines {
		if m[1] != want {
			return "", fmt.Errorf("the compose template starts %s, where only %s may stand", m[1], want)
		}
	}
	if regexp.MustCompile(`(?m)^\s*build:`).MatchString(template) {
		return "", errors.New("the compose template builds an image, where it must start the published one")
	}
	return strings.ReplaceAll(template, want, repository+"@"+digest), nil
}
