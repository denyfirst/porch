package ociimage

import (
	"fmt"
	"os"
	"path/filepath"
)

// Repository is where the release's image is published.
const Repository = "ghcr.io/denyfirst/porch"

// Source is the repository the image is built from. GHCR reads this label to
// link the package to it.
const Source = "https://github.com/denyfirst/porch"

// Architectures the image is built for: the Linux targets scripts/build.sh
// builds, which are the servers a container runs on.
var Architectures = []string{"amd64", "arm64"}

// Porch is the image a release ships for one processor: the service and its
// command line, run as nobody, proof of control and a password on. It is
// what the Dockerfile describes, written out here so that the bytes are this
// package's to fix.
func Porch(tag, arch string, porchd, porchScan []byte) Image {
	return Image{
		Platform: Platform{Architecture: arch, OS: "linux"},
		Files: []File{
			{Name: "porchd", Mode: 0o555, Data: porchd},
			{Name: "porch-scan", Mode: 0o555, Data: porchScan},
		},
		// nobody:nogroup, by number: there is no /etc/passwd in the image.
		User:       "65534:65534",
		Entrypoint: []string{"/porchd"},
		Cmd: []string{
			"-listen", "0.0.0.0:8080",
			"-verification-secret-file", "/data/secret",
			"-access-file", "/data/access",
		},
		Ports: []string{"8080/tcp"},
		Labels: map[string]string{
			"org.opencontainers.image.source":  Source,
			"org.opencontainers.image.version": tag,
		},
	}
}

// BuildRelease reads the release's Linux binaries out of dist and builds the
// image for every architecture.
func BuildRelease(tag, dist string) (*Layout, error) {
	var images []Image
	for _, arch := range Architectures {
		read := func(command string) ([]byte, error) {
			name := fmt.Sprintf("%s_%s_linux_%s", command, tag, arch)
			// #nosec G304 -- a file the build script itself just wrote
			b, err := os.ReadFile(filepath.Join(dist, name))
			if err != nil {
				return nil, fmt.Errorf("the image needs %s: %w", name, err)
			}
			return b, nil
		}
		porchd, err := read("porchd")
		if err != nil {
			return nil, err
		}
		porchScan, err := read("porch-scan")
		if err != nil {
			return nil, err
		}
		images = append(images, Porch(tag, arch, porchd, porchScan))
	}
	return Build(images, map[string]string{
		"org.opencontainers.image.source":  Source,
		"org.opencontainers.image.version": tag,
	})
}
