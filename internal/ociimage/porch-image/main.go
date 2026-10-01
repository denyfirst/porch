// Command porch-image builds, publishes and checks the release's container
// image. It is a release tool, run by scripts/build.sh and the release
// workflows, and not something an installation runs.
//
//	porch-image build -tag v0.26.0 -dist dist -compose docker-compose.yml
//	porch-image push  -archive dist/porch-image_v0.26.0.tar
//	porch-image check -archive dist/porch-image_v0.26.0.tar
//
// build writes the image to dist as an OCI layout and writes the compose file
// beside it with the image's digest in place of the placeholder, so the file
// the signature covers names the exact bytes it starts. push sends the layout
// to the registry by digest, with no tag. check reads the registry
// anonymously, as an installation will, and fails unless it serves exactly
// the layout.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/denyfirst/porch/internal/ociimage"
)

// releaseTag is what a tag this project cuts looks like, release candidates
// included.
var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "porch-image:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: porch-image build|push|check [flags]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	tag := fs.String("tag", "", "the release tag")
	dist := fs.String("dist", "", "the directory the release's binaries are in")
	compose := fs.String("compose", "", "the compose template, carrying the placeholder digest")
	archive := fs.String("archive", "", "the image archive build wrote")
	repository := fs.String("repository", ociimage.Repository, "where the image is published")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	switch args[0] {
	case "build":
		if *tag == "" || *dist == "" || *compose == "" {
			return errors.New("build needs -tag, -dist and -compose")
		}
		return build(*tag, *dist, *compose, *repository)
	case "push", "check":
		if *archive == "" {
			return errors.New(args[0] + " needs -archive")
		}
		// #nosec G304 G703 -- a path the release workflow or the maintainer names, read and never written
		f, err := os.Open(*archive)
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // read-only
		l, err := ociimage.ReadTar(f)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		reg, err := ociimage.NewRegistry(*repository)
		if err != nil {
			return err
		}
		if args[0] == "push" {
			// The workflow's own token, named by the environment so that it
			// is never on a command line.
			reg.Username, reg.Password = os.Getenv("REGISTRY_USERNAME"), os.Getenv("REGISTRY_PASSWORD")
			if err := reg.Push(ctx, l); err != nil {
				return err
			}
			fmt.Printf("pushed %s@%s\n", *repository, l.Index.Digest)
			return nil
		}
		if err := reg.Check(ctx, l); err != nil {
			return err
		}
		fmt.Printf("%s@%s is served exactly as built\n", *repository, l.Index.Digest)
		return nil
	}
	return fmt.Errorf("%q is not build, push or check", args[0])
}

func build(tag, dist, composeTemplate, repository string) error {
	// The tag goes into file names, so it is held to what a release tag is:
	// nothing in it can climb out of the directory or name another file.
	if !releaseTag.MatchString(tag) {
		return fmt.Errorf("%q is not a release tag", tag)
	}
	l, err := ociimage.BuildRelease(tag, dist)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := l.WriteTar(&buf, repository+":"+tag); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dist, "porch-image_"+tag+".tar"), buf.Bytes(), 0o644); err != nil { // #nosec G306 G703 -- a public release artifact, in the directory build.sh names, under a tag checked above
		return err
	}

	// #nosec G304 G703 -- the template in this repository, named by build.sh
	template, err := os.ReadFile(composeTemplate)
	if err != nil {
		return err
	}
	composed, err := ociimage.Compose(string(template), repository, l.Index.Digest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dist, "docker-compose.yml"), []byte(composed), 0o644); err != nil { // #nosec G306 G703 -- a public release artifact, in the directory build.sh names
		return err
	}
	fmt.Println(l.Index.Digest)
	return nil
}
