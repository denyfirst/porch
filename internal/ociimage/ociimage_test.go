package ociimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

func images(tag string) []Image {
	return []Image{
		Porch(tag, "amd64", []byte("porchd for amd64"), []byte("porch-scan for amd64")),
		Porch(tag, "arm64", []byte("porchd for arm64"), []byte("porch-scan for arm64")),
	}
}

func build(t *testing.T, imgs []Image) *Layout {
	t.Helper()
	l, err := Build(imgs, map[string]string{"org.opencontainers.image.version": "v9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func archive(t *testing.T, l *Layout) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := l.WriteTar(&buf, Repository+":v9.9.9"); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The same binaries make the same image, to the byte, whatever order they are
// handed over in. This is the property the release's signature rests on: the
// maintainer rebuilds the image and signs only if the digest matches the one
// the workflow built and pushed.
func TestTheSameBinariesMakeTheSameImage(t *testing.T) {
	a := build(t, images("v9.9.9"))

	reversed := images("v9.9.9")
	reversed[0], reversed[1] = reversed[1], reversed[0]
	reversed[0].Files[0], reversed[0].Files[1] = reversed[0].Files[1], reversed[0].Files[0]
	b := build(t, reversed)

	if a.Index.Digest != b.Index.Digest {
		t.Errorf("one set of binaries made two images: %s and %s", a.Index.Digest, b.Index.Digest)
	}
	if !bytes.Equal(archive(t, a), archive(t, b)) {
		t.Error("one image was written as two different archives")
	}

	// And different binaries make a different image, or the digest would pin
	// nothing.
	other := images("v9.9.9")
	other[1].Files[0].Data = []byte("a different porchd")
	if build(t, other).Index.Digest == a.Index.Digest {
		t.Error("different binaries made the same digest")
	}
}

// Nothing in the image records when it was built: no time in the layer, in
// its compression, or in the configuration. A time is the one thing two
// honest builds of the same bytes would disagree on.
func TestTheImageRecordsNoTime(t *testing.T) {
	l := build(t, images("v9.9.9"))
	manifests, err := l.Manifests()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range manifests {
		contents, err := l.Contents(m)
		if err != nil {
			t.Fatal(err)
		}
		config, layer := l.Blobs[contents[0].Digest], l.Blobs[contents[1].Digest]

		if strings.Contains(string(config), `"created"`) || strings.Contains(string(config), `"history"`) {
			t.Errorf("the configuration records a time: %s", config)
		}

		zr, err := gzip.NewReader(bytes.NewReader(layer))
		if err != nil {
			t.Fatal(err)
		}
		if !zr.ModTime.IsZero() || zr.Name != "" {
			t.Errorf("the layer's compression records a name or a time: %q %v", zr.Name, zr.ModTime)
		}
		tr := tar.NewReader(zr)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if !hdr.ModTime.Equal(epoch) {
				t.Errorf("%s carries the time %v", hdr.Name, hdr.ModTime)
			}
		}
	}
}

// The image is the two binaries and nothing else: no base system, no shell,
// owned by root, runnable by anybody and writable by nobody.
func TestTheImageIsTheTwoBinariesAndNothingElse(t *testing.T) {
	l := build(t, images("v9.9.9"))
	manifests, err := l.Manifests()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != 2 || manifests[0].Platform.Architecture != "amd64" || manifests[1].Platform.Architecture != "arm64" {
		t.Fatalf("the index does not name one image for each server processor: %+v", manifests)
	}
	for _, m := range manifests {
		contents, err := l.Contents(m)
		if err != nil {
			t.Fatal(err)
		}
		if len(contents) != 2 {
			t.Fatalf("the %s image has %d layers, want one", m.Platform.Architecture, len(contents)-1)
		}
		zr, err := gzip.NewReader(bytes.NewReader(l.Blobs[contents[1].Digest]))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		tr := tar.NewReader(zr)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, hdr.Name)
			if hdr.Mode != 0o555 || hdr.Uid != 0 || hdr.Gid != 0 || hdr.Typeflag != tar.TypeReg {
				t.Errorf("%s is %o owned by %d:%d, want a plain file 555 owned by root", hdr.Name, hdr.Mode, hdr.Uid, hdr.Gid)
			}
			data, _ := io.ReadAll(tr)
			if !strings.HasSuffix(string(data), m.Platform.Architecture) {
				t.Errorf("the %s image carries %s built for another processor", m.Platform.Architecture, hdr.Name)
			}
		}
		if strings.Join(names, " ") != "porch-scan porchd" {
			t.Errorf("the %s image holds %v, want the two binaries alone", m.Platform.Architecture, names)
		}
	}

	if _, err := Build([]Image{{Platform: Platform{"amd64", "linux"}, Files: []File{{Name: "../etc/passwd"}}}}, nil); err == nil {
		t.Error("a file outside the image's root was accepted")
	}
}

// The image starts the service as the Dockerfile always did: as nobody, with
// proof of control and a password on. Read from the Dockerfile rather than
// restated, so the two cannot drift.
func TestTheImageStartsWhatTheDockerfileStarts(t *testing.T) {
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	cmd := regexp.MustCompile(`(?m)^CMD (\[.*\])$`).FindSubmatch(dockerfile)
	user := regexp.MustCompile(`(?m)^USER (\S+)$`).FindSubmatch(dockerfile)
	entry := regexp.MustCompile(`(?m)^ENTRYPOINT (\[.*\])$`).FindSubmatch(dockerfile)
	if cmd == nil || user == nil || entry == nil {
		t.Fatal("the Dockerfile no longer has USER, ENTRYPOINT and CMD lines to compare with")
	}
	var wantCmd, wantEntry []string
	if err := json.Unmarshal(cmd[1], &wantCmd); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(entry[1], &wantEntry); err != nil {
		t.Fatal(err)
	}

	img := Porch("v9.9.9", "amd64", nil, nil)
	if img.User != string(user[1]) {
		t.Errorf("the image runs as %q, the Dockerfile as %q", img.User, user[1])
	}
	if strings.Join(img.Entrypoint, " ") != strings.Join(wantEntry, " ") {
		t.Errorf("the image starts %v, the Dockerfile %v", img.Entrypoint, wantEntry)
	}
	if strings.Join(img.Cmd, " ") != strings.Join(wantCmd, " ") {
		t.Errorf("the image runs %v, the Dockerfile %v", img.Cmd, wantCmd)
	}
	for _, flag := range []string{"-verification-secret-file", "-access-file"} {
		if !strings.Contains(strings.Join(img.Cmd, " "), flag) {
			t.Errorf("the image starts without %s", flag)
		}
	}
}

// A layout read back is the layout written, and a blob that does not hash to
// its name, or one the index needs and the archive lacks, is refused.
func TestALayoutIsReadBackAndATamperedOneIsRefused(t *testing.T) {
	l := build(t, images("v9.9.9"))
	written := archive(t, l)

	back, err := ReadTar(bytes.NewReader(written))
	if err != nil {
		t.Fatal(err)
	}
	if back.Index.Digest != l.Index.Digest || len(back.Blobs) != len(l.Blobs) {
		t.Error("the layout read back is not the one written")
	}

	// One byte of one binary changed, inside the archive.
	tampered := bytes.Replace(written, []byte("porchd for arm64"), []byte("porchd for arm65"), 1)
	if bytes.Equal(tampered, written) {
		// The layer is compressed, so the text is not there to change; change
		// a byte of the compressed blob instead.
		at := len(written) / 2
		tampered = append([]byte(nil), written...)
		tampered[at] ^= 0xff
	}
	if _, err := ReadTar(bytes.NewReader(tampered)); err == nil {
		t.Error("an archive with a changed byte was accepted")
	}

	// A blob the index needs, missing.
	missing := &Layout{Blobs: map[string][]byte{}, Index: l.Index}
	for d, b := range l.Blobs {
		missing.Blobs[d] = b
	}
	for d := range missing.Blobs {
		if d != l.Index.Digest {
			delete(missing.Blobs, d)
			break
		}
	}
	if err := missing.Verify(); err == nil {
		t.Error("a layout missing a blob verified")
	}

	// And a blob nothing references is held to its name all the same: an
	// archive carrying anything that is not what it says is not this
	// release's, whether or not the index happens to reach it.
	junk := &Layout{Blobs: map[string][]byte{}, Index: l.Index}
	for d, b := range l.Blobs {
		junk.Blobs[d] = b
	}
	junk.Blobs["sha256:"+strings.Repeat("0", 64)] = []byte("not what its name says")
	if _, err := ReadTar(bytes.NewReader(archive(t, junk))); err == nil {
		t.Error("an archive carrying a blob that does not hash to its name was accepted")
	}
}
