package ociimage

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The most a layout read from a file may hold, in all. The image is two
// binaries; a layout far larger than that is not this release's.
const maxLayout = 256 << 20

// WriteTar writes the layout as an OCI image layout in a tar archive, the
// form `docker load` reads and the release carries. Entries are sorted and
// carry the fixed time, so two writes of one layout are the same bytes.
//
// name, where not empty, is recorded as the image's name for a runtime that
// loads the archive. The compose file pins the index by digest, which this
// does not change.
func (l *Layout) WriteTar(w io.Writer, name string) error {
	if err := l.Verify(); err != nil {
		return err
	}

	ref := l.Index
	if name != "" {
		ref.Annotations = map[string]string{
			"io.containerd.image.name":          name,
			"org.opencontainers.image.ref.name": name[strings.LastIndex(name, ":")+1:],
		}
	}
	top, err := json.Marshal(index{SchemaVersion: 2, MediaType: MediaTypeIndex, Manifests: []Descriptor{ref}})
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`),
		"index.json": top,
	}
	for d, b := range l.Blobs {
		files["blobs/sha256/"+strings.TrimPrefix(d, "sha256:")] = b
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	tw := tar.NewWriter(w)
	for _, dir := range []string{"blobs/", "blobs/sha256/"} {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir, Name: dir, Mode: 0o755, ModTime: epoch, Format: tar.FormatUSTAR,
		}); err != nil {
			return err
		}
	}
	for _, n := range names {
		b := files[n]
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(b)), ModTime: epoch, Format: tar.FormatUSTAR,
		}); err != nil {
			return err
		}
		if _, err := tw.Write(b); err != nil {
			return err
		}
	}
	return tw.Close()
}

// ReadTar reads a layout WriteTar wrote, and refuses one whose blobs do not
// match their names or whose index points at something missing.
func ReadTar(r io.Reader) (*Layout, error) {
	l := &Layout{Blobs: map[string][]byte{}}
	var top []byte
	var total int64

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the image archive could not be read: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("the image archive holds %q, which is not a plain file", hdr.Name)
		}
		total += hdr.Size
		if hdr.Size < 0 || total > maxLayout {
			return nil, errors.New("the image archive is larger than a release's image can be")
		}
		b, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return nil, err
		}
		switch {
		case hdr.Name == "index.json":
			top = b
		case hdr.Name == "oci-layout":
		case strings.HasPrefix(hdr.Name, "blobs/sha256/"):
			d := "sha256:" + strings.TrimPrefix(hdr.Name, "blobs/sha256/")
			if Digest(b) != d {
				return nil, fmt.Errorf("the blob named %s does not hash to its name", d)
			}
			l.Blobs[d] = b
		default:
			return nil, fmt.Errorf("the image archive holds %q, which a layout does not", hdr.Name)
		}
	}
	if top == nil {
		return nil, errors.New("the image archive has no index.json")
	}

	var idx index
	if err := json.Unmarshal(top, &idx); err != nil {
		return nil, fmt.Errorf("index.json could not be read: %w", err)
	}
	if len(idx.Manifests) != 1 || idx.Manifests[0].MediaType != MediaTypeIndex {
		return nil, errors.New("index.json does not name exactly one multi-platform image")
	}
	l.Index = idx.Manifests[0]
	l.Index.Annotations = nil
	if err := l.Verify(); err != nil {
		return nil, err
	}
	return l, nil
}

// Verify checks that the index, every manifest it names and every blob those
// name are present, the size and digest each descriptor says, and of the
// kind it says.
func (l *Layout) Verify() error {
	if err := l.check(l.Index, MediaTypeIndex); err != nil {
		return err
	}
	var idx index
	if err := json.Unmarshal(l.Blobs[l.Index.Digest], &idx); err != nil {
		return fmt.Errorf("the index could not be read: %w", err)
	}
	if idx.MediaType != MediaTypeIndex || len(idx.Manifests) == 0 {
		return errors.New("the index names no manifests")
	}
	for _, m := range idx.Manifests {
		if m.Platform == nil {
			return fmt.Errorf("the manifest %s names no platform", m.Digest)
		}
		if err := l.check(m, MediaTypeManifest); err != nil {
			return err
		}
		var man manifest
		if err := json.Unmarshal(l.Blobs[m.Digest], &man); err != nil {
			return fmt.Errorf("the manifest %s could not be read: %w", m.Digest, err)
		}
		if err := l.check(man.Config, MediaTypeConfig); err != nil {
			return err
		}
		if len(man.Layers) == 0 {
			return fmt.Errorf("the manifest %s names no layers", m.Digest)
		}
		for _, layer := range man.Layers {
			if err := l.check(layer, MediaTypeLayer); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *Layout) check(d Descriptor, mediaType string) error {
	if d.MediaType != mediaType {
		return fmt.Errorf("%s is a %s where a %s was expected", d.Digest, d.MediaType, mediaType)
	}
	b, ok := l.Blobs[d.Digest]
	if !ok {
		return fmt.Errorf("%s is named and not present", d.Digest)
	}
	if Digest(b) != d.Digest || int64(len(b)) != d.Size {
		return fmt.Errorf("%s is not the size or the content its descriptor says", d.Digest)
	}
	return nil
}

// Manifests are the per-platform manifests the index names, in its order.
func (l *Layout) Manifests() ([]Descriptor, error) {
	var idx index
	if err := json.NewDecoder(bytes.NewReader(l.Blobs[l.Index.Digest])).Decode(&idx); err != nil {
		return nil, err
	}
	return idx.Manifests, nil
}

// Contents are the blobs one manifest names: its config and its layers.
func (l *Layout) Contents(m Descriptor) ([]Descriptor, error) {
	var man manifest
	if err := json.Unmarshal(l.Blobs[m.Digest], &man); err != nil {
		return nil, err
	}
	return append([]Descriptor{man.Config}, man.Layers...), nil
}
