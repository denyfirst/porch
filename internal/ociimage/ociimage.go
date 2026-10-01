// Package ociimage builds the container image a release ships, byte for byte
// the same on any machine with the same Go toolchain.
//
// The image is the release's own two binaries and nothing else, as the
// Dockerfile's FROM scratch always was. What changes is who builds it. A
// Docker build stamps times, orders files as the filesystem lists them and
// compresses with whatever its version does, so two builds of the same
// binaries name two different digests — and a digest nobody can reproduce is
// one a signature can only take on trust. This writes every byte itself:
// entries sorted, owners and times fixed, compressed by the standard library
// at a fixed level, JSON from structs whose field order is the order written.
// The release workflow and the maintainer's machine then arrive at the same
// digest, and the maintainer signs only after comparing the two — the split
// docs/releasing.md exists for, kept for the image as it is for the binaries.
//
// Nothing here is a general-purpose image tool, and nothing beyond the
// standard library is imported: an image that cannot be checked would undo
// the argument the release is built on.
package ociimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The media types this writes, from the OCI image specification.
const (
	MediaTypeIndex    = "application/vnd.oci.image.index.v1+json"
	MediaTypeManifest = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeConfig   = "application/vnd.oci.image.config.v1+json"
	MediaTypeLayer    = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// epoch is the time every entry carries. A build's own time is the commonest
// reason two builds of the same input differ; a fixed one is the fix.
var epoch = time.Unix(0, 0).UTC()

// File is one file in the image, at the root of its filesystem.
type File struct {
	// Name is the path inside the image, without a leading slash.
	Name string
	// Mode is the permission bits; the owner is always root.
	Mode int64
	Data []byte
}

// Platform is what an image runs on, in the spelling the specification uses.
type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// Image is one platform's image.
type Image struct {
	Platform   Platform
	Files      []File
	User       string
	Entrypoint []string
	Cmd        []string
	// Ports are exposed ports, such as "8080/tcp".
	Ports  []string
	Labels map[string]string
}

// Descriptor points at a blob by its digest.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *Platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Layout is a built image: every blob by its digest, and the index that names
// one manifest per platform. The index's digest is what a compose file pins.
type Layout struct {
	Blobs map[string][]byte
	Index Descriptor
}

// Digest is the content address of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Build makes the multi-platform image, with annotations on the index.
func Build(images []Image, annotations map[string]string) (*Layout, error) {
	if len(images) == 0 {
		return nil, errors.New("an image needs at least one platform")
	}
	l := &Layout{Blobs: map[string][]byte{}}
	put := func(mediaType string, b []byte) Descriptor {
		d := Descriptor{MediaType: mediaType, Digest: Digest(b), Size: int64(len(b))}
		l.Blobs[d.Digest] = b
		return d
	}

	seen := map[Platform]bool{}
	var manifests []Descriptor
	for _, img := range images {
		if seen[img.Platform] {
			return nil, fmt.Errorf("two images for %s/%s", img.Platform.OS, img.Platform.Architecture)
		}
		seen[img.Platform] = true

		raw, err := layerTar(img.Files)
		if err != nil {
			return nil, err
		}
		compressed, err := gzipped(raw)
		if err != nil {
			return nil, err
		}
		layer := put(MediaTypeLayer, compressed)

		cfg, err := json.Marshal(configFor(img, Digest(raw)))
		if err != nil {
			return nil, err
		}
		config := put(MediaTypeConfig, cfg)

		man, err := json.Marshal(manifest{
			SchemaVersion: 2,
			MediaType:     MediaTypeManifest,
			Config:        config,
			Layers:        []Descriptor{layer},
			Annotations:   annotations,
		})
		if err != nil {
			return nil, err
		}
		d := put(MediaTypeManifest, man)
		platform := img.Platform
		d.Platform = &platform
		manifests = append(manifests, d)
	}

	// Ordered by platform, so the index does not depend on the order the
	// caller listed them in.
	sort.Slice(manifests, func(i, j int) bool {
		a, b := manifests[i].Platform, manifests[j].Platform
		return a.OS+"/"+a.Architecture < b.OS+"/"+b.Architecture
	})

	idx, err := json.Marshal(index{
		SchemaVersion: 2,
		MediaType:     MediaTypeIndex,
		Manifests:     manifests,
		Annotations:   annotations,
	})
	if err != nil {
		return nil, err
	}
	l.Index = put(MediaTypeIndex, idx)
	return l, nil
}

type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type index struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     []Descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// imageConfig is the configuration a runtime reads. No "created": a time is
// the one field that would differ between two builds of the same bytes.
type imageConfig struct {
	Architecture string        `json:"architecture"`
	OS           string        `json:"os"`
	Config       runtimeConfig `json:"config"`
	RootFS       rootFS        `json:"rootfs"`
}

type runtimeConfig struct {
	User         string              `json:"User,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Entrypoint   []string            `json:"Entrypoint,omitempty"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
}

type rootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

func configFor(img Image, diffID string) imageConfig {
	ports := map[string]struct{}{}
	for _, p := range img.Ports {
		ports[p] = struct{}{}
	}
	if len(ports) == 0 {
		ports = nil
	}
	return imageConfig{
		Architecture: img.Platform.Architecture,
		OS:           img.Platform.OS,
		Config: runtimeConfig{
			User:         img.User,
			ExposedPorts: ports,
			Entrypoint:   img.Entrypoint,
			Cmd:          img.Cmd,
			Labels:       img.Labels,
		},
		RootFS: rootFS{Type: "layers", DiffIDs: []string{diffID}},
	}
}

// layerTar is the layer before compression: the files, sorted by name, owned
// by root, at the fixed time, in the plainest tar format there is.
func layerTar(files []File) ([]byte, error) {
	sorted := append([]File(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i, f := range sorted {
		if f.Name == "" || strings.HasPrefix(f.Name, "/") || strings.Contains(f.Name, "..") || strings.Contains(f.Name, "/") {
			return nil, fmt.Errorf("%q is not a name at the root of the image", f.Name)
		}
		if i > 0 && sorted[i-1].Name == f.Name {
			return nil, fmt.Errorf("%q is in the image twice", f.Name)
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.Name,
			Mode:     f.Mode,
			Size:     int64(len(f.Data)),
			ModTime:  epoch,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// gzipped compresses at a fixed level with no name and no time in the header,
// so the output depends on the input and the toolchain alone.
func gzipped(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
