package ociimage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeRegistry speaks as much of the distribution protocol as a push and a
// pull by digest use, behind a bearer challenge the way GHCR answers: an
// anonymous token reads, the credentials' token also writes.
type fakeRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte
	refs      []string // every manifest reference written
	realm     string   // overrides the token endpoint when set
	location  string   // overrides the upload location when set
	tamper    string   // a digest served with one byte changed
}

func newFake() (*fakeRegistry, *httptest.Server) {
	f := &fakeRegistry{blobs: map[string][]byte{}, manifests: map[string][]byte{}}
	srv := httptest.NewServer(f)
	return f, srv
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.URL.Path == "/token" {
		user, pass, ok := r.BasicAuth()
		switch {
		case !ok:
			fmt.Fprint(w, `{"token":"pull"}`)
		case user == "ci" && pass == "secret":
			fmt.Fprint(w, `{"token":"push"}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
		return
	}

	write := r.Method == http.MethodPost || r.Method == http.MethodPut
	auth := r.Header.Get("Authorization")
	if auth != "Bearer push" && (write || auth != "Bearer pull") {
		realm := f.realm
		if realm == "" {
			realm = "http://" + r.Host + "/token"
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`",service="test",scope="repository:denyfirst/porch:pull,push"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	const prefix = "/v2/denyfirst/porch/"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodPost && path == "blobs/uploads/":
		loc := f.location
		if loc == "" {
			loc = prefix + "blobs/uploads/one"
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusAccepted)
	case r.Method == http.MethodPut && strings.HasPrefix(path, "blobs/uploads/"):
		d := r.URL.Query().Get("digest")
		if Digest(body) != d {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.blobs[d] = body
		w.WriteHeader(http.StatusCreated)
	case strings.HasPrefix(path, "blobs/"):
		b, ok := f.blobs[strings.TrimPrefix(path, "blobs/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet {
			w.Write(f.served(strings.TrimPrefix(path, "blobs/"), b)) //nolint:errcheck,gosec
		}
	case r.Method == http.MethodPut && strings.HasPrefix(path, "manifests/"):
		ref := strings.TrimPrefix(path, "manifests/")
		f.refs = append(f.refs, ref)
		if Digest(body) != ref {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.manifests[ref] = body
		w.Header().Set("Docker-Content-Digest", ref)
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "manifests/"):
		ref := strings.TrimPrefix(path, "manifests/")
		b, ok := f.manifests[ref]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(f.served(ref, b)) //nolint:errcheck,gosec
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeRegistry) served(d string, b []byte) []byte {
	if d != f.tamper {
		return b
	}
	out := append([]byte(nil), b...)
	out[len(out)-1] ^= 1
	return out
}

func registryFor(t *testing.T, srv *httptest.Server, user, pass string) *Registry {
	t.Helper()
	reg, err := NewRegistry(strings.TrimPrefix(srv.URL, "http://") + "/denyfirst/porch")
	if err != nil {
		t.Fatal(err)
	}
	reg.Username, reg.Password = user, pass
	return reg
}

// The image goes up by digest and comes back, read anonymously as an
// installation reads it, as exactly the bytes that were built. No tag is
// written: a tag can be moved, and the compose file names the digest.
func TestTheImageIsPushedByDigestAndReadBackExactly(t *testing.T) {
	f, srv := newFake()
	defer srv.Close()
	l := build(t, images("v9.9.9"))
	ctx := context.Background()

	if err := registryFor(t, srv, "ci", "secret").Push(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := registryFor(t, srv, "", "").Check(ctx, l); err != nil {
		t.Errorf("the image pushed does not read back as built: %v", err)
	}

	for _, ref := range f.refs {
		if !strings.HasPrefix(ref, "sha256:") {
			t.Errorf("a manifest was written under %q, which is not a digest", ref)
		}
	}
	if len(f.blobs)+len(f.manifests) != len(l.Blobs) {
		t.Errorf("the registry holds %d objects, the layout %d", len(f.blobs)+len(f.manifests), len(l.Blobs))
	}

	// A second push sends no blob again, and changes nothing.
	before := len(f.refs)
	if err := registryFor(t, srv, "ci", "secret").Push(ctx, l); err != nil {
		t.Fatal(err)
	}
	if len(f.refs)-before != 3 {
		t.Errorf("a second push wrote %d manifests, want the same three again", len(f.refs)-before)
	}
}

// A registry serving anything but the bytes built fails the check, whichever
// blob it is: an index, a manifest, a configuration or a layer.
func TestARegistryServingOtherBytesFailsTheCheck(t *testing.T) {
	l := build(t, images("v9.9.9"))
	ctx := context.Background()
	for d := range l.Blobs {
		f, srv := newFake()
		if err := registryFor(t, srv, "ci", "secret").Push(ctx, l); err != nil {
			t.Fatal(err)
		}
		f.tamper = d
		if err := registryFor(t, srv, "", "").Check(ctx, l); err == nil {
			t.Errorf("a registry serving a changed %s passed the check", d)
		}
		srv.Close()
	}

	// And a registry missing one passes nothing either.
	f, srv := newFake()
	defer srv.Close()
	if err := registryFor(t, srv, "ci", "secret").Push(ctx, l); err != nil {
		t.Fatal(err)
	}
	for d := range f.blobs {
		delete(f.blobs, d)
		break
	}
	if err := registryFor(t, srv, "", "").Check(ctx, l); err == nil {
		t.Error("a registry missing a blob passed the check")
	}
}

// The workflow's token goes to the registry's own host and nowhere else: a
// challenge naming another token endpoint, or an upload sent elsewhere, is
// refused before anything is sent there.
func TestTheCredentialsGoNowhereButTheRegistry(t *testing.T) {
	var collected int
	thief := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		collected++
		fmt.Fprint(w, `{"token":"push"}`)
	}))
	defer thief.Close()
	l := build(t, images("v9.9.9"))
	ctx := context.Background()

	f, srv := newFake()
	f.realm = thief.URL + "/token"
	if err := registryFor(t, srv, "ci", "secret").Push(ctx, l); err == nil {
		t.Error("a push followed a token endpoint on another host")
	}
	srv.Close()

	f, srv = newFake()
	defer srv.Close()
	f.location = thief.URL + "/upload"
	if err := registryFor(t, srv, "ci", "secret").Push(ctx, l); err == nil {
		t.Error("a push sent a blob to an upload location on another host")
	}
	if collected != 0 {
		t.Errorf("another host was sent %d requests", collected)
	}

	// And a registry anywhere but this machine is spoken to over TLS.
	if reg, err := NewRegistry("ghcr.io/denyfirst/porch"); err != nil || reg.scheme != "https" {
		t.Errorf("a remote registry is not spoken to over TLS: %v", err)
	}
}

// Without the credentials nothing is written.
func TestAPushWithoutCredentialsIsRefused(t *testing.T) {
	f, srv := newFake()
	defer srv.Close()
	if err := registryFor(t, srv, "", "").Push(context.Background(), build(t, images("v9.9.9"))); err == nil {
		t.Error("an anonymous push succeeded")
	}
	if len(f.blobs)+len(f.manifests) != 0 {
		t.Error("an anonymous push wrote something")
	}
}
