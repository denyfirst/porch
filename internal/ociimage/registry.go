package ociimage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Registry speaks the OCI distribution protocol to one repository, by digest
// and never by tag.
//
// Written here rather than borrowed, because the bytes pushed have to be the
// bytes built: a client that re-compresses a layer on the way out changes its
// digest, and then the image in the registry is not the one the release
// signed. This one sends each blob as it is and names everything by the
// digest it already has.
type Registry struct {
	// Host is the registry's address; Name is the repository on it.
	Host, Name string

	// Username and Password are what the token endpoint is asked with. Empty
	// asks anonymously, which is how an installation pulls.
	Username, Password string

	Client *http.Client

	scheme string
	token  string
}

// NewRegistry parses "host/name". Plain HTTP is spoken only to a registry on
// this machine's loopback, which is what a test runs; anywhere else is TLS.
func NewRegistry(repository string) (*Registry, error) {
	host, name, ok := strings.Cut(repository, "/")
	if !ok || name == "" || !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return nil, fmt.Errorf("%q is not host/repository", repository)
	}
	scheme := "https"
	if h, _, err := net.SplitHostPort(host); err == nil && (h == "127.0.0.1" || h == "localhost" || h == "::1") {
		scheme = "http"
	}
	return &Registry{
		Host: host, Name: name, scheme: scheme,
		Client: &http.Client{Timeout: 5 * time.Minute},
	}, nil
}

// Push sends every blob the layout's index needs, then each manifest, then
// the index, all addressed by digest. A blob the registry already holds is not
// sent again.
func (r *Registry) Push(ctx context.Context, l *Layout) error {
	if err := l.Verify(); err != nil {
		return err
	}
	manifests, err := l.Manifests()
	if err != nil {
		return err
	}
	for _, m := range manifests {
		contents, err := l.Contents(m)
		if err != nil {
			return err
		}
		for _, d := range contents {
			if err := r.pushBlob(ctx, d, l.Blobs[d.Digest]); err != nil {
				return err
			}
		}
		if err := r.putManifest(ctx, m, l.Blobs[m.Digest]); err != nil {
			return err
		}
	}
	return r.putManifest(ctx, l.Index, l.Blobs[l.Index.Digest])
}

// Check reads the image back from the registry, anonymously when no
// credentials were given, and fails unless every manifest and blob it serves
// is the layout's, byte for byte.
func (r *Registry) Check(ctx context.Context, l *Layout) error {
	if err := l.Verify(); err != nil {
		return err
	}
	fetch := func(kind string, d Descriptor) error {
		accept := ""
		if kind == "manifests" {
			accept = d.MediaType
		}
		resp, err := r.do(ctx, http.MethodGet, r.url(kind+"/"+d.Digest), nil, accept, "")
		if err != nil {
			return err
		}
		defer resp.Body.Close() //nolint:errcheck // read to the end below
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("the registry does not serve %s: %s", d.Digest, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxLayout+1))
		if err != nil {
			return err
		}
		if !bytes.Equal(b, l.Blobs[d.Digest]) {
			return fmt.Errorf("the registry serves something else as %s", d.Digest)
		}
		return nil
	}

	if err := fetch("manifests", l.Index); err != nil {
		return err
	}
	manifests, err := l.Manifests()
	if err != nil {
		return err
	}
	for _, m := range manifests {
		if err := fetch("manifests", m); err != nil {
			return err
		}
		contents, err := l.Contents(m)
		if err != nil {
			return err
		}
		for _, d := range contents {
			if err := fetch("blobs", d); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Registry) url(path string) string {
	return r.scheme + "://" + r.Host + "/v2/" + r.Name + "/" + path
}

func (r *Registry) pushBlob(ctx context.Context, d Descriptor, b []byte) error {
	resp, err := r.do(ctx, http.MethodHead, r.url("blobs/"+d.Digest), nil, "", "")
	if err != nil {
		return err
	}
	resp.Body.Close() //nolint:errcheck,gosec // a HEAD has no body
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	resp, err = r.do(ctx, http.MethodPost, r.url("blobs/uploads/"), nil, "", "")
	if err != nil {
		return err
	}
	resp.Body.Close() //nolint:errcheck,gosec // the answer is in the headers
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("the registry refused an upload: %s", resp.Status)
	}
	loc, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
	if err != nil || resp.Header.Get("Location") == "" {
		return errors.New("the registry gave no upload location")
	}
	if loc.Host != r.Host {
		// An upload sent to another host would carry the token there.
		return fmt.Errorf("the registry asked for the upload at %s, which is not %s", loc.Host, r.Host)
	}
	q := loc.Query()
	q.Set("digest", d.Digest)
	loc.RawQuery = q.Encode()

	resp, err = r.do(ctx, http.MethodPut, loc.String(), b, "", "application/octet-stream")
	if err != nil {
		return err
	}
	resp.Body.Close() //nolint:errcheck,gosec // the status is the answer
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("the registry refused %s: %s", d.Digest, resp.Status)
	}
	return nil
}

func (r *Registry) putManifest(ctx context.Context, d Descriptor, b []byte) error {
	resp, err := r.do(ctx, http.MethodPut, r.url("manifests/"+d.Digest), b, "", d.MediaType)
	if err != nil {
		return err
	}
	resp.Body.Close() //nolint:errcheck,gosec // the status is the answer
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("the registry refused the manifest %s: %s", d.Digest, resp.Status)
	}
	if got := resp.Header.Get("Docker-Content-Digest"); got != "" && got != d.Digest {
		return fmt.Errorf("the registry stored the manifest %s as %s", d.Digest, got)
	}
	return nil
}

// do sends a request, and answers a registry's authentication challenge once:
// a bearer challenge by asking its token endpoint, a basic one with the
// credentials themselves.
func (r *Registry) do(ctx context.Context, method, target string, body []byte, accept, contentType string) (*http.Response, error) {
	send := func() (*http.Response, error) {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, rd)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if r.token != "" {
			req.Header.Set("Authorization", "Bearer "+r.token)
		}
		return r.Client.Do(req)
	}

	resp, err := send()
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close() //nolint:errcheck,gosec // replaced by the retry
	if err := r.authenticate(ctx, challenge); err != nil {
		return nil, err
	}
	return send()
}

func (r *Registry) authenticate(ctx context.Context, challenge string) error {
	kind, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(kind, "Bearer") {
		return fmt.Errorf("the registry asks for %q authentication, which this does not speak", kind)
	}
	fields := map[string]string{}
	for _, part := range splitParams(params) {
		k, v, ok := strings.Cut(part, "=")
		if ok {
			fields[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	// The credentials go to the registry's own host and over TLS, or not at
	// all: a challenge naming another host would otherwise collect the
	// workflow's token for whoever wrote it.
	realm, err := url.Parse(fields["realm"])
	if err != nil || realm.Host != r.Host || realm.Scheme != r.scheme {
		return fmt.Errorf("the registry's token endpoint %q is not one to send credentials to", fields["realm"])
	}
	q := realm.Query()
	if fields["service"] != "" {
		q.Set("service", fields["service"])
	}
	if fields["scope"] != "" {
		q.Set("scope", fields["scope"])
	}
	realm.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	if r.Username != "" {
		req.SetBasicAuth(r.Username, r.Password)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck // read below
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the registry's token endpoint refused: %s", resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return fmt.Errorf("the registry's token could not be read: %w", err)
	}
	r.token = tok.Token
	if r.token == "" {
		r.token = tok.AccessToken
	}
	if r.token == "" {
		return errors.New("the registry's token endpoint gave no token")
	}
	return nil
}

// splitParams splits a challenge's parameters on commas outside quotes:
// a scope can hold one ("pull,push").
func splitParams(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, c := range s {
		switch {
		case c == '"':
			quoted = !quoted
			cur.WriteRune(c)
		case c == ',' && !quoted:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	return append(out, cur.String())
}
