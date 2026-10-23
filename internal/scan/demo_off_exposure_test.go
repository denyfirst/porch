//go:build !demo

package scan

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/exposure"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/tlsprobe"
)

// A scan asks the exposure prober about the addresses its handshakes reached,
// and what answered reaches the line both faces show and the notes.
func TestAScanSaysWhichRiskyServicesAnswer(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	var mu sync.Mutex
	var asked []string
	d := &net.Dialer{Timeout: 5 * time.Second}
	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, net.JoinHostPort(host, port))
			},
			TotalTimeout: 20 * time.Second,
		},
		AllowAnyPort:   true,
		AllowIPTargets: true,
		Exposure: &exposure.Prober{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			asked = append(asked, address)
			mu.Unlock()
			if strings.HasSuffix(address, ":3389") {
				// Any connection that opens will do; nothing is sent over it.
				return d.DialContext(ctx, network, net.JoinHostPort(host, port))
			}
			return nil, errors.New("refused")
		}},
	}

	out, err := s.Scan(context.Background(), "denyfirst.dev:443")
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != len(exposure.Services) {
		t.Errorf("%d ports asked, want the list", len(asked))
	}
	if out.ExposureLine != "Remote Desktop (3389) answers to anybody on the internet" {
		t.Errorf("the line reads %q", out.ExposureLine)
	}
	notes := strings.Join(noteTexts(out), " ")
	if !strings.Contains(notes, "Remote Desktop answers on port 3389") {
		t.Errorf("the notes do not name it: %s", notes)
	}

	// And every port asked is listed, in the list's order, with what came back.
	if len(out.ExposureChecked) != len(exposure.Services) {
		t.Fatalf("%d ports listed, want the list", len(out.ExposureChecked))
	}
	for i, c := range out.ExposureChecked {
		svc := exposure.Services[i]
		if c.Item != strconv.Itoa(svc.Port) || c.What != svc.Name {
			t.Errorf("item %d is %+v, want port %d %s", i, c, svc.Port, svc.Name)
		}
		if open := svc.Port == 3389; c.Found != open || (open && !strings.HasPrefix(c.State, "answers at ")) || (!open && c.State != "no answer from here") {
			t.Errorf("port %d reads %+v", svc.Port, c)
		}
	}

	// Graded, and the grade reaches the verdict.
	if !slices.ContainsFunc(out.Findings(), func(f policy.Finding) bool {
		return f.RuleID == "exposure.service-open" && f.Verdict == policy.Weak
	}) {
		t.Errorf("Remote Desktop answers and no exposure.service-open finding was raised: %v", out.Findings())
	}
	if out.Verdict.Rank() < policy.Weak.Rank() {
		t.Errorf("Remote Desktop answers and the scan graded %q", out.Verdict)
	}

	s.Exposure = nil
	if out, _ := s.Scan(context.Background(), "denyfirst.dev:443"); out.ExposureLine != "" || out.Exposure != nil || len(out.ExposureFindings) != 0 {
		t.Errorf("a scan with no prober reports %q, %v", out.ExposureLine, out.ExposureFindings)
	}
}

// A host where every port asked accepts a connection is not running twenty-one
// services. It is completing every connection, the way a SYN proxy or a tarpit
// does, and none of it is graded or named as a service.
func TestAHostAcceptingEveryPortIsNotGradedForIt(t *testing.T) {
	host, port := revocationServer(t, "http://lists.example/one.crl")

	d := &net.Dialer{Timeout: 5 * time.Second}
	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, net.JoinHostPort(host, port))
			},
			TotalTimeout: 20 * time.Second,
		},
		AllowAnyPort:   true,
		AllowIPTargets: true,
	}
	without, err := s.Scan(context.Background(), "denyfirst.dev:443")
	if err != nil {
		t.Fatal(err)
	}

	s.Exposure = &exposure.Prober{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, net.JoinHostPort(host, port))
	}}
	out, err := s.Scan(context.Background(), "denyfirst.dev:443")
	if err != nil {
		t.Fatal(err)
	}

	if len(out.ExposureFindings) != 0 {
		t.Errorf("every port answered and it was graded: %v", out.ExposureFindings)
	}
	if out.Verdict != without.Verdict {
		t.Errorf("every port answering moved the verdict from %q to %q", without.Verdict, out.Verdict)
	}
	if !strings.Contains(out.ExposureLine, "accepts a connection") || strings.Contains(out.ExposureLine, "Remote Desktop") {
		t.Errorf("the line reads %q", out.ExposureLine)
	}
	notes := strings.Join(noteTexts(out), " ")
	if strings.Contains(notes, "answers on port") || !strings.Contains(notes, "not established and none is graded") {
		t.Errorf("the notes read: %s", notes)
	}
}

func noteTexts(r *Result) []string {
	var out []string
	for _, n := range r.Notes() {
		out = append(out, n.Text)
	}
	return out
}
