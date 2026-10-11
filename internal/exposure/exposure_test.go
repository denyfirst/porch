package exposure

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// listening answers on one port of the list, through a dialler that sends
// that port to a local listener and refuses every other, and records what the
// listener was sent.
func listening(t *testing.T, open int) (*Prober, *[]string, func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var got []byte
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				b, _ := io.ReadAll(c)
				mu.Lock()
				got = append(got, b...)
				mu.Unlock()
			}()
		}
	}()

	var dialled []string
	var dmu sync.Mutex
	p := &Prober{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		dmu.Lock()
		dialled = append(dialled, address)
		dmu.Unlock()
		_, port, _ := net.SplitHostPort(address)
		if port != strconv.Itoa(open) {
			return nil, errors.New("refused")
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, ln.Addr().String())
	}}
	return p, &dialled, func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return append([]byte(nil), got...)
	}
}

// A service that answers is reported, and nothing is sent to it.
func TestAnOpenServiceIsReportedAndSentNothing(t *testing.T) {
	p, dialled, sent := listening(t, 3389)
	got := p.Probe(context.Background(), []string{"192.0.2.10:443"})

	if !got.Asked || got.Reason != "" || got.Ports != len(Services) {
		t.Fatalf("read %+v", got)
	}
	if len(got.Open) != 1 || got.Open[0].Port != 3389 || got.Open[0].Name != "Remote Desktop" || got.Open[0].Address != "192.0.2.10" {
		t.Errorf("open: %+v", got.Open)
	}
	if len(*dialled) != len(Services) {
		t.Errorf("%d connections, want one per port on the list", len(*dialled))
	}
	time.Sleep(50 * time.Millisecond)
	if b := sent(); len(b) != 0 {
		t.Errorf("something was sent to the service: %q", b)
	}
}

// At most two addresses, one of each family, whatever the host resolves to.
func TestOneAddressOfEachFamilyIsAsked(t *testing.T) {
	p, dialled, _ := listening(t, 0)
	got := p.Probe(context.Background(), []string{"192.0.2.10:443", "192.0.2.11:443", "[2001:db8::1]:443", "2001:db8::2", "not an address"})
	if len(got.Addresses) != 2 || got.Addresses[0] != "192.0.2.10" || got.Addresses[1] != "2001:db8::1" {
		t.Errorf("asked %v", got.Addresses)
	}
	if len(*dialled) != 2*len(Services) {
		t.Errorf("%d connections", len(*dialled))
	}
	if len(got.Open) != 0 {
		t.Errorf("nothing listened and %v is open", got.Open)
	}
}

// Without a dialler of its own, nothing private is reached, so a name that
// resolves inward is not a way to look at an internal network.
func TestThePrivateNetworkIsNeverAsked(t *testing.T) {
	got := (&Prober{}).Probe(context.Background(), []string{"127.0.0.1", "10.0.0.5"})
	if len(got.Open) != 0 {
		t.Errorf("a private address answered: %+v", got.Open)
	}
}

// No address is no answer, and said as one.
func TestNoAddressIsNotAnAnswer(t *testing.T) {
	if got := (&Prober{}).Probe(context.Background(), nil); got.Reason == "" || len(got.Open) != 0 {
		t.Errorf("read %+v", got)
	}
}

// The list is the list: sixteen services, each with a reason, none of them a
// port anything here serves on purpose.
func TestTheListIsFixedAndEachEntrySaysWhy(t *testing.T) {
	if len(Services) != 16 {
		t.Errorf("%d services; the list changes in the open, with this test", len(Services))
	}
	seen := map[int]bool{}
	for _, s := range Services {
		if s.Why == "" || s.Name == "" || seen[s.Port] {
			t.Errorf("entry %+v", s)
		}
		seen[s.Port] = true
		switch s.Port {
		case 22, 25, 53, 80, 443, 465, 587, 993, 995:
			t.Errorf("port %d is one a service is meant to answer on", s.Port)
		}
	}
}
