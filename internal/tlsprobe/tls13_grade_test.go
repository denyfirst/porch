package tlsprobe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/denyfirst/porch/internal/policy"
)

// serverPredatingTLS13 answers every hello with a TLS 1.2 ServerHello and
// nothing else, which is what a server that has never heard of TLS 1.3 does
// with a hello offering only 1.3: it ignores the extension it does not know
// and answers in the version the hello's header names.
//
// Go's own server cannot be made to do this. Configured without TLS 1.3 it
// reads the extension and sends a protocol_version alert, which is the
// answer a modern server gives and not the one most servers without 1.3 give.
func serverPredatingTLS13(t *testing.T) (host, port string) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	hello := []byte{
		0x02, 0x00, 0x00, 0x26, // ServerHello, 38 bytes
		0x03, 0x03, // TLS 1.2
	}
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello,
		0x00,       // no session id
		0xc0, 0x2f, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0x00, // no compression
	)
	record := append([]byte{0x16, 0x03, 0x03, 0x00, byte(len(hello))}, hello...)

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				header := make([]byte, 5)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, int(header[3])<<8|int(header[4]))); err != nil {
					return
				}
				_, _ = c.Write(record)
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()

	host, port, _ = net.SplitHostPort(l.Addr().String())
	return host, port
}

// A server that answers a TLS 1.3 hello in TLS 1.2 has declined TLS 1.3.
//
// Go reports it as "server selected unsupported protocol version 303", and
// until 2026-10-23 the words "unsupported protocol version" put that in the
// case for a version this build of Go would not offer. A server without TLS
// 1.3 was reported as never asked, and with TLS 1.3 now graded, it would have
// escaped the grade too.
func TestAServerAnsweringTLS13InTLS12IsARefusal(t *testing.T) {
	host, port := serverPredatingTLS13(t)

	p := &Prober{Dial: (&net.Dialer{}).DialContext}
	_, _, err := p.handshake(context.Background(), host, port, tls.VersionTLS13, nil, nil, newAddressSet())
	if err == nil {
		t.Fatal("a TLS 1.3 handshake completed against a server that answered in TLS 1.2")
	}

	text, refused := classifyHandshakeError(err, tls.VersionTLS13)
	if !refused {
		t.Errorf("%q was classified as %q and not as a refusal. The server answered: it chose TLS 1.2.", err, text)
	}
	if strings.Contains(text, "declined to offer") {
		t.Errorf("classified as %q. This build of Go offered TLS 1.3; the server is the one that declined.", text)
	}
}

// The client declining to offer a version is still not the server refusing
// it. The case above sits beside this one and must not swallow it.
func TestAVersionThisClientWillNotOfferIsStillNotARefusal(t *testing.T) {
	text, refused := classifyHandshakeError(
		errorString("tls: no supported versions satisfy MinVersion and MaxVersion"), tls.VersionTLS10)
	if refused || !strings.Contains(text, "declined to offer") {
		t.Errorf("a version this client would not offer was classified as %q, refused=%v", text, refused)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

func strongTLS12() VersionResult {
	return VersionResult{
		Version: tls.VersionTLS12, Name: "TLS 1.2", Supported: true,
		Grade:              policy.GradeVersion(tls.VersionTLS12),
		Ciphers:            []CipherResult{gradeCipher(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)},
		CipherListComplete: true,
	}
}

// Sound TLS 1.2 and no TLS 1.3 is weak, and says why.
func TestWithoutTLS13TheTransportIsWeak(t *testing.T) {
	verdict, findings := summarise([]VersionResult{
		{Version: tls.VersionTLS13, Name: "TLS 1.3", Refused: true, Error: "server refused TLS 1.3"},
		strongTLS12(),
	})
	if verdict != policy.Weak {
		t.Errorf("graded %q, want weak", verdict)
	}
	if !slices.ContainsFunc(findings, func(f policy.Finding) bool {
		return f.RuleID == "version.no-tls13" && f.Verdict == policy.Weak && f.Policy == policy.TLSVersion
	}) {
		t.Errorf("no version.no-tls13 finding in %+v; a weak verdict nobody can explain is not a verdict", findings)
	}
}

// A TLS 1.3 handshake that did not finish proves nothing either way. Strong
// would claim it was accepted, weak would claim it was refused.
func TestAnUnmeasuredTLS13IsNeitherStrongNorWeak(t *testing.T) {
	for _, why := range []string{"the connection timed out", "the connection closed during the handshake"} {
		verdict, findings := summarise([]VersionResult{
			{Version: tls.VersionTLS13, Name: "TLS 1.3", Error: why},
			strongTLS12(),
		})
		if verdict != policy.Ungraded {
			t.Errorf("TLS 1.3 %s, sound TLS 1.2: graded %q, want ungraded", why, verdict)
		}
		for _, f := range findings {
			if f.RuleID == "version.no-tls13" {
				t.Errorf("TLS 1.3 %s and the report says the server declined it", why)
			}
		}
	}

	// A weakness that was seen stays seen.
	weak := strongTLS12()
	weak.Ciphers = append(weak.Ciphers, gradeCipher(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA))
	if verdict, _ := summarise([]VersionResult{
		{Version: tls.VersionTLS13, Name: "TLS 1.3", Error: "the connection timed out"},
		weak,
	}); verdict != policy.Weak {
		t.Errorf("a weak suite seen beside an unmeasured TLS 1.3 graded %q, want weak", verdict)
	}
}

// A server refusing everything has no connection to describe, and a missing
// version is not graded on top of nothing.
func TestARefusalOfEveryVersionRaisesNoVersionFinding(t *testing.T) {
	verdict, findings := summarise([]VersionResult{
		{Version: tls.VersionTLS13, Name: "TLS 1.3", Refused: true},
		{Version: tls.VersionTLS12, Name: "TLS 1.2", Refused: true},
	})
	if verdict != policy.Ungraded || len(findings) != 0 {
		t.Errorf("every version refused: graded %q with %+v, want ungraded and nothing", verdict, findings)
	}
}

// End to end: a real server without TLS 1.3 comes back weak, with the
// finding, and a real server with it does not carry the finding.
func TestAProbedServerWithoutTLS13IsGradedWeak(t *testing.T) {
	host, port := serverAccepting(t, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256})

	report, err := (&Prober{Dial: (&net.Dialer{}).DialContext}).Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if report.Verdict != policy.Weak {
		t.Errorf("a TLS 1.2-only server with one strong suite graded %q, want weak", report.Verdict)
	}
	if !slices.ContainsFunc(report.Findings, func(f policy.Finding) bool { return f.RuleID == "version.no-tls13" }) {
		t.Errorf("no version.no-tls13 among %+v", report.Findings)
	}
}

// The reader is told why a server with sound suites was not graded strong.
func TestAnUnmeasuredTLS13IsSaidInTheReport(t *testing.T) {
	host, port := serverAccepting(t, []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256})

	// Every TLS 1.3 hello is cut off before it reaches the server.
	p := &Prober{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &cutTLS13{Conn: c}, nil
	}}
	report, err := p.Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if report.Verdict == policy.Strong || report.Verdict == policy.Weak {
		t.Errorf("TLS 1.3 never answered and the transport graded %q", report.Verdict)
	}
	if !slices.ContainsFunc(report.Notes, func(n policy.Note) bool {
		return strings.Contains(n.Text, "Whether TLS 1.3 is accepted was not established")
	}) {
		t.Errorf("no note says TLS 1.3 was not established; notes: %+v", report.Notes)
	}
}

// cutTLS13 closes a connection whose first write is a hello offering TLS 1.3,
// the way a middlebox that does not understand it might.
type cutTLS13 struct {
	net.Conn
	seen bool
}

func (c *cutTLS13) Write(b []byte) (int, error) {
	if !c.seen {
		c.seen = true
		// supported_versions (0x002b) listing 0x0304.
		if i := strings.Index(string(b), "\x00\x2b"); i >= 0 && strings.Contains(string(b[i:]), "\x03\x04") {
			_ = c.Conn.Close()
			return 0, io.EOF
		}
	}
	return c.Conn.Write(b)
}

// The transport's verdict matrix: what summarise owes each answer a server
// can give across the versions. See internal/policy/matrix_test.go for why a
// table of whole answers exists beside the tests of each rule.
func TestTheTransportVerdictMatrix(t *testing.T) {
	accepted := func(version uint16, suite uint16) VersionResult {
		return VersionResult{
			Version: version, Name: versionName(version), Supported: true,
			Grade:              policy.GradeVersion(version),
			Ciphers:            []CipherResult{gradeCipher(suite)},
			CipherListComplete: true,
		}
	}
	refused := func(version uint16) VersionResult {
		return VersionResult{Version: version, Name: versionName(version), Refused: true, Error: "server refused"}
	}
	timedOut := func(version uint16) VersionResult {
		return VersionResult{Version: version, Name: versionName(version), Error: "the connection timed out"}
	}
	tls13 := accepted(tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256)
	tls12 := accepted(tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	unfinished := tls12
	unfinished.CipherListComplete = false

	for _, row := range []struct {
		situation string
		results   []VersionResult
		want      policy.Verdict
		rule      string
	}{
		{"accepts TLS 1.3 and 1.2 with sound suites and refuses the rest",
			[]VersionResult{tls13, tls12, refused(tls.VersionTLS11), refused(tls.VersionTLS10)}, policy.Strong, ""},
		{"accepts TLS 1.3 alone",
			[]VersionResult{tls13, refused(tls.VersionTLS12), refused(tls.VersionTLS11), refused(tls.VersionTLS10)}, policy.Strong, ""},
		{"accepts TLS 1.2 with sound suites and refuses TLS 1.3",
			[]VersionResult{refused(tls.VersionTLS13), tls12, refused(tls.VersionTLS11), refused(tls.VersionTLS10)}, policy.Weak, "version.no-tls13"},
		{"accepts TLS 1.2 and did not finish a TLS 1.3 handshake",
			[]VersionResult{timedOut(tls.VersionTLS13), tls12, refused(tls.VersionTLS11), refused(tls.VersionTLS10)}, policy.Ungraded, ""},
		{"accepts TLS 1.3 and still accepts TLS 1.0",
			[]VersionResult{tls13, tls12, refused(tls.VersionTLS11), accepted(tls.VersionTLS10, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)}, policy.Insecure, "version.deprecated"},
		{"accepts TLS 1.3 and stopped answering partway through the TLS 1.2 suites",
			[]VersionResult{tls13, unfinished, refused(tls.VersionTLS11), refused(tls.VersionTLS10)}, policy.Ungraded, ""},
		{"refuses every version",
			[]VersionResult{refused(tls.VersionTLS13), refused(tls.VersionTLS12), refused(tls.VersionTLS11), refused(tls.VersionTLS10)}, policy.Ungraded, ""},
		{"answers nothing",
			[]VersionResult{timedOut(tls.VersionTLS13), timedOut(tls.VersionTLS12), timedOut(tls.VersionTLS11), timedOut(tls.VersionTLS10)}, policy.Ungraded, ""},
	} {
		t.Run(row.situation, func(t *testing.T) {
			got, findings := summarise(row.results)
			if got != row.want {
				t.Errorf("a server that %s is graded %q, want %q", row.situation, got, row.want)
			}
			if row.rule != "" && !slices.ContainsFunc(findings, func(f policy.Finding) bool { return f.RuleID == row.rule }) {
				t.Errorf("a server that %s is graded without %s: %+v", row.situation, row.rule, findings)
			}
		})
	}
}
