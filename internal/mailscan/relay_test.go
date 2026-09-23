package mailscan

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/denyfirst/porch/internal/dnsclient"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/smtptls"
)

// relayExchangers records which exchangers were asked the relay question and
// which were only measured.
type relayExchangers struct {
	mu       sync.Mutex
	measured []string
	relayed  []string

	// accepting names the hosts that answer as open relays.
	accepting map[string]bool
}

func (r *relayExchangers) Probe(_ context.Context, host string) smtptls.Result {
	r.mu.Lock()
	r.measured = append(r.measured, host)
	r.mu.Unlock()
	return smtptls.Result{Host: host, Connected: true, Measured: true}
}

func (r *relayExchangers) ProbeRelay(_ context.Context, host string) smtptls.Result {
	r.mu.Lock()
	r.relayed = append(r.relayed, host)
	r.mu.Unlock()
	return smtptls.Result{
		Host: host, Connected: true, Measured: true,
		RelayAsked:    true,
		RelayAccepted: r.accepting[host],
		RelayReason:   reasonFor(r.accepting[host]),
	}
}

func reasonFor(accepted bool) string {
	if accepted {
		return ""
	}
	return "the server refused it (554)"
}

func (r *relayExchangers) lists() (measured, relayed []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	measured = append([]string(nil), r.measured...)
	relayed = append([]string(nil), r.relayed...)
	slices.Sort(measured)
	slices.Sort(relayed)
	return measured, relayed
}

// The relay question goes to an exchanger inside the domain being checked and
// to no other.
//
// An exchanger named by an MX record but run by a provider is that provider's
// server: a relay probe in their logs reads as a spam probe, and the address
// it came from is the one that gets listed for it.
func TestTheRelayQuestionGoesOnlyToTheDomainsOwnExchangers(t *testing.T) {
	skipUnderDemo(t)

	// notexample.com ends with the domain and is not inside it, which is the
	// difference a suffix test without the dot gets wrong.
	z := stsZone("mail.example.com", "mx.mail.example.com", "aspmx.provider.net",
		"example.com.attacker.test", "notexample.com")
	x := &relayExchangers{accepting: map[string]bool{}}

	got, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	measured, relayed := x.lists()
	if !slices.Equal(relayed, []string{"mail.example.com", "mx.mail.example.com"}) {
		t.Errorf("the relay question went to %v", relayed)
	}
	if !slices.Equal(measured, []string{"aspmx.provider.net", "example.com.attacker.test", "notexample.com"}) {
		t.Errorf("the exchangers measured without it were %v", measured)
	}

	// And the report says, per exchanger, whether it was asked at all.
	for _, x := range got.Observed.Exchangers {
		inside := x.Host == "mail.example.com" || x.Host == "mx.mail.example.com"
		if x.RelayAsked != inside {
			t.Errorf("%s: asked %v, want %v", x.Host, x.RelayAsked, inside)
		}
	}
}

// An exchanger that said it would forward for a domain that is not its own is
// graded insecure; one that refused, and one that was never asked, are not.
func TestAnOpenRelayIsGradedAndSilenceIsNot(t *testing.T) {
	skipUnderDemo(t)

	z := stsZone("mail.example.com", "aspmx.provider.net")
	x := &relayExchangers{accepting: map[string]bool{"mail.example.com": true}}

	got, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: x}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var found *policy.Finding
	for i, f := range got.Findings {
		if f.RuleID == "mail.open-relay" {
			found = &got.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("an open relay was not graded: %v", got.Findings)
	}
	if found.Verdict != policy.Insecure || got.Verdict != policy.Insecure {
		t.Errorf("verdicts are %q and %q", found.Verdict, got.Verdict)
	}
	if !strings.Contains(found.Rationale, "mail.example.com") {
		t.Errorf("the finding does not name the exchanger: %s", found.Rationale)
	}
	if strings.Contains(found.Rationale, "aspmx.provider.net") {
		t.Errorf("the finding names an exchanger that was never asked: %s", found.Rationale)
	}

	// Nothing accepted, nothing graded.
	closed := &relayExchangers{accepting: map[string]bool{}}
	shut, err := (&Scanner{Resolver: z, ReadExchangers: true, Exchangers: closed}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range shut.Findings {
		if f.RuleID == "mail.open-relay" {
			t.Errorf("a server that refused was graded as a relay: %+v", f)
		}
	}
}

// An exchanger whose name is an alias is found by asking the name itself, and
// graded: RFC 2181 forbids it, and it is the hardest kind of delivery problem
// to find, because mail from some senders arrives and mail from others does
// not.
func TestAnExchangerThatIsAnAliasIsGraded(t *testing.T) {
	skipUnderDemo(t)

	z := stsZone("mail.example.com", "aspmx.provider.net")
	z.aliases = map[string][]string{"mail.example.com": {"host.provider.example"}}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got.Observed.MXAliases) != 1 || got.Observed.MXAliases[0] != "mail.example.com" {
		t.Errorf("the aliases read %v", got.Observed.MXAliases)
	}

	var found *policy.Finding
	for i, f := range got.Findings {
		if f.RuleID == "mail.exchanger-is-an-alias" {
			found = &got.Findings[i]
		}
	}
	if found == nil || found.Verdict != policy.Weak {
		t.Fatalf("an aliased exchanger: %v", got.Findings)
	}
	if !strings.Contains(found.Rationale, "mail.example.com") || strings.Contains(found.Rationale, "aspmx.provider.net") {
		t.Errorf("the finding names the wrong exchangers: %s", found.Rationale)
	}

	// A domain whose exchangers are plain names is not graded for it, and a
	// lookup that failed is not an alias.
	plain := stsZone("mail.example.com")
	if got, _ := (&Scanner{Resolver: plain}).Scan(context.Background(), "example.com"); len(got.Observed.MXAliases) != 0 {
		t.Errorf("plain names read as aliases: %v", got.Observed.MXAliases)
	}
	unread := stsZone("mail.example.com")
	unread.fail = map[string]error{"cname:mail.example.com": dnsclient.ErrServerFail}
	if got, _ := (&Scanner{Resolver: unread}).Scan(context.Background(), "example.com"); len(got.Observed.MXAliases) != 0 {
		t.Errorf("a failed lookup read as an alias: %v", got.Observed.MXAliases)
	}
}

// The alias question is asked of as many exchangers as are contacted and no
// more. The list belongs to whoever is being measured, so a domain naming
// forty of them buys forty lookups from this machine unless something bounds
// it — which is the same bound the exchangers themselves have.
func TestTheAliasQuestionIsBoundedLikeTheExchangers(t *testing.T) {
	skipUnderDemo(t)

	var many []string
	for i := range maxExchangers + 4 {
		many = append(many, "mx"+string(rune('a'+i))+".example.com")
	}
	z := stsZone(many...)
	z.aliases = map[string][]string{}
	for _, host := range many {
		z.aliases[host] = []string{"host.provider.example"}
	}

	got, err := (&Scanner{Resolver: z}).Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got.Observed.MXAliases) != maxExchangers {
		t.Errorf("%d exchangers were asked, want the bound of %d", len(got.Observed.MXAliases), maxExchangers)
	}
}
