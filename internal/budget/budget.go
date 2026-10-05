// Package budget keeps time back for the report a measurement belongs to.
//
// A check measures something and then asks others about it: the TLS check
// asks a revocation list, a responder, the logs and the zone's CAA records;
// the mail check asks the exchangers; the web check asks for the security
// contact, the IPv6 address and the other form of the name. The service
// counts a check that overran its request as a timeout and sends nothing of
// it, which is right for the measurement and wrong for those questions: one
// slow party at the end cost the whole report (audit 2026-10-05, F10 and F11).
// So they are asked with a context that ends a little before the request's,
// and what they did not establish is said in the report instead.
package budget

import (
	"context"
	"time"
)

// Reserve is how long before the caller's deadline those questions give up,
// so that the report is written and sent in time. What follows them is
// arithmetic on what was read.
const Reserve = 2 * time.Second

// ShortOf is ctx ending reserve before ctx's own deadline, or ctx unchanged
// when it has none. A deadline already within the reserve gives a context that
// is already done, so a question asked with it gives up at once.
func ShortOf(ctx context.Context, reserve time.Duration) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline.Add(-reserve))
}

// Half is ctx ending halfway between now and ctx's own deadline, or ctx
// unchanged when it has none.
//
// For a third party asked before a measurement rather than after it: the
// names inventory asks a transparency monitor, then reads what each name it
// found is doing and the certificate each answering host presents. Asked with
// the request's whole deadline, a monitor that never answered took all of it,
// and on 2026-10-05 the demonstration's inventory came back with no names, its
// own records unread and nothing asked of its hosts (audit F12). With half,
// the estate's own hosts keep the other half however slow the monitor is.
func Half(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, time.Now().Add(time.Until(deadline)/2))
}
