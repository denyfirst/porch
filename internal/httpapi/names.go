package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/mailscan"
	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/verify"
)

// The inventory endpoint: which names under a domain appear in publicly logged
// certificates.
//
// # Why this one is behind proof and the checks are not always
//
// A check measures how a host answers. Anybody may point this tool at a host
// they do not own and learn how it is reached, because that is what any visitor
// learns and the scanned party can see them doing it.
//
// This is different in both halves. What it produces is a list of somebody's
// names — the shape of an estate rather than the state of one host — and the
// scanned party cannot see it happen, because nothing is asked of them. A
// service that answered it for anybody would be an anonymous reconnaissance
// endpoint with this project's name on it, and the fact that the data is public
// does not change what the service would be doing: assembling it, on request,
// for people who will not say who they are.
//
// So it requires proof of control, always, on any deployment that has a scope
// at all — and where there is no scope it is refused rather than opened, which
// is the opposite of how the checks behave. An installation with no
// verification configured is one where nobody has been shown to own anything,
// and "nobody has proven anything" must not mean "everybody may ask".
//
// # And never on the demonstration
//
// That deployment promises it queries no transparency log (N12). This is the
// largest question this project knows how to put to one.
func (s *Server) handleNames(w http.ResponseWriter, r *http.Request) {
	t, ok := s.admit(w, r, parseNamesTarget, s.proofs, "Too many inventories from this address. Try again shortly.")
	if !ok {
		return
	}

	if demo.Enabled {
		s.refuse(w, http.StatusNotFound, "not_offered",
			"This deployment reads no certificate transparency logs.")
		return
	}

	scope := s.scanner.Verify
	if scope == nil {
		s.refuse(w, http.StatusForbidden, "proof_required",
			"An inventory of a domain's names is only produced for domains this "+
				"installation has been shown control of, and this installation has no "+
				"verification configured.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.limits.RequestTimeout)
	defer cancel()

	switch _, err := scope.CoversSigned(ctx, t.host, verify.AnyPort); {
	case err == nil:
	case errors.Is(err, verify.ErrNotVerified):
		s.refuse(w, http.StatusForbidden, "proof_required",
			"Publish the proof record for this domain first. An inventory is only "+
				"produced for domains this installation has been shown control of.")
		return
	default:
		// The lookup failed, which is not the domain being unverified. Telling
		// somebody to publish a record they have already published would send
		// them to the wrong place.
		s.refuse(w, http.StatusBadGateway, "scan_failed",
			"The proof record could not be looked up. Try again shortly.")
		return
	}

	// Only now, after proof. Whether this installation has a monitor is a fact
	// about the installation, and telling somebody who has not proven anything
	// is answering a question they were not entitled to ask.
	//
	// Refused rather than answered with an empty inventory, which would report
	// an estate as publishing nothing (R4).
	if s.names == nil {
		s.refuse(w, http.StatusNotFound, "not_offered",
			"This installation was not started with a certificate transparency monitor.")
		return
	}

	// A slot of its own. One inventory is several requests to a monitor, and a
	// queue of them must not hold the slots a scan needs.
	if err := s.proofSem.acquire(ctx); err != nil {
		w.Header().Set("Retry-After", "5")
		s.refuse(w, http.StatusServiceUnavailable, "too_busy",
			"Too many inventories are in flight. Try again shortly.")
		return
	}
	defer s.proofSem.release()

	found := s.names.SearchEstate(ctx, t.host)
	if ctx.Err() != nil {
		s.refuse(w, http.StatusGatewayTimeout, "timeout",
			"The inventory did not finish within the time allowed.")
		return
	}

	writeJSON(w, http.StatusOK, found)
}

// parseNamesTarget takes a bare domain.
//
// A port or a path means somebody is asking a question this endpoint does not
// answer, and answering the nearest one instead is how a report comes to be
// about something other than what was asked. A mail address has its local part
// dropped first, as everywhere else, so that pasting one here discloses no more
// than pasting it into a check.
func parseNamesTarget(raw string) (target, *refusal) {
	raw, _ = mailscan.DropLocalPart(raw)

	host, port, _, err := scan.SplitTargetPort(raw)
	if err != nil {
		return target{}, &refusal{
			status:  http.StatusBadRequest,
			code:    "invalid_target",
			message: "That is not a domain name. Give a name such as example.com.",
		}
	}
	if port != "" && port != "443" {
		return target{}, &refusal{
			status:  http.StatusBadRequest,
			code:    "invalid_target",
			message: "An inventory is of a domain rather than of a port. Give a name such as example.com.",
		}
	}
	return target{host: strings.ToLower(host), scope: scan.DefaultPort}, nil
}
