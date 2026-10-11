package mailscan

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/smtptls"
)

// The expiry is the presented leaf's, and nothing where nothing was presented.
func TestTheExchangersCertificateExpiryIsTheLeafs(t *testing.T) {
	end := time.Date(2027, 1, 7, 12, 0, 0, 0, time.UTC)
	got := leafExpiry(smtptls.Result{Chain: []*x509.Certificate{{NotAfter: end}, {NotAfter: end.AddDate(5, 0, 0)}}})
	if !got.Equal(end) {
		t.Errorf("read %v, want the leaf's %v", got, end)
	}
	if !leafExpiry(smtptls.Result{}).IsZero() || !leafExpiry(smtptls.Result{Chain: []*x509.Certificate{nil}}).IsZero() {
		t.Error("an expiry was read where no certificate was presented")
	}
}
