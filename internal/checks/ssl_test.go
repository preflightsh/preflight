package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/preflightsh/preflight/internal/config"
)

// A unit test cannot stand up a TLS listener SafeTLSDial will talk to (it
// refuses loopback), so these tests exercise the leaf-certificate grading
// and the error classification directly. That is where the bugs lived: the
// expiry branch was unreachable and the hostname branch used the wrong
// errors.As target.
func selfSignedCert(t *testing.T, notBefore, notAfter time.Time, dnsName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSSLExpiryGrading(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		notAfter time.Time
		severity Severity
		passed   bool
	}{
		{"expires in 3 days is an error", now.Add(3 * 24 * time.Hour), SeverityError, false},
		{"expires in 20 days is a warning", now.Add(20 * 24 * time.Hour), SeverityWarn, false},
		{"expires in 60 days passes", now.Add(60 * 24 * time.Hour), SeverityInfo, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := SSLCheck{}.expiryResult(selfSignedCert(t, now.Add(-time.Hour), tc.notAfter, "example.com"))
			if res.Severity != tc.severity || res.Passed != tc.passed {
				t.Errorf("got severity=%s passed=%v, want %s/%v (%s)", res.Severity, res.Passed, tc.severity, tc.passed, res.Message)
			}
		})
	}
}

// A handshake that rejected the certificate must fail the check, whatever
// the reason. Before this test every rejection was a warning.
func TestSSLVerificationFailureIsAnError(t *testing.T) {
	err := &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
	// peekLeafCertificate can't reach a fake host, so this exercises the
	// path where classification has only the handshake error to go on.
	res := SSLCheck{}.classifyDialError("invalid.invalid:443", err)
	if res.Passed || res.Severity != SeverityError {
		t.Errorf("verification failure graded %s passed=%v, want error", res.Severity, res.Passed)
	}
	if !strings.Contains(res.Message, "verification failed") {
		t.Errorf("message = %q", res.Message)
	}
}

// Connection-level failures (DNS, refused, timeout) stay warnings: they say
// the host is unreachable from here, not that the certificate is bad.
func TestSSLConnectFailureIsAWarning(t *testing.T) {
	res := SSLCheck{}.classifyDialError("invalid.invalid:443", &net.OpError{Op: "dial", Err: errRefused})
	if res.Severity != SeverityWarn {
		t.Errorf("connect failure graded %s, want warn", res.Severity)
	}
}

var errRefused = &net.DNSError{Err: "no such host", Name: "invalid.invalid", IsNotFound: true}

// Keep the http import used: a plain-HTTP production URL is graded before
// any dial happens.
func TestSSLRejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	res, _ := SSLCheck{}.Run(Context{Config: &config.PreflightConfig{URLs: config.URLConfig{Production: srv.URL}}})
	if res.Passed || res.Severity != SeverityError || !strings.Contains(res.Message, "HTTPS") {
		t.Errorf("plain http production URL: got %s passed=%v %q", res.Severity, res.Passed, res.Message)
	}
}
