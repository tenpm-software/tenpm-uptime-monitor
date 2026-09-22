package monitor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

func tlsCheckFor(url, match string) model.Check {
	return model.Check{ID: 1, Name: "t", URL: url, MatchString: match, IntervalSec: 60, Enabled: true}
}

// selfSignedTLSListener accepts one TLS connection at a time, presenting a
// freshly minted, self-signed certificate for 127.0.0.1 with the given
// expiry - never trusted by the system root pool, so every test through it
// needs InsecureSkipVerify unless it's specifically exercising the refusal.
func selfSignedTLSListener(t *testing.T, notAfter time.Time) net.Listener {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// The handshake is lazy - it only actually runs once something
			// reads or writes, or calls Handshake explicitly. Driving it
			// here is what lets the client side's own HandshakeContext
			// complete rather than see the connection close mid-exchange.
			go func(c net.Conn) {
				defer c.Close()
				if tconn, ok := c.(*tls.Conn); ok {
					_ = tconn.HandshakeContext(context.Background())
				}
			}(conn)
		}
	}()
	return ln
}

func TestTLSCheckerHandshakeSuccess(t *testing.T) {
	ln := selfSignedTLSListener(t, time.Now().Add(60*24*time.Hour))
	check := tlsCheckFor("tls://"+ln.Addr().String(), "")
	check.InsecureSkipVerify = true

	r := NewTLSChecker().Run(context.Background(), check)
	if !r.Success || r.Error != "" {
		t.Fatalf("expected success on a completed handshake, got %+v", r)
	}
	if !strings.Contains(r.ResponseSample, "subject=CN=127.0.0.1") {
		t.Fatalf("expected the certificate summary as the response sample, got %q", r.ResponseSample)
	}
	if !strings.Contains(r.ResponseSample, "daysRemaining=") {
		t.Fatalf("expected daysRemaining in the response sample, got %q", r.ResponseSample)
	}
}

// TestTLSCheckerVerificationFails: a self-signed certificate is refused by
// ordinary chain verification, the same as HTTPChecker's own default
// behaviour against one - InsecureSkipVerify exists precisely to opt out of
// this.
func TestTLSCheckerVerificationFails(t *testing.T) {
	ln := selfSignedTLSListener(t, time.Now().Add(60*24*time.Hour))

	r := NewTLSChecker().Run(context.Background(), tlsCheckFor("tls://"+ln.Addr().String(), ""))
	if r.Success {
		t.Fatalf("expected an untrusted self-signed certificate to fail verification, got %+v", r)
	}
}

func TestTLSCheckerCertExpiryExceeded(t *testing.T) {
	ln := selfSignedTLSListener(t, time.Now().Add(24*time.Hour))
	check := tlsCheckFor("tls://"+ln.Addr().String(), "")
	check.InsecureSkipVerify = true
	check.CertExpiryWarnDays = 30

	r := NewTLSChecker().Run(context.Background(), check)
	if r.Success || !strings.Contains(r.Error, "certificate expires in") {
		t.Fatalf("expected a cert-expiry failure, got %+v", r)
	}
}

// TestTLSCheckerCertExpiryWithinThreshold: a generous CertExpiryWarnDays
// doesn't affect an otherwise-passing check - same shape
// TestTCPCheckerResponseTimeWithinThreshold pins for MaxResponseTimeMS.
func TestTLSCheckerCertExpiryWithinThreshold(t *testing.T) {
	ln := selfSignedTLSListener(t, time.Now().Add(90*24*time.Hour))
	check := tlsCheckFor("tls://"+ln.Addr().String(), "")
	check.InsecureSkipVerify = true
	check.CertExpiryWarnDays = 30

	r := NewTLSChecker().Run(context.Background(), check)
	if !r.Success {
		t.Fatalf("expected success within the expiry threshold, got error %q", r.Error)
	}
}

func TestTLSCheckerMatchString(t *testing.T) {
	ln := selfSignedTLSListener(t, time.Now().Add(60*24*time.Hour))
	url := "tls://" + ln.Addr().String()

	check := tlsCheckFor(url, "CN=127.0.0.1")
	check.InsecureSkipVerify = true
	if r := NewTLSChecker().Run(context.Background(), check); !r.Success {
		t.Fatalf("expected match-string success, got error %q", r.Error)
	}

	negated := tlsCheckFor(url, "CN=127.0.0.1")
	negated.InsecureSkipVerify = true
	negated.MatchMode = model.MatchNotContains
	if r := NewTLSChecker().Run(context.Background(), negated); r.Success || !strings.Contains(r.Error, "forbidden match string") {
		t.Fatalf("expected a forbidden-match failure, got %+v", r)
	}
}

func TestTLSCheckerMissingPort(t *testing.T) {
	r := NewTLSChecker().Run(context.Background(), tlsCheckFor("tls://example.com", ""))
	if r.Success || !strings.Contains(r.Error, "must include a port") {
		t.Fatalf("expected a missing-port failure, got %+v", r)
	}
}

func TestTLSCheckerClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // the port is now closed; connections will be refused

	r := NewTLSChecker().Run(context.Background(), tlsCheckFor("tls://"+addr, ""))
	if r.Success || r.Error == "" {
		t.Fatalf("expected failure on a closed port, got %+v", r)
	}
}
