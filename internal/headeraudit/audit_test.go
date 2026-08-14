package headeraudit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "https://example.com/path?x=1", false},
		{"http rejected", "http://example.com", true},
		{"userinfo rejected", "https://user:pass@example.com", true},
		{"fragment rejected", "https://example.com/#section", true},
		{"invalid port", "https://example.com:99999", true},
		{"surrounding whitespace", " https://example.com", true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := validateURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateURL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIP(t *testing.T) {
	t.Parallel()

	if err := validateIP([]byte{127, 0, 0, 1}, false); err == nil {
		t.Fatal("loopback should be blocked without allow-private")
	}
	if err := validateIP([]byte{127, 0, 0, 1}, true); err != nil {
		t.Fatalf("loopback should be allowed with allow-private: %v", err)
	}
	if err := validateIP([]byte{169, 254, 169, 254}, true); err == nil {
		t.Fatal("link-local metadata address must remain blocked")
	}
	if err := validateIP([]byte{8, 8, 8, 8}, false); err != nil {
		t.Fatalf("public unicast should be allowed: %v", err)
	}
}

func TestAuditTLSFixture(t *testing.T) {
	t.Parallel()

	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=()")
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewTLSServer(h)
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())

	result, err := Audit(context.Background(), server.URL, Config{
		Timeout:      5 * time.Second,
		AllowPrivate: true,
		RootCAs:      pool,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if result.StatusCode != http.StatusNoContent {
		t.Fatalf("StatusCode = %d, want %d", result.StatusCode, http.StatusNoContent)
	}
	if result.TLS.Version == "" || result.TLS.CipherSuite == "" {
		t.Fatalf("TLS information missing: %+v", result.TLS)
	}
	for _, finding := range result.Findings {
		if finding.Status != "pass" {
			t.Fatalf("unexpected non-pass finding: %+v", finding)
		}
	}
}

func TestAuditRedirectsDefaultOff(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())

	result, err := Audit(context.Background(), server.URL+"/start", Config{
		Timeout:      5 * time.Second,
		AllowPrivate: true,
		RootCAs:      pool,
		MaxRedirects: 0,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if result.StatusCode != http.StatusFound {
		t.Fatalf("StatusCode = %d, want %d", result.StatusCode, http.StatusFound)
	}
	if result.FinalURL != server.URL+"/start" {
		t.Fatalf("FinalURL = %q; redirect should not have been followed", result.FinalURL)
	}
	if len(result.Redirects) != 0 {
		t.Fatalf("Redirects = %#v, want empty", result.Redirects)
	}
}

func TestAuditFollowsExplicitRedirectLimit(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())

	result, err := Audit(context.Background(), server.URL+"/start", Config{
		Timeout:      5 * time.Second,
		AllowPrivate: true,
		RootCAs:      pool,
		MaxRedirects: 1,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if result.StatusCode != http.StatusNoContent {
		t.Fatalf("StatusCode = %d, want %d", result.StatusCode, http.StatusNoContent)
	}
	if len(result.Redirects) != 1 {
		t.Fatalf("Redirects = %#v, want one redirect", result.Redirects)
	}
}

func TestAuditUntrustedCertificateIsTLSError(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, err := Audit(context.Background(), server.URL, Config{
		Timeout:      5 * time.Second,
		AllowPrivate: true,
	})
	if err == nil {
		t.Fatal("Audit() error = nil, want TLS verification error")
	}
	auditErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if auditErr.Kind != ErrTLS {
		t.Fatalf("error kind = %s, want %s", auditErr.Kind, ErrTLS)
	}
}

func TestClassifyRequestError(t *testing.T) {
	t.Parallel()

	tlsErr := classifyRequestError(x509.UnknownAuthorityError{})
	if got := tlsErr.(*Error).Kind; got != ErrTLS {
		t.Fatalf("TLS error kind = %s, want %s", got, ErrTLS)
	}

	networkErr := classifyRequestError(errors.New("connection refused"))
	if got := networkErr.(*Error).Kind; got != ErrNetwork {
		t.Fatalf("network error kind = %s, want %s", got, ErrNetwork)
	}
}

func TestInspectTLS(t *testing.T) {
	t.Parallel()

	state := &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}

	good := inspectTLS(state, time.Now().Add(30*24*time.Hour))
	if good.Status != "pass" {
		t.Fatalf("good certificate status = %s, want pass", good.Status)
	}

	near := inspectTLS(state, time.Now().Add(24*time.Hour))
	if near.Status != "warn" {
		t.Fatalf("near-expiry status = %s, want warn", near.Status)
	}

	expired := inspectTLS(state, time.Now().Add(-time.Hour))
	if expired.Status != "warn" || expired.Message != "TLS certificate is expired" {
		t.Fatalf("expired finding = %+v", expired)
	}
}

func TestTLSVersionName(t *testing.T) {
	t.Parallel()

	tests := map[uint16]string{
		tls.VersionTLS13: "TLS 1.3",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS10: "TLS 1.0",
		0x9999:           "0x9999",
	}
	for version, want := range tests {
		if got := tlsVersionName(version); got != want {
			t.Fatalf("tlsVersionName(%#x) = %q, want %q", version, got, want)
		}
	}
}
