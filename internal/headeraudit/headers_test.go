package headeraudit

import (
	"net/http"
	"testing"
)

func TestInspectHeadersWeakSet(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=300")
	h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
	h.Set("X-Content-Type-Options", "invalid")
	h.Set("Referrer-Policy", "unsafe-url")

	findings := inspectHeaders(h)
	if len(findings) != 6 {
		t.Fatalf("len(findings) = %d, want 6", len(findings))
	}
	for _, finding := range findings {
		if finding.Status != "warn" {
			t.Fatalf("finding %s = %s, want warn", finding.ID, finding.Status)
		}
	}
}

func TestClickjackingCSPFallback(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	finding := inspectClickjacking(h)
	if finding.Status != "pass" {
		t.Fatalf("status = %s, want pass", finding.Status)
	}
}
