package headeraudit

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWriteText(t *testing.T) {
	t.Parallel()

	result := Result{
		RequestedURL: "https://example.com/start",
		FinalURL:     "https://example.com/final",
		StatusCode:   200,
		Protocol:     "HTTP/2.0",
		Redirects:    []string{"https://example.com/final"},
		TLS: TLSInfo{
			Version:     "TLS 1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
			Certificate: Certificate{Subject: "CN=example.com", NotAfter: "2026-12-31T00:00:00Z"},
		},
		Findings: []Finding{{ID: "example", Status: "pass", Message: "example finding"}},
	}

	var out bytes.Buffer
	WriteText(&out, result)
	text := out.String()
	for _, want := range []string{"Final:", "HTTP:   200 (HTTP/2.0)", "TLS 1.3", "Redirects:", "[PASS]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output %q does not contain %q", text, want)
		}
	}
}

func TestErrorFormatting(t *testing.T) {
	t.Parallel()

	inner := errors.New("boom")
	withOp := &Error{Kind: ErrInternal, Op: "test", Err: inner}
	if got := withOp.Error(); got != "test: boom" {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(withOp, inner) {
		t.Fatal("Unwrap() does not expose inner error")
	}
	withoutOp := &Error{Kind: ErrInternal, Err: inner}
	if got := withoutOp.Error(); got != "boom" {
		t.Fatalf("Error() without op = %q", got)
	}
}
