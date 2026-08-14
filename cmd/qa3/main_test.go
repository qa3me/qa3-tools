package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunUnknownCommand(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := run([]string{"unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunHeaderAuditRejectsHTTP(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := run([]string{"header-audit", "http://example.com"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "only https:// URLs are allowed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunHelpAndVersion(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "QA3 defensive security tools") {
		t.Fatalf("help stdout = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "0.1.0-dev") {
		t.Fatalf("version stdout = %q", stdout.String())
	}
}

func TestRunHeaderAuditRejectsInvalidFlags(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := run([]string{"header-audit", "--timeout", "500ms", "https://example.com"}, &stdout, &stderr); code != 2 {
		t.Fatalf("timeout code = %d, want 2", code)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"header-audit", "--max-redirects", "6", "https://example.com"}, &stdout, &stderr); code != 2 {
		t.Fatalf("redirect code = %d, want 2", code)
	}
}
