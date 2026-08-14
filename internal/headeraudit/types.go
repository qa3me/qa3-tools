package headeraudit

import (
	"crypto/x509"
	"fmt"
	"time"
)

type ErrorKind string

const (
	ErrInvalidInput ErrorKind = "invalid_input"
	ErrNetwork      ErrorKind = "network"
	ErrTLS          ErrorKind = "tls"
	ErrInternal     ErrorKind = "internal"
)

type Error struct {
	Kind ErrorKind
	Op   string
	Err  error
}

func (e *Error) Error() string {
	if e.Op == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

type Config struct {
	Timeout      time.Duration
	MaxRedirects int
	AllowPrivate bool
	UserAgent    string

	// RootCAs is intentionally not exposed by the CLI in v0.1. It supports
	// deterministic integration tests and future private-PKI use without
	// weakening TLS verification.
	RootCAs *x509.CertPool
}

type Finding struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Value    string `json:"value,omitempty"`
}

type Certificate struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DNSNames  []string `json:"dns_names,omitempty"`
}

type TLSInfo struct {
	Version     string      `json:"version"`
	CipherSuite string      `json:"cipher_suite"`
	ServerName  string      `json:"server_name"`
	Certificate Certificate `json:"certificate"`
}

type Result struct {
	RequestedURL string    `json:"requested_url"`
	FinalURL     string    `json:"final_url"`
	StatusCode   int       `json:"status_code"`
	Protocol     string    `json:"protocol"`
	Redirects    []string  `json:"redirects,omitempty"`
	TLS          TLSInfo   `json:"tls"`
	Findings     []Finding `json:"findings"`
}
