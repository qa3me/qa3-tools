package headeraudit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func Audit(ctx context.Context, target string, cfg Config) (Result, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "qa3-header-audit/0.1"
	}
	if cfg.Timeout < time.Second || cfg.Timeout > 30*time.Second {
		return Result{}, &Error{Kind: ErrInvalidInput, Op: "validate timeout", Err: fmt.Errorf("timeout must be between 1s and 30s")}
	}
	if cfg.MaxRedirects < 0 || cfg.MaxRedirects > 5 {
		return Result{}, &Error{Kind: ErrInvalidInput, Op: "validate redirects", Err: fmt.Errorf("max redirects must be between 0 and 5")}
	}

	u, err := validateURL(target)
	if err != nil {
		return Result{}, &Error{Kind: ErrInvalidInput, Op: "validate target", Err: err}
	}

	connectTimeout := cfg.Timeout
	if connectTimeout > 3*time.Second {
		connectTimeout = 3 * time.Second
	}

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialContext(cfg.AllowPrivate, connectTimeout),
		DisableKeepAlives:      true,
		MaxIdleConns:           0,
		TLSHandshakeTimeout:    cfg.Timeout,
		ResponseHeaderTimeout:  cfg.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    cfg.RootCAs,
		},
	}
	defer transport.CloseIdleConnections()

	redirects := make([]string, 0, cfg.MaxRedirects)
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if cfg.MaxRedirects == 0 {
				return http.ErrUseLastResponse
			}
			if len(via) > cfg.MaxRedirects {
				return fmt.Errorf("redirect limit exceeded (%d)", cfg.MaxRedirects)
			}
			if _, err := validateURL(req.URL.String()); err != nil {
				return fmt.Errorf("unsafe redirect target: %w", err)
			}
			redirects = append(redirects, req.URL.String())
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Result{}, &Error{Kind: ErrInternal, Op: "build request", Err: err}
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, classifyRequestError(err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return Result{}, &Error{Kind: ErrTLS, Op: "inspect TLS", Err: fmt.Errorf("TLS connection state is unavailable")}
	}

	leaf := resp.TLS.PeerCertificates[0]
	result := Result{
		RequestedURL: u.String(),
		FinalURL:     resp.Request.URL.String(),
		StatusCode:   resp.StatusCode,
		Protocol:     resp.Proto,
		Redirects:    redirects,
		TLS: TLSInfo{
			Version:     tlsVersionName(resp.TLS.Version),
			CipherSuite: tls.CipherSuiteName(resp.TLS.CipherSuite),
			ServerName:  resp.TLS.ServerName,
			Certificate: Certificate{
				Subject:   leaf.Subject.String(),
				Issuer:    leaf.Issuer.String(),
				NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:  leaf.NotAfter.UTC().Format(time.RFC3339),
				DNSNames:  append([]string(nil), leaf.DNSNames...),
			},
		},
		Findings: inspectHeaders(resp.Header),
	}

	result.Findings = append(result.Findings, inspectTLS(resp.TLS, leaf.NotAfter))
	return result, nil
}

func validateURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return nil, fmt.Errorf("URL must not be empty or contain surrounding whitespace")
	}
	if strings.Contains(raw, "#") {
		return nil, fmt.Errorf("URL fragments are not allowed")
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("only https:// URLs are allowed")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("URL hostname is required")
	}
	if u.User != nil {
		return nil, fmt.Errorf("URL userinfo is not allowed")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, fmt.Errorf("URL fragments are not allowed")
	}
	if err := validatePort(u.Port()); err != nil {
		return nil, err
	}
	return u, nil
}

func classifyRequestError(err error) error {
	var recordErr tls.RecordHeaderError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateInvalid x509.CertificateInvalidError
	if errors.As(err, &recordErr) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostnameError) ||
		errors.As(err, &certificateInvalid) {
		return &Error{Kind: ErrTLS, Op: "TLS handshake", Err: err}
	}

	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "tls") || strings.Contains(lower, "x509") || strings.Contains(lower, "certificate") {
		return &Error{Kind: ErrTLS, Op: "TLS handshake", Err: err}
	}
	return &Error{Kind: ErrNetwork, Op: "request", Err: err}
}

func inspectTLS(state *tls.ConnectionState, notAfter time.Time) Finding {
	f := Finding{
		ID:       "tls-transport",
		Category: "tls",
		Status:   "pass",
		Value:    tlsVersionName(state.Version) + " / " + tls.CipherSuiteName(state.CipherSuite),
		Message:  "TLS certificate verification succeeded",
	}

	remaining := time.Until(notAfter)
	if remaining < 0 {
		f.Status = "warn"
		f.Message = "TLS certificate is expired"
		return f
	}
	if remaining < 14*24*time.Hour {
		f.Status = "warn"
		f.Message = "TLS certificate expires in less than 14 days"
	}
	return f
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
