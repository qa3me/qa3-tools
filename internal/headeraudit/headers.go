package headeraudit

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func inspectHeaders(h http.Header) []Finding {
	findings := make([]Finding, 0, 6)
	findings = append(findings, inspectHSTS(h.Get("Strict-Transport-Security")))
	findings = append(findings, inspectCSP(h.Get("Content-Security-Policy")))
	findings = append(findings, inspectContentTypeOptions(h.Get("X-Content-Type-Options")))
	findings = append(findings, inspectClickjacking(h))
	findings = append(findings, inspectReferrerPolicy(h.Get("Referrer-Policy")))
	findings = append(findings, inspectPermissionsPolicy(h.Get("Permissions-Policy")))
	return findings
}

func inspectHSTS(value string) Finding {
	f := Finding{ID: "strict-transport-security", Category: "header", Value: value}
	if strings.TrimSpace(value) == "" {
		f.Status = "warn"
		f.Message = "Strict-Transport-Security is missing"
		return f
	}

	maxAge := int64(-1)
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if len(part) < 8 || !strings.EqualFold(part[:8], "max-age=") {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(part[8:]), 10, 64)
		if err == nil {
			maxAge = n
		}
	}

	if maxAge < 0 {
		f.Status = "warn"
		f.Message = "Strict-Transport-Security is present but max-age is missing or invalid"
		return f
	}
	if maxAge < 31536000 {
		f.Status = "warn"
		f.Message = fmt.Sprintf("Strict-Transport-Security max-age is %d seconds; review whether a one-year policy is appropriate", maxAge)
		return f
	}

	f.Status = "pass"
	f.Message = "Strict-Transport-Security is present with max-age of at least one year"
	return f
}

func inspectCSP(value string) Finding {
	f := Finding{ID: "content-security-policy", Category: "header", Value: value}
	if strings.TrimSpace(value) == "" {
		f.Status = "warn"
		f.Message = "Content-Security-Policy is missing"
		return f
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "'unsafe-inline'") || strings.Contains(lower, "'unsafe-eval'") {
		f.Status = "warn"
		f.Message = "Content-Security-Policy contains unsafe-inline or unsafe-eval; review whether it can be tightened"
		return f
	}
	f.Status = "pass"
	f.Message = "Content-Security-Policy is present without obvious unsafe-inline or unsafe-eval tokens"
	return f
}

func inspectContentTypeOptions(value string) Finding {
	f := Finding{ID: "x-content-type-options", Category: "header", Value: value}
	if strings.EqualFold(strings.TrimSpace(value), "nosniff") {
		f.Status = "pass"
		f.Message = "X-Content-Type-Options is set to nosniff"
		return f
	}
	f.Status = "warn"
	if strings.TrimSpace(value) == "" {
		f.Message = "X-Content-Type-Options is missing"
	} else {
		f.Message = "X-Content-Type-Options is present but is not set to nosniff"
	}
	return f
}

func inspectClickjacking(h http.Header) Finding {
	xfo := strings.TrimSpace(h.Get("X-Frame-Options"))
	csp := strings.ToLower(h.Get("Content-Security-Policy"))
	f := Finding{ID: "clickjacking-protection", Category: "header"}

	if strings.EqualFold(xfo, "DENY") || strings.EqualFold(xfo, "SAMEORIGIN") {
		f.Status = "pass"
		f.Message = "Frame embedding is restricted by X-Frame-Options"
		f.Value = xfo
		return f
	}
	if strings.Contains(csp, "frame-ancestors") {
		f.Status = "pass"
		f.Message = "Frame embedding is controlled by CSP frame-ancestors"
		f.Value = "frame-ancestors"
		return f
	}

	f.Status = "warn"
	f.Message = "No X-Frame-Options or CSP frame-ancestors control was detected"
	return f
}

func inspectReferrerPolicy(value string) Finding {
	f := Finding{ID: "referrer-policy", Category: "header", Value: value}
	value = strings.TrimSpace(value)
	if value == "" {
		f.Status = "warn"
		f.Message = "Referrer-Policy is missing"
		return f
	}
	if strings.EqualFold(value, "unsafe-url") {
		f.Status = "warn"
		f.Message = "Referrer-Policy is set to unsafe-url"
		return f
	}
	f.Status = "pass"
	f.Message = "Referrer-Policy is present"
	return f
}

func inspectPermissionsPolicy(value string) Finding {
	f := Finding{ID: "permissions-policy", Category: "header", Value: value}
	if strings.TrimSpace(value) == "" {
		f.Status = "warn"
		f.Message = "Permissions-Policy is missing"
		return f
	}
	f.Status = "pass"
	f.Message = "Permissions-Policy is present"
	return f
}
