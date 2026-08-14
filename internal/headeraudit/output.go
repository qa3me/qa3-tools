package headeraudit

import (
	"fmt"
	"io"
	"strings"
)

func WriteText(w io.Writer, result Result) {
	fmt.Fprintf(w, "Target: %s\n", result.RequestedURL)
	if result.FinalURL != result.RequestedURL {
		fmt.Fprintf(w, "Final:  %s\n", result.FinalURL)
	}
	fmt.Fprintf(w, "HTTP:   %d (%s)\n", result.StatusCode, result.Protocol)
	fmt.Fprintf(w, "TLS:    %s / %s\n", result.TLS.Version, result.TLS.CipherSuite)
	fmt.Fprintf(w, "Cert:   %s → %s\n", result.TLS.Certificate.Subject, result.TLS.Certificate.NotAfter)
	if len(result.Redirects) > 0 {
		fmt.Fprintf(w, "Redirects: %s\n", strings.Join(result.Redirects, " -> "))
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Findings:")
	for _, finding := range result.Findings {
		fmt.Fprintf(w, "  [%-4s] %-28s %s\n", strings.ToUpper(finding.Status), finding.ID, finding.Message)
	}
}
