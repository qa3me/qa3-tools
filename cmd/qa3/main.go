package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/qa3me/qa3-tools/internal/headeraudit"
)

const version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "qa3 %s\n", version)
		return 0
	case "header-audit":
		return runHeaderAudit(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runHeaderAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("header-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	jsonOutput := fs.Bool("json", false, "emit JSON output")
	timeout := fs.Duration("timeout", 10*time.Second, "overall request timeout (1s-30s)")
	maxRedirects := fs.Int("max-redirects", 0, "maximum HTTPS redirects to follow (0-5)")
	allowPrivate := fs.Bool("allow-private", false, "allow loopback and private-network targets")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: qa3 header-audit [flags] <https-url>")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "error: exactly one HTTPS URL is required")
		fs.Usage()
		return 2
	}
	if *timeout < time.Second || *timeout > 30*time.Second {
		fmt.Fprintln(stderr, "error: --timeout must be between 1s and 30s")
		return 2
	}
	if *maxRedirects < 0 || *maxRedirects > 5 {
		fmt.Fprintln(stderr, "error: --max-redirects must be between 0 and 5")
		return 2
	}

	cfg := headeraudit.Config{
		Timeout:      *timeout,
		MaxRedirects: *maxRedirects,
		AllowPrivate: *allowPrivate,
		UserAgent:    "qa3-header-audit/0.1",
	}

	result, err := headeraudit.Audit(context.Background(), fs.Arg(0), cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitCode(err)
	}

	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(stderr, "error: encode JSON: %v\n", err)
			return 1
		}
	} else {
		headeraudit.WriteText(stdout, result)
	}

	return 0
}

func exitCode(err error) int {
	var auditErr *headeraudit.Error
	if !errors.As(err, &auditErr) {
		return 1
	}

	switch auditErr.Kind {
	case headeraudit.ErrInvalidInput:
		return 2
	case headeraudit.ErrNetwork:
		return 3
	case headeraudit.ErrTLS:
		return 4
	default:
		return 1
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "QA3 defensive security tools")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  qa3 <command> [arguments]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  header-audit   Audit response security headers and TLS for one HTTPS URL")
	fmt.Fprintln(w, "  version        Print the development version")
}
