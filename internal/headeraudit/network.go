package headeraudit

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var alwaysBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func dialContext(allowPrivate bool, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse destination: %w", err)
		}

		ips, err := resolveAllowedIPs(ctx, host, allowPrivate)
		if err != nil {
			return nil, err
		}

		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("no allowed address resolved for %s", host)
	}
}

func resolveAllowedIPs(ctx context.Context, host string, allowPrivate bool) ([]net.IP, error) {
	if parsed := net.ParseIP(host); parsed != nil {
		if err := validateIP(parsed, allowPrivate); err != nil {
			return nil, err
		}
		return []net.IP{parsed}, nil
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses returned", host)
	}

	ips := make([]net.IP, 0, len(addrs))
	var blocked []string
	for _, addr := range addrs {
		if err := validateIP(addr.IP, allowPrivate); err != nil {
			blocked = append(blocked, addr.IP.String())
			continue
		}
		ips = append(ips, addr.IP)
		if len(ips) == 8 {
			break
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("target resolves only to blocked addresses: %s", strings.Join(blocked, ", "))
	}
	return ips, nil
}

func validateIP(ip net.IP, allowPrivate bool) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("invalid IP address")
	}
	addr = addr.Unmap()

	for _, prefix := range alwaysBlockedPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("address %s is blocked", addr)
		}
	}

	if addr.IsLoopback() || addr.IsPrivate() {
		if !allowPrivate {
			return fmt.Errorf("address %s is private; use --allow-private only for authorized internal targets", addr)
		}
		return nil
	}
	if !addr.IsGlobalUnicast() {
		return fmt.Errorf("address %s is not globally routable", addr)
	}
	return nil
}

func validatePort(port string) error {
	if port == "" {
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}
