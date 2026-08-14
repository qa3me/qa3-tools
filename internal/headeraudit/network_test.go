package headeraudit

import (
	"context"
	"testing"
)

func TestResolveAllowedIPLiteral(t *testing.T) {
	t.Parallel()

	ips, err := resolveAllowedIPs(context.Background(), "8.8.8.8", false)
	if err != nil {
		t.Fatalf("public IP resolve error = %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "8.8.8.8" {
		t.Fatalf("resolved IPs = %#v", ips)
	}

	if _, err := resolveAllowedIPs(context.Background(), "127.0.0.1", false); err == nil {
		t.Fatal("private literal should be blocked")
	}
	if _, err := resolveAllowedIPs(context.Background(), "127.0.0.1", true); err != nil {
		t.Fatalf("private literal should be allowed with opt-in: %v", err)
	}
}
