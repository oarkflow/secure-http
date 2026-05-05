package security

import "testing"

func TestResolveClientIPIgnoresForwardedForWithoutTrustedProxy(t *testing.T) {
	got := ResolveClientIP("203.0.113.10:443", "198.51.100.2", TrustedProxyConfig{})
	if got != "203.0.113.10" {
		t.Fatalf("ResolveClientIP() = %q, want remote address", got)
	}
}

func TestResolveClientIPUsesForwardedForFromTrustedProxy(t *testing.T) {
	got := ResolveClientIP("10.0.0.10:443", "198.51.100.2, 10.0.0.10", TrustedProxyConfig{
		TrustedCIDRs: []string{"10.0.0.0/8"},
	})
	if got != "198.51.100.2" {
		t.Fatalf("ResolveClientIP() = %q, want forwarded client", got)
	}
}
