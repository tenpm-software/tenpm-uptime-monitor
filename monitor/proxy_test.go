package monitor

import "testing"

func TestParseProxyURLEmptyMeansNoProxy(t *testing.T) {
	u, err := ParseProxyURL("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u != nil {
		t.Fatalf("expected nil proxy url for empty input, got %v", u)
	}

	u, err = ParseProxyURL("   ")
	if err != nil {
		t.Fatalf("unexpected error for whitespace input: %v", err)
	}
	if u != nil {
		t.Fatalf("expected nil proxy url for whitespace input, got %v", u)
	}
}

func TestParseProxyURLAcceptsSupportedSchemes(t *testing.T) {
	for _, raw := range []string{
		"http://proxy.example:8080",
		"https://proxy.example:8443",
		"socks5://proxy.example:1080",
		"socks5://user:pass@proxy.example:1080",
	} {
		u, err := ParseProxyURL(raw)
		if err != nil {
			t.Fatalf("ParseProxyURL(%q): unexpected error: %v", raw, err)
		}
		if u == nil || u.String() != raw {
			t.Fatalf("ParseProxyURL(%q) = %v, want round trip", raw, u)
		}
	}
}

func TestParseProxyURLRejectsUnsupportedSchemes(t *testing.T) {
	for _, raw := range []string{
		"ftp://proxy.example:21",
		"socks4://proxy.example:1080",
		"proxy.example:8080", // no scheme at all
	} {
		if _, err := ParseProxyURL(raw); err == nil {
			t.Fatalf("ParseProxyURL(%q): expected an error, got none", raw)
		}
	}
}

func TestParseProxyURLRejectsMissingHost(t *testing.T) {
	if _, err := ParseProxyURL("http://"); err == nil {
		t.Fatalf("expected an error for a proxy url with no host")
	}
}
