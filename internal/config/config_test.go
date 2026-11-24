package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sample = `
listen = ["100.64.0.8:53", "[fd7a:115c:a1e0::8]:53"]
interface = "tailscale0"
state_file = "/var/lib/ts-router/state.json"
upstreams = ["1.1.1.1:53", "1.0.0.1:53"]
answer_ttl = "60s"
synthetic_v4 = "198.18.0.0/15"
allow_sources = ["100.64.0.5/32", "100.64.0.7"]
gc_after = "720h"

[[zone]]
name = "Tailscale.com."
`

func load(t *testing.T, s string) (*Config, error) {
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoadSample(t *testing.T) {
	c, err := load(t, sample)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(c.AnswerTTL) != 60*time.Second || time.Duration(c.GCAfter) != 720*time.Hour {
		t.Fatalf("durations: %v %v", c.AnswerTTL, c.GCAfter)
	}
	if c.Prefix != netip.MustParsePrefix("198.18.0.0/15") {
		t.Fatalf("prefix %v", c.Prefix)
	}
	if c.Zones[0].Name != "tailscale.com" {
		t.Fatalf("zone %q", c.Zones[0].Name)
	}
}

func TestDefaults(t *testing.T) {
	c, err := load(t, "listen = [\"127.0.0.1:5353\"]\n[[zone]]\nname=\"a.test\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Interface != "tailscale0" || len(c.Upstreams) != 2 || time.Duration(c.AnswerTTL) != time.Minute {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestInvalid(t *testing.T) {
	for name, s := range map[string]string{
		"no listen":  "[[zone]]\nname=\"a\"\n",
		"no zone":    "listen=[\"127.0.0.1:53\"]\n",
		"bad prefix": "listen=[\"127.0.0.1:53\"]\nsynthetic_v4=\"fd00::/8\"\n[[zone]]\nname=\"a\"\n",
		"bad source": "listen=[\"127.0.0.1:53\"]\nallow_sources=[\"x\"]\n[[zone]]\nname=\"a\"\n",
		"bad ttl":    "listen=[\"127.0.0.1:53\"]\nanswer_ttl=\"abc\"\n[[zone]]\nname=\"a\"\n",
	} {
		if _, err := load(t, s); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestInZone(t *testing.T) {
	c, _ := load(t, sample)
	for name, want := range map[string]bool{
		"tailscale.com":       true,
		"wwwv2.tailscale.com": true,
		"a.b.tailscale.com":   true,
		"nottailscale.com":    false,
		"tailscale.com.evil":  false,
		"com":                 false,
	} {
		if got := c.InZone(name); got != want {
			t.Errorf("InZone(%q)=%v", name, got)
		}
	}
}

func TestNormalizeAndAllowed(t *testing.T) {
	if got := Normalize("WwwV2.Tailscale.COM."); got != "wwwv2.tailscale.com" {
		t.Fatal(got)
	}
	c, _ := load(t, sample)
	if !c.Allowed(netip.MustParseAddr("100.64.0.5")) || !c.Allowed(netip.MustParseAddr("100.64.0.7")) {
		t.Fatal("expected allowed")
	}
	if c.Allowed(netip.MustParseAddr("100.64.0.6")) {
		t.Fatal("expected denied")
	}
	if !c.Allowed(netip.MustParseAddr("::ffff:100.64.0.5")) {
		t.Fatal("v4-mapped should match")
	}
}
