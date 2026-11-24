package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
)

type Duration time.Duration

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

type Zone struct {
	Name string `toml:"name"`
}

type Config struct {
	Listen       []string `toml:"listen"`
	Interface    string   `toml:"interface"`
	StateFile    string   `toml:"state_file"`
	Upstreams    []string `toml:"upstreams"`
	AnswerTTL    Duration `toml:"answer_ttl"`
	SyntheticV4  string   `toml:"synthetic_v4"`
	AllowSources []string `toml:"allow_sources"`
	GCAfter      Duration `toml:"gc_after"`
	Zones        []Zone   `toml:"zone"`

	Prefix netip.Prefix   `toml:"-"`
	Allow  []netip.Prefix `toml:"-"`
}

func Load(path string) (*Config, error) {
	c := &Config{}
	if _, err := toml.DecodeFile(path, c); err != nil {
		return nil, err
	}
	if err := c.finish(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c *Config) finish() error {
	if c.Interface == "" {
		c.Interface = "tailscale0"
	}
	if c.StateFile == "" {
		c.StateFile = "/var/lib/ts-router/state.json"
	}
	if len(c.Upstreams) == 0 {
		c.Upstreams = []string{"1.1.1.1:53", "1.0.0.1:53"}
	}
	if c.AnswerTTL == 0 {
		c.AnswerTTL = Duration(60 * time.Second)
	}
	if c.SyntheticV4 == "" {
		c.SyntheticV4 = "198.18.0.0/15"
	}
	if c.GCAfter == 0 {
		c.GCAfter = Duration(720 * time.Hour)
	}
	if len(c.Listen) == 0 {
		return errors.New("listen: at least one address is required")
	}
	for _, l := range c.Listen {
		if _, err := netip.ParseAddrPort(l); err != nil {
			return fmt.Errorf("listen %q: %w", l, err)
		}
	}
	if len(c.Zones) == 0 {
		return errors.New("at least one [[zone]] is required")
	}
	for i := range c.Zones {
		n := normalize(c.Zones[i].Name)
		if n == "" {
			return errors.New("zone: empty name")
		}
		c.Zones[i].Name = n
	}
	p, err := netip.ParsePrefix(c.SyntheticV4)
	if err != nil || !p.Addr().Is4() || p.Bits() > 30 {
		return fmt.Errorf("synthetic_v4 %q: need an IPv4 prefix of /30 or shorter", c.SyntheticV4)
	}
	c.Prefix = p.Masked()
	for _, s := range c.AllowSources {
		if pf, err := netip.ParsePrefix(s); err == nil {
			c.Allow = append(c.Allow, pf.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("allow_sources %q: not an IP or CIDR", s)
		}
		c.Allow = append(c.Allow, netip.PrefixFrom(a, a.BitLen()))
	}
	for _, u := range c.Upstreams {
		if _, err := netip.ParseAddrPort(u); err != nil {
			return fmt.Errorf("upstreams %q: %w", u, err)
		}
	}
	return nil
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// Normalize returns the lowercase name without the trailing dot.
func Normalize(name string) string { return normalize(dns.CanonicalName(name)) }

// InZone reports whether name (normalized) is a configured zone apex or below one.
func (c *Config) InZone(name string) bool {
	for _, z := range c.Zones {
		if name == z.Name || strings.HasSuffix(name, "."+z.Name) {
			return true
		}
	}
	return false
}

func (c *Config) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range c.Allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
