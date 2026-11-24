package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

const (
	MinTTL  = 30 * time.Second
	MaxTTL  = time.Hour
	maxHops = 8
)

type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}

// Client tries each upstream in order over UDP and retries over TCP when truncated.
type Client struct {
	Servers []string
	Timeout time.Duration
}

func (c *Client) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	var last error
	for _, srv := range c.Servers {
		r, _, err := (&dns.Client{Timeout: timeout}).ExchangeContext(ctx, m, srv)
		if err == nil && r.Truncated {
			r, _, err = (&dns.Client{Net: "tcp", Timeout: timeout}).ExchangeContext(ctx, m, srv)
		}
		if err == nil && r.Rcode == dns.RcodeServerFailure {
			err = errors.New("upstream SERVFAIL")
		}
		if err == nil {
			return r, nil
		}
		last = fmt.Errorf("%s: %w", srv, err)
		if ctx.Err() != nil {
			break
		}
	}
	if last == nil {
		last = errors.New("no upstreams")
	}
	return nil, last
}

type Result struct {
	NXDomain bool
	IPs      []netip.Addr
	TTL      time.Duration
}

type Resolver struct {
	Exchanger Exchanger
}

// LookupA resolves the IPv4 addresses of name, following CNAMEs the upstream did not chase itself.
func (r *Resolver) LookupA(ctx context.Context, name string) (Result, error) {
	target := dns.Fqdn(name)
	ttl := uint32(0)
	first := true
	for range maxHops {
		q := new(dns.Msg)
		q.SetQuestion(target, dns.TypeA)
		q.RecursionDesired = true
		resp, err := r.Exchanger.Exchange(ctx, q)
		if err != nil {
			return Result{}, err
		}
		if resp.Rcode == dns.RcodeNameError {
			return Result{NXDomain: true}, nil
		}
		if resp.Rcode != dns.RcodeSuccess {
			return Result{}, fmt.Errorf("upstream rcode %s", dns.RcodeToString[resp.Rcode])
		}
		var ips []netip.Addr
		var next string
		for _, rr := range resp.Answer {
			h := rr.Header()
			if first || h.Ttl < ttl {
				ttl, first = h.Ttl, false
			}
			switch v := rr.(type) {
			case *dns.A:
				if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
					ips = append(ips, a)
				}
			case *dns.CNAME:
				next = v.Target
			}
		}
		if len(ips) > 0 {
			return Result{IPs: ips, TTL: Clamp(time.Duration(ttl) * time.Second)}, nil
		}
		if next == "" || next == target {
			return Result{TTL: Clamp(time.Duration(ttl) * time.Second)}, nil
		}
		target = next
	}
	return Result{}, errors.New("CNAME chain too long")
}

func Clamp(d time.Duration) time.Duration {
	return min(max(d, MinTTL), MaxTTL)
}
