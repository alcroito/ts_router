package upstream

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fake struct {
	fn    func(q *dns.Msg) (*dns.Msg, error)
	calls int
}

func (f *fake) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	f.calls++
	return f.fn(m)
}

func rr(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

func reply(q *dns.Msg, rcode int, rrs ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.Rcode = rcode
	m.Answer = rrs
	return m
}

func TestLookupDirect(t *testing.T) {
	f := &fake{fn: func(q *dns.Msg) (*dns.Msg, error) {
		return reply(q, 0, rr("a.test. 300 IN A 1.2.3.4"), rr("a.test. 300 IN A 1.2.3.5")), nil
	}}
	res, err := (&Resolver{f}).LookupA(context.Background(), "a.test")
	if err != nil || len(res.IPs) != 2 || res.IPs[0].String() != "1.2.3.4" || res.TTL != 300*time.Second {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestLookupCNAMEInAnswerUsesMinTTL(t *testing.T) {
	f := &fake{fn: func(q *dns.Msg) (*dns.Msg, error) {
		return reply(q, 0, rr("a.test. 100 IN CNAME b.test."), rr("b.test. 5000 IN A 9.9.9.9")), nil
	}}
	res, _ := (&Resolver{f}).LookupA(context.Background(), "a.test")
	if len(res.IPs) != 1 || res.TTL != 100*time.Second {
		t.Fatalf("%+v", res)
	}
}

func TestLookupFollowsDanglingCNAME(t *testing.T) {
	f := &fake{fn: func(q *dns.Msg) (*dns.Msg, error) {
		if q.Question[0].Name == "a.test." {
			return reply(q, 0, rr("a.test. 600 IN CNAME b.test.")), nil
		}
		return reply(q, 0, rr("b.test. 600 IN A 9.9.9.9")), nil
	}}
	res, err := (&Resolver{f}).LookupA(context.Background(), "a.test")
	if err != nil || len(res.IPs) != 1 || f.calls != 2 {
		t.Fatalf("%+v %v calls=%d", res, err, f.calls)
	}
}

func TestLookupCNAMELoop(t *testing.T) {
	f := &fake{fn: func(q *dns.Msg) (*dns.Msg, error) {
		if q.Question[0].Name == "a.test." {
			return reply(q, 0, rr("a.test. 60 IN CNAME b.test.")), nil
		}
		return reply(q, 0, rr("b.test. 60 IN CNAME a.test.")), nil
	}}
	if _, err := (&Resolver{f}).LookupA(context.Background(), "a.test"); err == nil {
		t.Fatal("expected error")
	}
}

func TestLookupNXDomainNoDataAndFailure(t *testing.T) {
	r := &Resolver{&fake{fn: func(q *dns.Msg) (*dns.Msg, error) { return reply(q, dns.RcodeNameError), nil }}}
	if res, err := r.LookupA(context.Background(), "x.test"); err != nil || !res.NXDomain {
		t.Fatalf("nxdomain: %+v %v", res, err)
	}
	r = &Resolver{&fake{fn: func(q *dns.Msg) (*dns.Msg, error) { return reply(q, 0), nil }}}
	if res, err := r.LookupA(context.Background(), "x.test"); err != nil || res.NXDomain || len(res.IPs) != 0 {
		t.Fatalf("nodata: %+v %v", res, err)
	}
	r = &Resolver{&fake{fn: func(q *dns.Msg) (*dns.Msg, error) { return nil, errors.New("down") }}}
	if _, err := r.LookupA(context.Background(), "x.test"); err == nil {
		t.Fatal("expected error")
	}
	r = &Resolver{&fake{fn: func(q *dns.Msg) (*dns.Msg, error) { return reply(q, dns.RcodeRefused), nil }}}
	if _, err := r.LookupA(context.Background(), "x.test"); err == nil {
		t.Fatal("expected error for REFUSED")
	}
}

func TestClamp(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0: MinTTL, 10 * time.Second: MinTTL, 5 * time.Minute: 5 * time.Minute, 48 * time.Hour: MaxTTL,
	} {
		if got := Clamp(in); got != want {
			t.Errorf("Clamp(%v)=%v want %v", in, got, want)
		}
	}
}

func serve(t *testing.T, h dns.HandlerFunc) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &dns.Server{PacketConn: pc, Handler: h}
	go s.ActivateAndServe()
	t.Cleanup(func() { s.Shutdown() })
	return pc.LocalAddr().String()
}

func TestClientFallsBackToSecondServer(t *testing.T) {
	bad := serve(t, func(w dns.ResponseWriter, q *dns.Msg) {
		w.WriteMsg(reply(q, dns.RcodeServerFailure))
	})
	good := serve(t, func(w dns.ResponseWriter, q *dns.Msg) {
		w.WriteMsg(reply(q, 0, rr("a.test. 60 IN A 1.1.1.1")))
	})
	c := &Client{Servers: []string{bad, good}, Timeout: time.Second}
	q := new(dns.Msg)
	q.SetQuestion("a.test.", dns.TypeA)
	r, err := c.Exchange(context.Background(), q)
	if err != nil || len(r.Answer) != 1 {
		t.Fatalf("%v %v", r, err)
	}
}

func TestClientAllDown(t *testing.T) {
	c := &Client{Servers: []string{"127.0.0.1:1"}, Timeout: 200 * time.Millisecond}
	q := new(dns.Msg)
	q.SetQuestion("a.test.", dns.TypeA)
	if _, err := c.Exchange(context.Background(), q); err == nil {
		t.Fatal("expected error")
	}
}
