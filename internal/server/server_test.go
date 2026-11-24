package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/alcroito/ts_router/internal/config"
	"github.com/alcroito/ts_router/internal/nft"
	"github.com/alcroito/ts_router/internal/state"
)

type scripted struct {
	mu    sync.Mutex
	ips   map[string]string // name -> "ip" or "" for NXDOMAIN
	ttl   uint32
	fail  bool
	calls []string
}

func (s *scripted) Exchange(_ context.Context, m *dns.Msg) (*dns.Msg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := m.Question[0]
	s.calls = append(s.calls, dns.TypeToString[q.Qtype]+" "+q.Name)
	if s.fail {
		return nil, errors.New("upstream down")
	}
	r := new(dns.Msg)
	r.SetReply(m)
	if q.Qtype != dns.TypeA {
		r.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 5}, Txt: []string{"upstream"}}}
		if q.Qtype == dns.TypeAAAA {
			r.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 5}, AAAA: net.ParseIP("2001:db8::1")}}
		}
		return r, nil
	}
	ip, ok := s.ips[config.Normalize(q.Name)]
	if !ok {
		r.Rcode = dns.RcodeNameError
		return r, nil
	}
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl}, A: net.ParseIP(ip)}}
	return r, nil
}

func (s *scripted) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

type env struct {
	srv   *Server
	up    *scripted
	nft   *nft.Fake
	now   time.Time
	store *state.Store
	path  string
}

var (
	allowed = netip.MustParseAddr("100.64.0.5")
	other   = netip.MustParseAddr("100.64.0.9")
)

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := &config.Config{
		Listen:      []string{"127.0.0.1:53"},
		AnswerTTL:   config.Duration(60 * time.Second),
		GCAfter:     config.Duration(720 * time.Hour),
		Zones:       []config.Zone{{Name: "example.test"}},
		Prefix:      netip.MustParsePrefix("198.18.0.0/15"),
		Allow:       []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")},
		Interface:   "tailscale0",
		SyntheticV4: "198.18.0.0/15",
	}
	path := filepath.Join(t.TempDir(), "state.json")
	return mkEnv(t, cfg, path, &scripted{ips: map[string]string{"a.example.test": "1.2.3.4", "example.test": "1.2.3.9"}, ttl: 300}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
}

func mkEnv(t *testing.T, cfg *config.Config, path string, up *scripted, now time.Time) *env {
	store, err := state.Open(path, cfg.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	f := nft.NewFake()
	s := New(cfg, store, f, up, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e := &env{srv: s, up: up, nft: f, now: now, store: store, path: path}
	s.Now = func() time.Time { return e.now }
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) query(src netip.Addr, name string, qt uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qt)
	return e.srv.Handle(context.Background(), src, q)
}

func TestAnswersSyntheticAndWritesMapFirst(t *testing.T) {
	e := newEnv(t)
	r := e.query(allowed, "A.Example.Test", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("%v", r)
	}
	a := r.Answer[0].(*dns.A)
	if a.A.String() != "198.18.0.1" || a.Hdr.Ttl != 60 || a.Hdr.Name != "A.Example.Test." {
		t.Fatalf("answer %v", a)
	}
	if e.nft.M[netip.MustParseAddr("198.18.0.1")] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("map %v", e.nft.M)
	}
	r2 := e.query(allowed, "a.example.test", dns.TypeA)
	if r2.Answer[0].(*dns.A).A.String() != "198.18.0.1" {
		t.Fatal("not stable")
	}
	if e.up.count() != 1 {
		t.Fatalf("expected cached answer, upstream calls: %v", e.up.calls)
	}
}

func TestApexAndDistinctNames(t *testing.T) {
	e := newEnv(t)
	a := e.query(allowed, "example.test", dns.TypeA).Answer[0].(*dns.A).A.String()
	b := e.query(allowed, "a.example.test", dns.TypeA).Answer[0].(*dns.A).A.String()
	if a == b {
		t.Fatal("same synthetic for different names")
	}
}

func TestOutsideZoneRefused(t *testing.T) {
	e := newEnv(t)
	for _, n := range []string{"google.com", "notexample.test", "example.test.evil.com"} {
		for _, src := range []netip.Addr{allowed, other} {
			if r := e.query(src, n, dns.TypeA); r.Rcode != dns.RcodeRefused {
				t.Errorf("%s from %s: rcode %d", n, src, r.Rcode)
			}
		}
	}
	if e.up.count() != 0 {
		t.Fatal("upstream contacted for out-of-zone names")
	}
}

func TestDisallowedSourcePassThrough(t *testing.T) {
	e := newEnv(t)
	r := e.query(other, "a.example.test", dns.TypeA)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
		t.Fatalf("expected real answer: %v", r)
	}
	if len(e.nft.M) != 0 || len(e.store.Entries()) != 0 {
		t.Fatal("pass-through must not allocate")
	}
	r = e.query(other, "a.example.test", dns.TypeAAAA)
	if len(r.Answer) != 1 {
		t.Fatal("AAAA must pass through for other sources")
	}
}

func TestEmptyTypes(t *testing.T) {
	e := newEnv(t)
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB} {
		r := e.query(allowed, "a.example.test", qt)
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
			t.Errorf("type %d: %v", qt, r)
		}
	}
	if e.up.count() != 0 {
		t.Fatal("upstream contacted")
	}
}

func TestOtherTypesForwarded(t *testing.T) {
	e := newEnv(t)
	r := e.query(allowed, "a.example.test", dns.TypeTXT)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.TXT).Txt[0] != "upstream" {
		t.Fatalf("%v", r)
	}
}

func TestNXDomain(t *testing.T) {
	e := newEnv(t)
	r := e.query(allowed, "missing.example.test", dns.TypeA)
	if r.Rcode != dns.RcodeNameError || len(e.store.Entries()) != 0 {
		t.Fatalf("%v", r)
	}
}

func TestServFailWithoutPreviousIP(t *testing.T) {
	e := newEnv(t)
	e.up.fail = true
	r := e.query(allowed, "a.example.test", dns.TypeA)
	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("%v", r)
	}
	if len(e.store.Entries()) != 0 {
		t.Fatal("allocated on failure")
	}
}

func TestServeStale(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.up.fail = true
	e.now = e.now.Add(10 * time.Minute)
	r := e.query(allowed, "a.example.test", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || r.Answer[0].(*dns.A).A.String() != "198.18.0.1" {
		t.Fatalf("%v", r)
	}
}

func TestStaleWindowBacksOffUpstream(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.up.fail = true
	e.now = e.now.Add(10 * time.Minute)
	e.query(allowed, "a.example.test", dns.TypeA)
	n := e.up.count()
	e.now = e.now.Add(29 * time.Second)
	r := e.query(allowed, "a.example.test", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || e.up.count() != n {
		t.Fatalf("upstream hit inside the stale window: %d -> %d", n, e.up.count())
	}
	e.now = e.now.Add(2 * time.Second)
	r = e.query(allowed, "a.example.test", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || e.up.count() == n {
		t.Fatalf("no retry after the window: %d", e.up.count())
	}
}

func TestRefreshBacksOffAfterFailure(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.up.fail = true
	e.now = e.now.Add(295 * time.Second)
	e.srv.Refresh(context.Background())
	n := e.up.count()
	e.now = e.now.Add(5 * time.Second)
	e.srv.Refresh(context.Background())
	if e.up.count() != n {
		t.Fatal("refresh retried within the back-off window")
	}
}

func TestRepairRecreatesAfterListFailure(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.nft.FailList = errors.New("no such table")
	e.nft.M = map[netip.Addr]netip.Addr{}
	before := len(e.nft.Log())
	e.srv.Repair()
	if got := e.nft.Log()[before:]; len(got) != 1 || got[0] != "setup" {
		t.Fatalf("writes: %v", got)
	}
	if e.nft.M[netip.MustParseAddr("198.18.0.1")] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("map %v", e.nft.M)
	}
}

func TestRepairRestoresMissingAndWrongElements(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.query(allowed, "example.test", dns.TypeA)
	s1, s2 := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
	delete(e.nft.M, s1)
	e.nft.M[s2] = netip.MustParseAddr("9.9.9.9")
	e.srv.Repair()
	if e.nft.M[s1] != netip.MustParseAddr("1.2.3.4") || e.nft.M[s2] != netip.MustParseAddr("1.2.3.9") {
		t.Fatalf("map %v", e.nft.M)
	}
	before := len(e.nft.Log())
	e.srv.Repair()
	if len(e.nft.Log()) != before {
		t.Fatal("repair wrote to a healthy map")
	}
}

func TestRealIPChangeUpdatesMapKeepsSynthetic(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.up.ips["a.example.test"] = "5.6.7.8"
	e.now = e.now.Add(301 * time.Second)
	r := e.query(allowed, "a.example.test", dns.TypeA)
	if r.Answer[0].(*dns.A).A.String() != "198.18.0.1" {
		t.Fatal("synthetic changed")
	}
	if e.nft.M[netip.MustParseAddr("198.18.0.1")] != netip.MustParseAddr("5.6.7.8") {
		t.Fatalf("map %v", e.nft.M)
	}
}

func TestRealTTLClamped(t *testing.T) {
	e := newEnv(t)
	e.up.ttl = 1
	e.query(allowed, "a.example.test", dns.TypeA)
	ent, _ := e.store.Get("a.example.test")
	if got := ent.RealExpiry.Sub(e.now); got != 30*time.Second {
		t.Fatalf("min clamp: %v", got)
	}
	e.up.ttl = 86400
	e.now = e.now.Add(time.Minute)
	e.query(allowed, "a.example.test", dns.TypeA)
	ent, _ = e.store.Get("a.example.test")
	if got := ent.RealExpiry.Sub(e.now); got != time.Hour {
		t.Fatalf("max clamp: %v", got)
	}
}

func TestMapWriteFailureIsServFail(t *testing.T) {
	e := newEnv(t)
	e.nft.FailSet = errors.New("netlink down")
	r := e.query(allowed, "a.example.test", dns.TypeA)
	if r.Rcode != dns.RcodeServerFailure || len(r.Answer) != 0 {
		t.Fatalf("answered without a map entry: %v", r)
	}
}

func TestRefreshOnlyActiveEntriesNearExpiry(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.up.ips["a.example.test"] = "5.6.7.8"
	n := e.up.count()

	e.now = e.now.Add(100 * time.Second)
	e.srv.Refresh(context.Background())
	if e.up.count() != n {
		t.Fatal("refreshed too early")
	}
	e.now = e.now.Add(195 * time.Second)
	e.srv.Refresh(context.Background())
	if e.nft.M[netip.MustParseAddr("198.18.0.1")] != netip.MustParseAddr("5.6.7.8") {
		t.Fatalf("not refreshed: %v", e.nft.M)
	}

	e.up.ips["a.example.test"] = "9.9.9.9"
	e.now = e.now.Add(48 * time.Hour)
	n = e.up.count()
	e.srv.Refresh(context.Background())
	if e.up.count() != n {
		t.Fatal("refreshed an entry idle for over 24h")
	}
}

func TestCollectRemovesMapEntry(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.now = e.now.Add(721 * time.Hour)
	e.srv.Collect()
	if len(e.nft.M) != 0 || len(e.store.Entries()) != 0 {
		t.Fatalf("not collected: %v", e.nft.M)
	}
}

func TestRestartKeepsSyntheticAndRepopulatesMap(t *testing.T) {
	e := newEnv(t)
	e.query(allowed, "a.example.test", dns.TypeA)
	e.query(allowed, "example.test", dns.TypeA)

	e2 := mkEnv(t, e.srv.Cfg, e.path, &scripted{ips: map[string]string{"a.example.test": "1.2.3.4"}, ttl: 300, fail: true}, e.now.Add(time.Second))
	if len(e2.nft.M) != 2 || e2.nft.M[netip.MustParseAddr("198.18.0.1")] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("map after restart: %v", e2.nft.M)
	}
	r := e2.query(allowed, "a.example.test", dns.TypeA)
	if r.Answer[0].(*dns.A).A.String() != "198.18.0.1" {
		t.Fatal("synthetic changed across restart")
	}
}

func TestMalformedRequests(t *testing.T) {
	e := newEnv(t)
	q := new(dns.Msg)
	q.Id = 7
	if r := e.srv.Handle(context.Background(), allowed, q); r.Rcode != dns.RcodeFormatError {
		t.Fatalf("no question: %d", r.Rcode)
	}
	q.SetQuestion("a.example.test.", dns.TypeA)
	q.Opcode = dns.OpcodeUpdate
	if r := e.srv.Handle(context.Background(), allowed, q); r.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("update: %d", r.Rcode)
	}
}

func TestUDPAndTCPListeners(t *testing.T) {
	e := newEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	e.srv.Cfg.Listen = []string{addr}
	e.srv.Cfg.Allow = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.srv.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	for _, network := range []string{"udp", "tcp"} {
		var r *dns.Msg
		var err error
		for range 50 {
			q := new(dns.Msg)
			q.SetQuestion("a.example.test.", dns.TypeA)
			r, _, err = (&dns.Client{Net: network, Timeout: time.Second}).Exchange(q, addr)
			if err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "198.18.0.1" {
			t.Fatalf("%s: %v %v", network, r, err)
		}
	}
}
