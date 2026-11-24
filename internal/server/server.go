package server

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/alcroito/ts_router/internal/config"
	"github.com/alcroito/ts_router/internal/nft"
	"github.com/alcroito/ts_router/internal/state"
	"github.com/alcroito/ts_router/internal/upstream"
)

const (
	activeWindow = 24 * time.Hour
	refreshAhead = 10 * time.Second
)

type Server struct {
	Cfg   *config.Config
	Store *state.Store
	NFT   nft.Backend
	Ex    upstream.Exchanger
	Now   func() time.Time
	Log   *slog.Logger

	res upstream.Resolver
	mu  sync.Mutex
}

func New(cfg *config.Config, store *state.Store, b nft.Backend, ex upstream.Exchanger, log *slog.Logger) *Server {
	return &Server{Cfg: cfg, Store: store, NFT: b, Ex: ex, Now: time.Now, Log: log, res: upstream.Resolver{Exchanger: ex}}
}

// Init repopulates the nftables map from state; it must run before serving.
func (s *Server) Init() error {
	m := map[netip.Addr]netip.Addr{}
	for _, e := range s.Store.Entries() {
		if len(e.Real) > 0 {
			m[e.Synthetic] = e.Real[0]
		}
	}
	return s.NFT.Setup(m)
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var src netip.Addr
	udp := false
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		src, _ = netip.AddrFromSlice(a.IP)
		udp = true
	case *net.TCPAddr:
		src, _ = netip.AddrFromSlice(a.IP)
	}
	resp := s.Handle(ctx, src, req)
	if udp {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		s.Log.Warn("write response", "err", err)
	}
}

func (s *Server) Handle(ctx context.Context, src netip.Addr, req *dns.Msg) *dns.Msg {
	if req.Opcode != dns.OpcodeQuery {
		return rcode(req, dns.RcodeNotImplemented)
	}
	if len(req.Question) != 1 {
		return rcode(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	name := config.Normalize(q.Name)
	if !s.Cfg.InZone(name) {
		return rcode(req, dns.RcodeRefused)
	}
	if !s.Cfg.Allowed(src) || q.Qclass != dns.ClassINET {
		return s.forward(ctx, req)
	}
	switch q.Qtype {
	case dns.TypeA:
		return s.handleA(ctx, req, name)
	case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
		return s.reply(req)
	}
	return s.forward(ctx, req)
}

func (s *Server) forward(ctx context.Context, req *dns.Msg) *dns.Msg {
	r, err := s.Ex.Exchange(ctx, req.Copy())
	if err != nil {
		s.Log.Warn("forward failed", "name", req.Question[0].Name, "err", err)
		return rcode(req, dns.RcodeServerFailure)
	}
	r.Id = req.Id
	return r
}

func (s *Server) handleA(ctx context.Context, req *dns.Msg, name string) *dns.Msg {
	now := s.Now()
	e, have := s.Store.Get(name)
	if have {
		s.Store.Touch(name, now)
		if len(e.Real) > 0 && now.Before(e.RealExpiry) {
			return s.answer(req, e.Synthetic)
		}
	}
	res, err := s.res.LookupA(ctx, name)
	switch {
	case err != nil:
		s.Log.Warn("upstream lookup failed", "name", name, "err", err)
		if have && len(e.Real) > 0 {
			return s.answer(req, e.Synthetic)
		}
		return rcode(req, dns.RcodeServerFailure)
	case res.NXDomain:
		return rcode(req, dns.RcodeNameError)
	case len(res.IPs) == 0:
		return s.reply(req)
	}
	e, err = s.apply(name, res, now)
	if err != nil {
		s.Log.Error("update mapping", "name", name, "err", err)
		return rcode(req, dns.RcodeServerFailure)
	}
	return s.answer(req, e.Synthetic)
}

// apply allocates if needed and writes the nft map entry before state.
func (s *Server) apply(name string, res upstream.Result, now time.Time) (state.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.Store.Allocate(name, now)
	if err != nil {
		return e, err
	}
	real := slices.Clone(res.IPs)
	if len(e.Real) > 0 {
		if i := slices.Index(real, e.Real[0]); i > 0 {
			real[0], real[i] = real[i], real[0]
		}
	}
	if len(e.Real) == 0 || e.Real[0] != real[0] {
		if err := s.NFT.Set(e.Synthetic, real[0]); err != nil {
			return e, err
		}
		s.Log.Info("mapped", "name", name, "synthetic", e.Synthetic, "real", real[0])
	}
	if err := s.Store.SetReal(name, real, now.Add(res.TTL)); err != nil {
		return e, err
	}
	e.Real = real
	return e, nil
}

func (s *Server) answer(req *dns.Msg, ip netip.Addr) *dns.Msg {
	m := s.reply(req)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(time.Duration(s.Cfg.AnswerTTL) / time.Second)},
		A:   ip.AsSlice(),
	}}
	return m
}

func (s *Server) reply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	return m
}

func rcode(req *dns.Msg, rc int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rc)
	return m
}

// Refresh re-resolves recently queried entries that are about to expire.
func (s *Server) Refresh(ctx context.Context) {
	now := s.Now()
	for _, e := range s.Store.Entries() {
		if now.Sub(e.LastQuery) > activeWindow || now.Before(e.RealExpiry.Add(-refreshAhead)) {
			continue
		}
		res, err := s.res.LookupA(ctx, e.Name)
		if err != nil || res.NXDomain || len(res.IPs) == 0 {
			continue
		}
		if _, err := s.apply(e.Name, res, now); err != nil {
			s.Log.Error("refresh", "name", e.Name, "err", err)
		}
	}
}

// Collect drops idle entries and their map elements.
func (s *Server) Collect() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.Store.GC(s.Now(), time.Duration(s.Cfg.GCAfter)) {
		if err := s.NFT.Delete(e.Synthetic); err != nil {
			s.Log.Error("gc delete", "name", e.Name, "err", err)
		}
		s.Log.Info("expired", "name", e.Name, "synthetic", e.Synthetic)
	}
}
