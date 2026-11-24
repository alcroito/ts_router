package server

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Run serves UDP and TCP on all configured addresses until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	lc := net.ListenConfig{Control: freebind}
	var servers []*dns.Server
	closeAll := func() {
		for _, d := range servers {
			d.Shutdown()
		}
	}
	for _, addr := range s.Cfg.Listen {
		pc, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			closeAll()
			return err
		}
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			pc.Close()
			closeAll()
			return err
		}
		servers = append(servers,
			&dns.Server{PacketConn: pc, Handler: s},
			&dns.Server{Listener: ln, Handler: s},
		)
		s.Log.Info("listening", "addr", addr)
	}
	errc := make(chan error, len(servers))
	for _, d := range servers {
		go func() { errc <- d.ActivateAndServe() }()
	}

	go s.background(ctx)

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	closeAll()
	s.Store.Flush()
	return err
}

func (s *Server) background(ctx context.Context) {
	refresh := time.NewTicker(5 * time.Second)
	flush := time.NewTicker(30 * time.Second)
	gc := time.NewTicker(10 * time.Minute)
	repair := time.NewTicker(repairEvery)
	defer repair.Stop()
	defer refresh.Stop()
	defer flush.Stop()
	defer gc.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			s.Refresh(rctx)
			cancel()
		case <-flush.C:
			if err := s.Store.Flush(); err != nil {
				s.Log.Error("flush state", "err", err)
			}
		case <-gc.C:
			s.Collect()
		case <-repair.C:
			s.Repair()
		}
	}
}
