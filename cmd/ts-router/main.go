package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/alcroito/ts_router/internal/config"
	"github.com/alcroito/ts_router/internal/nft"
	"github.com/alcroito/ts_router/internal/server"
	"github.com/alcroito/ts_router/internal/state"
	"github.com/alcroito/ts_router/internal/upstream"
)

const usage = "usage: ts-router {serve|status|health|cleanup} [-config file]"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/ts-router/config.toml", "config file")
	fs.Parse(os.Args[2:])

	var err error
	switch cmd {
	case "serve":
		err = serve(*cfgPath)
	case "status":
		err = status(*cfgPath)
	case "health":
		err = health(*cfgPath)
	case "cleanup":
		err = nft.New("", netip.Prefix{}).Cleanup()
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ts-router:", err)
		os.Exit(1)
	}
}

func serve(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	store, err := state.Open(cfg.StateFile, cfg.Prefix)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	s := server.New(cfg, store, nft.New(cfg.Interface, cfg.Prefix),
		&upstream.Client{Servers: cfg.Upstreams}, log)
	if err := s.Init(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return s.Run(ctx)
}

func status(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	store, err := state.Open(cfg.StateFile, cfg.Prefix)
	if err != nil {
		return err
	}
	live, nerr := nft.New(cfg.Interface, cfg.Prefix).List()
	if nerr != nil {
		fmt.Printf("nftables: unavailable (%v)\n", nerr)
	}
	fmt.Printf("%-40s %-15s %-15s %-8s %s\n", "NAME", "SYNTHETIC", "REAL", "NFT", "LAST QUERY")
	for _, e := range store.Entries() {
		real := "-"
		if len(e.Real) > 0 {
			real = e.Real[0].String()
		}
		mark := "?"
		if nerr == nil {
			switch got, ok := live[e.Synthetic]; {
			case !ok:
				mark = "missing"
			case len(e.Real) > 0 && got == e.Real[0]:
				mark = "ok"
			default:
				mark = "differs"
			}
		}
		fmt.Printf("%-40s %-15s %-15s %-8s %s\n", e.Name, e.Synthetic, real, mark, e.LastQuery.Format(time.RFC3339))
	}
	return nil
}

// health queries a name outside every zone: REFUSED proves the DNS listener answers without side effects.
func health(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	ap, _ := netip.ParseAddrPort(cfg.Listen[0])
	host := ap.Addr()
	if host.IsUnspecified() {
		host = netip.MustParseAddr("127.0.0.1")
		if ap.Addr().Is6() {
			host = netip.MustParseAddr("::1")
		}
	}
	q := new(dns.Msg)
	q.SetQuestion("health.invalid.", dns.TypeA)
	addr := net.JoinHostPort(host.String(), fmt.Sprint(ap.Port()))
	r, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(q, addr)
	if err != nil {
		return fmt.Errorf("dns %s: %w", addr, err)
	}
	if r.Rcode != dns.RcodeRefused {
		return fmt.Errorf("dns %s: unexpected rcode %s", addr, dns.RcodeToString[r.Rcode])
	}
	if _, err := nft.New(cfg.Interface, cfg.Prefix).List(); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	return nil
}
