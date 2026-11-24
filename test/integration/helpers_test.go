//go:build integration && linux

package integration

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// The test binary doubles as the helper programs that run inside the namespaces.
func runHelper(mode string) {
	var err error
	switch mode {
	case "dns":
		err = helperDNS(os.Getenv("TSR_ADDR"), os.Getenv("TSR_IPFILE"))
	case "echo":
		err = helperEcho(os.Getenv("TSR_ADDR"))
	case "icmpwatch":
		err = helperICMP(os.Getenv("TSR_OUT"))
	case "query":
		err = helperQuery(os.Getenv("TSR_SERVER"), os.Getenv("TSR_NAME"))
	case "tcp":
		err = helperTCP(os.Getenv("TSR_ADDR"))
	case "udp":
		err = helperUDP(os.Getenv("TSR_ADDR"), 1, 0)
	case "udpflow":
		err = helperUDP(os.Getenv("TSR_ADDR"), 40, time.Second)
	default:
		err = fmt.Errorf("unknown helper %q", mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func helperDNS(addr, ipfile string) error {
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			b, _ := os.ReadFile(ipfile)
			r.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP(strings.TrimSpace(string(b))),
			}}
		}
		w.WriteMsg(r)
	})
	return (&dns.Server{Addr: addr, Net: "udp", Handler: h}).ListenAndServe()
}

func helperEcho(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "udp from %s\n", from)
			pc.WriteTo([]byte(fmt.Sprintf("src=%s dst=%s\n", from.(*net.UDPAddr).IP, addr[:strings.LastIndex(addr, ":")])), from)
		}
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "tcp from %s\n", c.RemoteAddr())
		fmt.Fprintf(c, "src=%s dst=%s\n", c.RemoteAddr().(*net.TCPAddr).IP, c.LocalAddr().(*net.TCPAddr).IP)
		c.Close()
	}
}

func helperICMP(out string) error {
	pc, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if n > 0 && buf[0] == 8 {
			f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			fmt.Fprintln(f, from.String())
			f.Close()
		}
	}
}

func helperQuery(server, name string) error {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r, _, err := (&dns.Client{Timeout: 5 * time.Second}).Exchange(q, server)
	if err != nil {
		return err
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		return fmt.Errorf("rcode %s, %d answers", dns.RcodeToString[r.Rcode], len(r.Answer))
	}
	fmt.Println(r.Answer[0].(*dns.A).A)
	return nil
}

func helperTCP(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

func helperUDP(addr string, n int, every time.Duration) error {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	buf := make([]byte, 1500)
	for i := 0; i < n; i++ {
		if _, err := c.Write([]byte("x")); err != nil {
			return err
		}
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		k, err := c.Read(buf)
		if err != nil {
			return err
		}
		fmt.Print(string(buf[:k]))
		time.Sleep(every)
	}
	return nil
}
