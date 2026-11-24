//go:build integration && linux

package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	nsClient = "tsr-client"
	nsRouter = "tsr-router"
	nsServer = "tsr-server"
	nsOther  = "tsr-other"
)

var (
	testBin   string
	routerBin string
)

func TestMain(m *testing.M) {
	if h := os.Getenv("TSR_HELPER"); h != "" {
		runHelper(h)
	}
	os.Exit(m.Run())
}

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func nsCmd(ns string, args ...string) *exec.Cmd {
	return exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
}

func inNS(ns string, args ...string) []string {
	return append([]string{"ip", "netns", "exec", ns}, args...)
}

func helper(t *testing.T, ns, mode string, env ...string) (string, error) {
	t.Helper()
	cmd := nsCmd(ns, testBin)
	cmd.Env = append(os.Environ(), append([]string{"TSR_HELPER=" + mode}, env...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

type proc struct {
	cmd *exec.Cmd
	out *bytes.Buffer
}

func start(t *testing.T, ns string, name string, env []string, args ...string) *proc {
	t.Helper()
	cmd := nsCmd(ns, args...)
	cmd.Env = append(os.Environ(), env...)
	out := &bytes.Buffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proc{cmd, out}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("%s output:\n%s", name, out.String())
		}
	})
	return p
}

func (p *proc) stop(t *testing.T) {
	t.Helper()
	p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("process did not stop on SIGTERM")
	}
}

func setupNetwork(t *testing.T) {
	for _, ns := range []string{nsClient, nsRouter, nsServer, nsOther} {
		exec.Command("ip", "netns", "del", ns).Run()
		sh(t, "ip", "netns", "add", ns)
		sh(t, inNS(ns, "ip", "link", "set", "lo", "up")...)
	}
	t.Cleanup(func() {
		for _, ns := range []string{nsClient, nsRouter, nsServer, nsOther} {
			exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	link := func(nsA, a, addrA, nsB, b, addrB string) {
		sh(t, "ip", "link", "add", a, "netns", nsA, "type", "veth", "peer", "name", b, "netns", nsB)
		sh(t, inNS(nsA, "ip", "addr", "add", addrA, "dev", a)...)
		sh(t, inNS(nsA, "ip", "link", "set", a, "up")...)
		sh(t, inNS(nsB, "ip", "addr", "add", addrB, "dev", b)...)
		sh(t, inNS(nsB, "ip", "link", "set", b, "up")...)
	}
	link(nsClient, "c0", "10.100.1.2/24", nsRouter, "tailscale0", "10.100.1.1/24")
	link(nsServer, "s0", "10.100.2.2/24", nsRouter, "eth0", "10.100.2.1/24")
	link(nsOther, "o0", "10.100.3.2/24", nsRouter, "eth1", "10.100.3.1/24")
	sh(t, inNS(nsServer, "ip", "addr", "add", "10.100.2.3/24", "dev", "s0")...)
	sh(t, inNS(nsServer, "ip", "route", "add", "default", "via", "10.100.2.1")...)
	sh(t, inNS(nsClient, "ip", "route", "add", "198.18.0.0/15", "via", "10.100.1.1")...)
	sh(t, inNS(nsOther, "ip", "route", "add", "198.18.0.0/15", "via", "10.100.3.1")...)
	sh(t, inNS(nsRouter, "sysctl", "-w", "net.ipv4.ip_forward=1")...)
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestDataPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dir := t.TempDir()
	var err error
	if testBin, err = os.Executable(); err != nil {
		t.Fatal(err)
	}
	routerBin = filepath.Join(dir, "ts-router")
	sh(t, "go", "build", "-o", routerBin, "../../cmd/ts-router")
	setupNetwork(t)

	ipFile := filepath.Join(dir, "real_ip")
	os.WriteFile(ipFile, []byte("10.100.2.2\n"), 0o644)
	cfgPath := filepath.Join(dir, "config.toml")
	cfg := fmt.Sprintf(`listen = ["10.100.1.1:53"]
interface = "tailscale0"
state_file = %q
upstreams = ["127.0.0.1:5353"]
allow_sources = ["10.100.1.2/32"]

[[zone]]
name = "test.example"
`, filepath.Join(dir, "state.json"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	start(t, nsRouter, "fake upstream", []string{"TSR_HELPER=dns", "TSR_ADDR=127.0.0.1:5353", "TSR_IPFILE=" + ipFile}, testBin)
	srv1 := start(t, nsServer, "echo 2", []string{"TSR_HELPER=echo", "TSR_ADDR=10.100.2.2:7000"}, testBin)
	srv2 := start(t, nsServer, "echo 3", []string{"TSR_HELPER=echo", "TSR_ADDR=10.100.2.3:7000"}, testBin)
	icmpOut := filepath.Join(dir, "icmp_sources")
	start(t, nsServer, "icmp watch", []string{"TSR_HELPER=icmpwatch", "TSR_OUT=" + icmpOut}, testBin)
	time.Sleep(500 * time.Millisecond)

	startRouter := func() *proc {
		p := start(t, nsRouter, "ts-router", nil, routerBin, "serve", "-config", cfgPath)
		waitFor(t, "ts-router health", 10*time.Second, func() bool {
			return nsCmd(nsRouter, routerBin, "health", "-config", cfgPath).Run() == nil
		})
		return p
	}
	router := startRouter()

	query := func() string {
		out, err := helper(t, nsClient, "query", "TSR_SERVER=10.100.1.1:53", "TSR_NAME=svc.test.example")
		if err != nil {
			t.Fatalf("query: %v: %s", err, out)
		}
		return out
	}
	syn := query()
	if syn != "198.18.0.1" {
		t.Fatalf("synthetic IP %q", syn)
	}

	t.Run("tcp", func(t *testing.T) {
		out, err := helper(t, nsClient, "tcp", "TSR_ADDR="+syn+":7000")
		if err != nil || out != "src=10.100.2.1 dst=10.100.2.2" {
			t.Fatalf("%v: %q", err, out)
		}
	})
	t.Run("udp", func(t *testing.T) {
		out, err := helper(t, nsClient, "udp", "TSR_ADDR="+syn+":7000")
		if err != nil || out != "src=10.100.2.1 dst=10.100.2.2" {
			t.Fatalf("%v: %q", err, out)
		}
	})
	t.Run("icmp", func(t *testing.T) {
		sh(t, inNS(nsClient, "ping", "-c", "2", "-W", "2", syn)...)
		waitFor(t, "icmp source file", 3*time.Second, func() bool {
			b, _ := os.ReadFile(icmpOut)
			return strings.Contains(string(b), "10.100.2.1")
		})
		b, _ := os.ReadFile(icmpOut)
		if strings.Contains(string(b), "10.100.1.2") {
			t.Fatalf("server saw the client address: %s", b)
		}
	})
	t.Run("unmapped synthetic IP is dropped", func(t *testing.T) {
		before := srv1.out.String() + srv2.out.String()
		for _, mode := range []string{"tcp", "udp"} {
			start := time.Now()
			out, err := helper(t, nsClient, mode, "TSR_ADDR=198.18.99.99:7000")
			if err == nil {
				t.Fatalf("%s reached something: %s", mode, out)
			}
			if mode == "tcp" && time.Since(start) < 2*time.Second {
				t.Fatalf("tcp failed fast (%v), expected a silent drop: %s", time.Since(start), out)
			}
		}
		if err := nsCmd(nsClient, "ping", "-c", "1", "-W", "2", "198.18.99.99").Run(); err == nil {
			t.Fatal("ping to unmapped IP succeeded")
		}
		if srv1.out.String()+srv2.out.String() != before {
			t.Fatal("server saw traffic")
		}
	})
	t.Run("other interface is not translated", func(t *testing.T) {
		before := srv1.out.String()
		if out, err := helper(t, nsOther, "tcp", "TSR_ADDR="+syn+":7000"); err == nil {
			t.Fatalf("translated: %s", out)
		}
		if out, err := helper(t, nsOther, "udp", "TSR_ADDR="+syn+":7000"); err == nil {
			t.Fatalf("translated: %s", out)
		}
		if srv1.out.String() != before {
			t.Fatal("server saw traffic")
		}
	})
	t.Run("status shows the map entry", func(t *testing.T) {
		out, err := nsCmd(nsRouter, routerBin, "status", "-config", cfgPath).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "svc.test.example") || !strings.Contains(string(out), " ok ") {
			t.Fatalf("status: %v\n%s", err, out)
		}
	})

	t.Run("restart keeps table and synthetic IP", func(t *testing.T) {
		router.stop(t)
		out, err := helper(t, nsClient, "tcp", "TSR_ADDR="+syn+":7000")
		if err != nil || out != "src=10.100.2.1 dst=10.100.2.2" {
			t.Fatalf("flows must work while ts-router is down: %v %q", err, out)
		}
		router = startRouter()
		if got := query(); got != syn {
			t.Fatalf("synthetic changed to %s", got)
		}
	})

	t.Run("repairs a removed table", func(t *testing.T) {
		sh(t, inNS(nsRouter, "nft", "delete", "table", "inet", "ts_router")...)
		if out, err := helper(t, nsClient, "tcp", "TSR_ADDR="+syn+":7000"); err == nil {
			t.Fatalf("flow works without the table: %s", out)
		}
		waitFor(t, "table repair", 45*time.Second, func() bool {
			out, err := helper(t, nsClient, "tcp", "TSR_ADDR="+syn+":7000")
			return err == nil && out == "src=10.100.2.1 dst=10.100.2.2"
		})
	})

	t.Run("real IP change", func(t *testing.T) {
		type flow struct {
			out string
			err error
		}
		old := make(chan flow, 1)
		go func() {
			out, err := helper(t, nsClient, "udpflow", "TSR_ADDR="+syn+":7000")
			old <- flow{out, err}
		}()
		time.Sleep(time.Second)
		os.WriteFile(ipFile, []byte("10.100.2.3\n"), 0o644)
		// real TTL is clamped to 30s, so the new address appears on the first query after that
		waitFor(t, "map update", 60*time.Second, func() bool {
			query()
			out, err := helper(t, nsClient, "tcp", "TSR_ADDR="+syn+":7000")
			return err == nil && out == "src=10.100.2.1 dst=10.100.2.3"
		})
		if got := query(); got != syn {
			t.Fatalf("synthetic changed to %s", got)
		}
		f := <-old
		if f.err != nil {
			t.Fatalf("open UDP flow broke: %v\n%s", f.err, f.out)
		}
		lines := strings.Split(f.out, "\n")
		if len(lines) != 40 {
			t.Fatalf("got %d replies", len(lines))
		}
		for _, l := range lines {
			if l != "src=10.100.2.1 dst=10.100.2.2" {
				t.Fatalf("open flow moved to a new IP: %q", l)
			}
		}
		out, err := helper(t, nsClient, "udp", "TSR_ADDR="+syn+":7000")
		if err != nil || out != "src=10.100.2.1 dst=10.100.2.3" {
			t.Fatalf("new UDP flow: %v %q", err, out)
		}
	})

	t.Run("cleanup removes the table", func(t *testing.T) {
		router.stop(t)
		sh(t, inNS(nsRouter, routerBin, "cleanup")...)
		out, _ := nsCmd(nsRouter, routerBin, "status", "-config", cfgPath).CombinedOutput()
		if !strings.Contains(string(out), "nftables: unavailable") {
			t.Fatalf("table still present:\n%s", out)
		}
		if out, err := helper(t, nsClient, "tcp", "TSR_ADDR="+syn+":7000"); err == nil {
			t.Fatalf("flow reached server without table: %s", out)
		}
	})
}
