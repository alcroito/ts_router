package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"net/netip"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func open(t *testing.T, path, prefix string) *Store {
	t.Helper()
	s, err := Open(path, netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAllocateStableAndSequential(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "s.json"), "198.18.0.0/15")
	a, _ := s.Allocate("a.test", t0)
	b, _ := s.Allocate("b.test", t0)
	a2, _ := s.Allocate("a.test", t0)
	if a.Synthetic != netip.MustParseAddr("198.18.0.1") || b.Synthetic != netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("got %v %v", a.Synthetic, b.Synthetic)
	}
	if a2.Synthetic != a.Synthetic {
		t.Fatal("not stable")
	}
}

func TestRoundTripAcrossRestart(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "s.json")
	s := open(t, p, "198.18.0.0/15")
	a, _ := s.Allocate("a.test", t0)
	real := []netip.Addr{netip.MustParseAddr("1.2.3.4")}
	if err := s.SetReal("a.test", real, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.Touch("a.test", t0.Add(time.Hour))
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}

	s2 := open(t, p, "198.18.0.0/15")
	got, ok := s2.Get("a.test")
	if !ok || got.Synthetic != a.Synthetic || got.Real[0] != real[0] || !got.LastQuery.Equal(t0.Add(time.Hour)) {
		t.Fatalf("round trip: %+v", got)
	}
	c, _ := s2.Allocate("c.test", t0)
	if c.Synthetic != netip.MustParseAddr("198.18.0.2") {
		t.Fatalf("next not persisted: %v", c.Synthetic)
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".state-*")); len(m) != 0 {
		t.Fatalf("temp files left: %v", m)
	}
}

func TestWrapAround(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "s.json"), "10.0.0.0/29")
	var ips []netip.Addr
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		e, err := s.Allocate(n, t0)
		if err != nil {
			t.Fatal(err)
		}
		ips = append(ips, e.Synthetic)
	}
	if ips[0] != netip.MustParseAddr("10.0.0.1") || ips[5] != netip.MustParseAddr("10.0.0.6") {
		t.Fatalf("usable range wrong: %v", ips)
	}
	if _, err := s.Allocate("g", t0); err == nil {
		t.Fatal("expected exhaustion")
	}
	// free "b" (10.0.0.2) and wrap: the next allocation after cooldown must find it.
	s.Touch("a", t0.Add(100*time.Hour))
	for _, n := range []string{"c", "d", "e", "f"} {
		s.Touch(n, t0.Add(100*time.Hour))
	}
	gone := s.GC(t0.Add(100*time.Hour), time.Hour)
	if len(gone) != 1 || gone[0].Name != "b" {
		t.Fatalf("gc: %+v", gone)
	}
	g, err := s.Allocate("g", t0.Add(100*time.Hour+FreeCooldown))
	if err != nil || g.Synthetic != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("wrap: %v %v", g.Synthetic, err)
	}
}

func TestFreedNotReusedDuringCooldown(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "s.json"), "10.0.0.0/29")
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		s.Allocate(n, t0)
	}
	now := t0.Add(48 * time.Hour)
	for _, n := range []string{"a", "c", "d", "e", "f"} {
		s.Touch(n, now)
	}
	s.GC(now, time.Hour)
	if _, err := s.Allocate("g", now.Add(time.Hour)); err == nil {
		t.Fatal("freed IP reused inside cooldown")
	}
	if _, err := s.Allocate("g", now.Add(FreeCooldown+time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestGCKeepsRecent(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "s.json"), "198.18.0.0/15")
	s.Allocate("old", t0)
	s.Allocate("new", t0.Add(29*24*time.Hour))
	gone := s.GC(t0.Add(31*24*time.Hour), 30*24*time.Hour)
	if len(gone) != 1 || gone[0].Name != "old" {
		t.Fatalf("gc: %+v", gone)
	}
	if _, ok := s.Get("new"); !ok {
		t.Fatal("new dropped")
	}
	// the freed IP survives a restart
	s2 := open(t, s.path, "198.18.0.0/15")
	if len(s2.freed) != 1 {
		t.Fatalf("freed not persisted: %v", s2.freed)
	}
}

func TestOpenCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(p, []byte("{"), 0o600)
	if _, err := Open(p, netip.MustParsePrefix("198.18.0.0/15")); err == nil {
		t.Fatal("expected error")
	}
}

func TestPrefixChangeDropsForeignEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	s := open(t, p, "198.18.0.0/15")
	s.Allocate("a", t0)
	s2 := open(t, p, "10.9.0.0/16")
	if len(s2.Entries()) != 0 {
		t.Fatal("foreign entry kept")
	}
}
