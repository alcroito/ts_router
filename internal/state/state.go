package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"
)

// FreeCooldown is how long a freed synthetic IP stays unused, well beyond any client cache.
const FreeCooldown = 24 * time.Hour

type Entry struct {
	Name       string       `json:"name"`
	Synthetic  netip.Addr   `json:"synthetic"`
	Real       []netip.Addr `json:"real"`
	RealExpiry time.Time    `json:"real_expiry"`
	LastQuery  time.Time    `json:"last_query"`
}

func (e Entry) clone() Entry {
	e.Real = slices.Clone(e.Real)
	return e
}

type freedIP struct {
	IP netip.Addr `json:"ip"`
	At time.Time  `json:"at"`
}

type fileFormat struct {
	Next    uint32    `json:"next"`
	Entries []Entry   `json:"entries"`
	Freed   []freedIP `json:"freed"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	prefix  netip.Prefix
	size    uint32
	entries map[string]*Entry
	used    map[netip.Addr]bool
	freed   map[netip.Addr]time.Time
	next    uint32
	dirty   bool
}

// Open loads the state file; a missing file gives an empty store.
func Open(path string, prefix netip.Prefix) (*Store, error) {
	s := &Store{
		path:    path,
		prefix:  prefix,
		size:    uint32(1) << (32 - prefix.Bits()),
		entries: map[string]*Entry{},
		used:    map[netip.Addr]bool{},
		freed:   map[netip.Addr]time.Time{},
		next:    1,
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f fileFormat
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if f.Next >= 1 && f.Next < s.size-1 {
		s.next = f.Next
	}
	for i := range f.Entries {
		e := f.Entries[i]
		if !prefix.Contains(e.Synthetic) || s.used[e.Synthetic] {
			continue
		}
		s.entries[e.Name] = &e
		s.used[e.Synthetic] = true
	}
	for _, fr := range f.Freed {
		if prefix.Contains(fr.IP) && !s.used[fr.IP] {
			s.freed[fr.IP] = fr.At
		}
	}
	return s, nil
}

func (s *Store) Get(name string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[name]
	if !ok {
		return Entry{}, false
	}
	return e.clone(), true
}

// Allocate returns the entry for name, creating it with a new synthetic IP if needed.
func (s *Store) Allocate(name string, now time.Time) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[name]; ok {
		return e.clone(), nil
	}
	ip, err := s.pick(now)
	if err != nil {
		return Entry{}, err
	}
	e := &Entry{Name: name, Synthetic: ip, LastQuery: now}
	s.entries[name] = e
	s.used[ip] = true
	if err := s.save(); err != nil {
		delete(s.entries, name)
		delete(s.used, ip)
		return Entry{}, err
	}
	return e.clone(), nil
}

func (s *Store) pick(now time.Time) (netip.Addr, error) {
	base := s.prefix.Addr().As4()
	b := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	for range s.size - 2 {
		off := s.next
		s.next++
		if s.next >= s.size-1 {
			s.next = 1
		}
		v := b + off
		ip := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		if s.used[ip] {
			continue
		}
		if at, ok := s.freed[ip]; ok {
			if now.Before(at.Add(FreeCooldown)) {
				continue
			}
			delete(s.freed, ip)
		}
		return ip, nil
	}
	return netip.Addr{}, errors.New("synthetic range exhausted")
}

// SetReal stores the resolved addresses and expiry; it saves the file only if the addresses changed.
func (s *Store) SetReal(name string, real []netip.Addr, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[name]
	if !ok {
		return fmt.Errorf("no allocation for %q", name)
	}
	changed := !slices.Equal(e.Real, real)
	e.Real = slices.Clone(real)
	e.RealExpiry = expiry
	if !changed {
		s.dirty = true
		return nil
	}
	return s.save()
}

func (s *Store) Touch(name string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[name]; ok {
		e.LastQuery = now
		s.dirty = true
	}
}

// SetExpiry moves the real-IP expiry without rewriting the file.
func (s *Store) SetExpiry(name string, expiry time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[name]; ok {
		e.RealExpiry = expiry
		s.dirty = true
	}
}

// GC drops entries not queried for longer than after and returns them.
// The entries are dropped from memory even if saving fails.
func (s *Store) GC(now time.Time, after time.Duration) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []Entry
	for name, e := range s.entries {
		if now.Sub(e.LastQuery) > after {
			gone = append(gone, e.clone())
			delete(s.entries, name)
			delete(s.used, e.Synthetic)
			s.freed[e.Synthetic] = now
		}
	}
	if len(gone) > 0 {
		return gone, s.save()
	}
	return gone, nil
}

func (s *Store) Entries() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Synthetic.Less(out[j].Synthetic) })
	return out
}

// Flush writes the file if timestamps changed since the last save.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.save()
}

func (s *Store) save() error {
	f := fileFormat{Next: s.next}
	for _, e := range s.entries {
		f.Entries = append(f.Entries, *e)
	}
	sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].Synthetic.Less(f.Entries[j].Synthetic) })
	for ip, at := range s.freed {
		f.Freed = append(f.Freed, freedIP{ip, at})
	}
	sort.Slice(f.Freed, func(i, j int) bool { return f.Freed[i].IP.Less(f.Freed[j].IP) })
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}
