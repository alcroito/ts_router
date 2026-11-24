package nft

import (
	"net/netip"
	"sort"
	"sync"
)

const (
	TableName = "ts_router"
	MapName   = "v4"
)

// Backend manages the nftables table holding the synthetic -> real map.
type Backend interface {
	// Setup recreates the table atomically and fills the map.
	Setup(entries map[netip.Addr]netip.Addr) error
	// Set adds or replaces one map element.
	Set(synthetic, real netip.Addr) error
	Delete(synthetic netip.Addr) error
	List() (map[netip.Addr]netip.Addr, error)
	// Cleanup removes the table; a missing table is not an error.
	Cleanup() error
}

// Fake is an in-memory Backend for tests.
type Fake struct {
	mu       sync.Mutex
	M        map[netip.Addr]netip.Addr
	Writes   []string
	SetupOK  bool
	FailSet  error
	FailList error
}

func NewFake() *Fake { return &Fake{M: map[netip.Addr]netip.Addr{}} }

func (f *Fake) Setup(e map[netip.Addr]netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.M = map[netip.Addr]netip.Addr{}
	for k, v := range e {
		f.M[k] = v
	}
	f.SetupOK = true
	f.Writes = append(f.Writes, "setup")
	return nil
}

func (f *Fake) Set(s, r netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailSet != nil {
		return f.FailSet
	}
	f.M[s] = r
	f.Writes = append(f.Writes, "set "+s.String()+" "+r.String())
	return nil
}

func (f *Fake) Delete(s netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.M, s)
	f.Writes = append(f.Writes, "del "+s.String())
	return nil
}

func (f *Fake) List() (map[netip.Addr]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailList != nil {
		return nil, f.FailList
	}
	out := map[netip.Addr]netip.Addr{}
	for k, v := range f.M {
		out[k] = v
	}
	return out, nil
}

func (f *Fake) Cleanup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.M = map[netip.Addr]netip.Addr{}
	f.SetupOK = false
	return nil
}

func (f *Fake) Log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Writes...)
}

// SortedKeys is a helper for stable output.
func SortedKeys(m map[netip.Addr]netip.Addr) []netip.Addr {
	keys := make([]netip.Addr, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Less(keys[j]) })
	return keys
}
