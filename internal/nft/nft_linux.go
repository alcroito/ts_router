//go:build linux

package nft

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type backend struct {
	iface  string
	prefix netip.Prefix
}

func New(iface string, prefix netip.Prefix) Backend {
	return &backend{iface: iface, prefix: prefix}
}

func table() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
}

func b4(a netip.Addr) []byte {
	v := a.As4()
	return v[:]
}

func ifname(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	return b
}

func mask4(bits int) []byte {
	m := uint32(0xffffffff) << (32 - bits)
	return []byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}
}

// ipv4Only guards ip header matches in the inet table.
func ipv4Only() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
	}
}

func inPrefix(p netip.Prefix) []expr.Any {
	return []expr.Any{
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask4(p.Bits()), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b4(p.Addr())},
	}
}

func daddr() expr.Any {
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}
}

func (b *backend) Setup(entries map[netip.Addr]netip.Addr) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := table()
	// add, delete, add in one batch: replaces an existing table atomically and does not fail if absent.
	c.AddTable(t)
	c.DelTable(t)
	t = c.AddTable(t)

	set := &nftables.Set{
		Table:    t,
		Name:     MapName,
		IsMap:    true,
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeIPAddr,
	}
	var elems []nftables.SetElement
	for s, r := range entries {
		elems = append(elems, nftables.SetElement{Key: b4(s), Val: b4(r)})
	}
	if err := c.AddSet(set, elems); err != nil {
		return err
	}

	accept := nftables.ChainPolicyAccept
	pre := c.AddChain(&nftables.Chain{
		Name: "prerouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept,
	})
	rule := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(b.iface)},
	}
	rule = append(rule, ipv4Only()...)
	rule = append(rule, daddr())
	rule = append(rule, inPrefix(b.prefix)...)
	rule = append(rule,
		daddr(),
		&expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: set.Name, SetID: set.ID},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1},
	)
	c.AddRule(&nftables.Rule{Table: t, Chain: pre, Exprs: rule})

	drop := c.AddChain(&nftables.Chain{
		Name: "drop_unmapped", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest + 10), Policy: &accept,
	})
	rule = ipv4Only()
	rule = append(rule, daddr())
	rule = append(rule, inPrefix(b.prefix)...)
	rule = append(rule, &expr.Verdict{Kind: expr.VerdictDrop})
	c.AddRule(&nftables.Rule{Table: t, Chain: drop, Exprs: rule})

	post := c.AddChain(&nftables.Chain{
		Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource, Policy: &accept,
	})
	rule = ipv4Only()
	rule = append(rule,
		&expr.Ct{Register: 1, Key: expr.CtKeyDST, Direction: 0},
	)
	rule = append(rule, inPrefix(b.prefix)...)
	rule = append(rule, &expr.Masq{})
	c.AddRule(&nftables.Rule{Table: t, Chain: post, Exprs: rule})

	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables setup: %w", err)
	}
	return nil
}

func (b *backend) mapSet(c *nftables.Conn) (*nftables.Set, error) {
	return c.GetSetByName(table(), MapName)
}

func (b *backend) Set(s, r netip.Addr) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	set, err := b.mapSet(c)
	if err != nil {
		return err
	}
	cur, err := c.GetSetElements(set)
	if err != nil {
		return err
	}
	for _, e := range cur {
		if string(e.Key) == string(b4(s)) {
			if string(e.Val) == string(b4(r)) {
				return nil
			}
			// the kernel refuses to overwrite a map element, so delete and add in one batch
			if err := c.SetDeleteElements(set, []nftables.SetElement{{Key: b4(s)}}); err != nil {
				return err
			}
			break
		}
	}
	if err := c.SetAddElements(set, []nftables.SetElement{{Key: b4(s), Val: b4(r)}}); err != nil {
		return err
	}
	return c.Flush()
}

func (b *backend) Delete(s netip.Addr) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	set, err := b.mapSet(c)
	if err != nil {
		return err
	}
	cur, err := c.GetSetElements(set)
	if err != nil {
		return err
	}
	for _, e := range cur {
		if string(e.Key) == string(b4(s)) {
			if err := c.SetDeleteElements(set, []nftables.SetElement{{Key: b4(s)}}); err != nil {
				return err
			}
			return c.Flush()
		}
	}
	return nil
}

func (b *backend) List() (map[netip.Addr]netip.Addr, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	set, err := b.mapSet(c)
	if err != nil {
		return nil, err
	}
	elems, err := c.GetSetElements(set)
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]netip.Addr{}
	for _, e := range elems {
		k, ok1 := netip.AddrFromSlice(e.Key)
		v, ok2 := netip.AddrFromSlice(e.Val)
		if ok1 && ok2 {
			out[k] = v
		}
	}
	return out, nil
}

func (b *backend) Cleanup() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	t := table()
	c.AddTable(t)
	c.DelTable(t)
	if err := c.Flush(); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}
