//go:build !linux

package nft

import (
	"errors"
	"net/netip"
)

type unsupported struct{}

func New(iface string, prefix netip.Prefix) Backend { return unsupported{} }

var errUnsupported = errors.New("nftables backend requires Linux")

func (unsupported) Setup(map[netip.Addr]netip.Addr) error { return errUnsupported }
func (unsupported) Set(_, _ netip.Addr) error             { return errUnsupported }
func (unsupported) Delete(netip.Addr) error               { return errUnsupported }
func (unsupported) Cleanup() error                        { return errUnsupported }
func (unsupported) List() (map[netip.Addr]netip.Addr, error) {
	return nil, errUnsupported
}
