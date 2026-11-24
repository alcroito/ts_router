//go:build linux

package server

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// freebind lets the socket bind a tailnet address before tailscale0 has it.
func freebind(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if strings.HasSuffix(network, "6") {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
		}
	})
	if err != nil {
		return err
	}
	return serr
}
