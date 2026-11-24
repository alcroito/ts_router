//go:build !linux

package server

import "syscall"

func freebind(network, address string, c syscall.RawConn) error { return nil }
