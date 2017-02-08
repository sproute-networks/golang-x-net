// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd solaris windows

package icmp

import (
	"net"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/net/internal/iana"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ListenPacket listens for incoming ICMP packets addressed to
// address [on this interface]. See net.Dial for the syntax of address.
//
// For non-privileged datagram-oriented ICMP endpoints, network must
// be "udp4" or "udp6". The endpoint allows to read, write a few
// limited ICMP messages such as echo request and echo reply.
// Currently only Darwin and Linux support this.
//
// Examples:
//	IfListenPacket("eth0", "udp4", "192.168.0.1")
//	IfListenPacket("eth0", "udp4", "0.0.0.0")
//	IfListenPacket("eth0", "udp6", "fe80::1%en0")
//	IfListenPacket("eth0", "udp6", "::")
//
// For privileged raw ICMP endpoints, network must be "ip4" or "ip6"
// followed by a colon and an ICMP protocol number or name.
//
// Examples:
//	IfListenPacket("eth0", "ip4:icmp", "192.168.0.1")
//	IfListenPacket("eth0", "ip4:1", "0.0.0.0")
//	IfListenPacket("eth0", "ip6:ipv6-icmp", "fe80::1%en0")
//	IfListenPacket("eth0", "ip6:58", "::")
func IfListenPacket(ifstr, network, address string) (*PacketConn, error) {
	var family, proto int

	dgram := false
	switch network {
	case "udp4":
		family, proto = syscall.AF_INET, iana.ProtocolICMP
		dgram = true
	case "udp6":
		family, proto = syscall.AF_INET6, iana.ProtocolIPv6ICMP
		dgram = true
	default:
		i := last(network, ':')
		switch network[:i] {
		case "ip4":
			family, proto = syscall.AF_INET, iana.ProtocolICMP
		case "ip6":
			family, proto = syscall.AF_INET6, iana.ProtocolIPv6ICMP
		default:
			return nil, os.ErrInvalid
		}
	}

	var cerr,err error
	var c net.PacketConn
	var s int

	if dgram {
		s, err = syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	} else {
		s, err = syscall.Socket(family, syscall.SOCK_RAW, proto)
	}

	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	if runtime.GOOS == "darwin" && family == syscall.AF_INET {
		if err := syscall.SetsockoptInt(s, iana.ProtocolIP, sysIP_STRIPHDR, 1); err != nil {
			syscall.Close(s)
			return nil, os.NewSyscallError("setsockopt", err)
		}
	}
	sa, err := sockaddr(family, address)
	if err != nil {
		syscall.Close(s)
		return nil, err
	}
	if err := syscall.Bind(s, sa); err != nil {
		syscall.Close(s)
		return nil, os.NewSyscallError("bind", err)
	}
	if ifstr != "" {
		err = syscall.BindToDevice(s, ifstr)
		if err != nil {
			syscall.Close(s)
			return nil, os.NewSyscallError("bindtodevice", err)
		}
	}

	var f *os.File

	if dgram {
		f = os.NewFile(uintptr(s), "datagram-oriented icmp")
	} else {
		f = os.NewFile(uintptr(s), "raw icmp")
	}

	c, cerr = net.FilePacketConn(f)
	f.Close()

	if cerr != nil {
		return nil, cerr
	}

	switch proto {
	case iana.ProtocolICMP:
		return &PacketConn{c: c, p4: ipv4.NewPacketConn(c)}, nil
	case iana.ProtocolIPv6ICMP:
		return &PacketConn{c: c, p6: ipv6.NewPacketConn(c)}, nil
	default:
		return nil, os.ErrInvalid
	}
}
