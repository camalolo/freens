//go:build !windows

// setMulticastInterface for the unixes: the fd is a plain int and the
// 8-byte ip_mreq(/ip_mreqn) layout carries {INADDR_ANY, interface address}.

package upnp

import (
	"net"
	"syscall"
	"unsafe"
)

// unsafePointer reinterprets the 8-byte ip_mreq layout for the
// SetsockoptIPMreq call (avoids importing x/net for one setsockopt).
func unsafePointer(b *[8]byte) unsafe.Pointer { return unsafe.Pointer(b) }

// setMulticastInterface pins the socket's outgoing multicast interface
// (IP_MULTICAST_IF) to ip — best-effort via the raw fd; errors are ignored
// (the multicast send then simply follows the routing table as before).
func setMulticastInterface(conn *net.UDPConn, ip net.IP) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		var mreq [8]byte // struct ip_mreq_n { imr_multiaddr, imr_address }
		copy(mreq[4:], ip.To4())
		_ = syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, (*syscall.IPMreq)(unsafePointer(&mreq)))
	})
}
