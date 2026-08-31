//go:build windows

// setMulticastInterface for Windows: the raw fd is a syscall.Handle and
// IP_MULTICAST_IF takes struct ip_mreq { imr_multiaddr (INADDR_ANY),
// imr_address (the interface) } — the same layout as the unix path.

package upnp

import (
	"net"
	"syscall"
)

// setMulticastInterface pins the socket's outgoing multicast interface
// (IP_MULTICAST_IF) to ip — best-effort; errors are ignored (the multicast
// send then simply follows the routing table as before).
func setMulticastInterface(conn *net.UDPConn, ip net.IP) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		var mreq syscall.IPMreq
		copy(mreq.Interface[:], ip.To4())
		_ = syscall.SetsockoptIPMreq(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, &mreq)
	})
}
