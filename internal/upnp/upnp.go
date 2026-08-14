// Package upnp implements the subset of UPnP IGD (Internet Gateway Device)
// needed for zero-config DHT reachability: discover the LAN's router over
// SSDP, ask it to forward this node's UDP DHT port (AddAnyPortMapping, with
// the IGDv1 AddPortMapping fallback), learn the external address, and
// release the mapping at shutdown.
//
// # Where it sits in the NAT ladder
//
//	-advertise (explicit)  >  UPnP (this package, default-on)  >
//	-turn-relay  >  -stun (discovery)  >  observed source
//
// A router-granted mapping is the best zero-config outcome: explicit,
// stable across source addresses (so it holds where a STUN-discovered
// reflexive address would not), and free of relay bandwidth/trust costs.
// It requires the router to have UPnP enabled and to be the true edge
// (CGNAT carriers answer from behind their own NAT — GetExternalIPAddress
// returns the carrier's address while the mapping is meaningless there;
// the package treats a 0.0.0.0/empty external address as failure).
//
// # Scope and security posture
//
//   - Services: WANIPConnection:1/:2 and WANPPPConnection:1 control URLs,
//     discovered from the device description XML (nested deviceList walk —
//     IGDs bury the connection service 2–3 levels deep).
//   - Actions: AddAnyPortMapping (IGDv2, router picks the external port and
//     returns it), AddPortMapping (IGDv1 exact-port, with a small random
//     retry on 718 ConflictInMappingEntry), GetExternalIPAddress,
//     DeletePortMapping. Nothing else — this client never enumerates,
//     reads, or modifies mappings other than the one it created.
//   - The mapping is labeled (NewPortMappingDescription), UDP-only, points
//     solely at THIS host's internal port, and uses lease duration 0
//     (permanent) with an explicit DeletePortMapping at shutdown.
//   - SSDP responses are only trusted to yield http:// LOCATION URLs; the
//     device XML and SOAP control endpoints are then fetched like any
//     other HTTP service. (SSDP has no authentication by design — the
//     caller treats the whole feature as best-effort convenience.)
package upnp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// unsafePointer reinterprets the 8-byte ip_mreq layout for the
// SetsockoptIPMreq call (avoids importing x/net for one setsockopt).
func unsafePointer(b *[8]byte) unsafe.Pointer { return unsafe.Pointer(b) }

const (
	ssdpAddr   = "239.255.255.250:1900"
	ssdpWave   = 1500 * time.Millisecond // per M-SEARCH response window
	httpWait   = 3 * time.Second         // device XML / SOAP round trip
	maxDevices = 3                       // device descriptions fetched per Discover
	soapEnv    = `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>%s</s:Body></s:Envelope>`
)

// searchTargets are the SSDP ST values routers answer with their device
// description LOCATION (IGD v1 and v2 device types).
var searchTargets = []string{
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
}

// ---------------------------------------------------------------------------
// Gateway discovery
// ---------------------------------------------------------------------------

// Gateway is one discovered IGD: its device-description base URL and the
// resolved control endpoint for a WAN connection service.
type Gateway struct {
	base    *url.URL // device description URL (control URLs resolve against it)
	control *url.URL // WANIPConnection / WANPPPConnection control URL
	service string   // the service URN, e.g. urn:schemas-upnp-org:service:WANIPConnection:1
	log     Logger
}

// Logger is the minimal logging surface (satisfied by *slog.Logger).
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

// Service returns the WAN connection service URN (diagnostics).
func (g *Gateway) Service() string { return g.service }

// ControlURL returns the SOAP control endpoint (diagnostics).
func (g *Gateway) ControlURL() string { return g.control.String() }

// ssdpSearch is the injectable SSDP wave (tests substitute a fake LOCATION).
var ssdpSearch = func(ctx context.Context) ([]string, error) {
	return ssdpWave0(ctx)
}

func ssdpWave0(ctx context.Context) ([]string, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("upnp: ssdp socket: %w", err)
	}
	defer conn.Close()
	dst, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	deadline := time.Now().Add(ssdpWave)

	msearch := func(st string) string {
		return fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: %s\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n", ssdpAddr, st)
	}

	// (1) Multicast, pinned to each candidate LAN interface. A multi-homed
	// host's default route may point AWAY from the IGD's LAN (a PPPoE WAN
	// link, a second NIC): the kernel then multicasts out the wrong face
	// and the router never hears the M-SEARCH. IP_MULTICAST_IF forces each
	// LAN-shaped interface in turn (best-effort; failures fall through to
	// the other sends).
	for _, ip := range lanInterfaceIPs() {
		setMulticastInterface(conn, ip)
		for _, st := range searchTargets {
			// Non-fatal: a VPN/tun interface can hold a private IPv4 yet
			// fail its multicast send (ENOKEY and friends) — one dead
			// face must not abort the wave for the healthy ones.
			_, _ = conn.WriteToUDP([]byte(msearch(st)), dst)
		}
	}
	// (2) Unicast straight at the routing table's default gateway. Some
	// firmwares ignore multicast M-SEARCH entirely; the gateway is by
	// definition where the IGD lives. /proc/net/route is Linux (this
	// daemon's platform); elsewhere the step is skipped and multicast
	// alone carries the wave.
	for _, gw := range defaultGateways() {
		ua := &net.UDPAddr{IP: gw, Port: 1900}
		for _, st := range searchTargets {
			if _, err := conn.WriteToUDP([]byte(msearch(st)), ua); err == nil {
				break // one ST per gateway is enough to elicit a LOCATION
			}
		}
	}

	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		if err := conn.SetReadDeadline(time.Now().Add(time.Until(deadline))); err != nil {
			break
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // deadline: wave over
		}
		if loc, ok := parseLocation(buf[:n]); ok {
			seen[loc] = true // single reader goroutine: no lock needed
		}
	}
	out := make([]string, 0, len(seen))
	for loc := range seen {
		out = append(out, loc)
	}
	return out, nil
}

// lanInterfaceIPs lists IPv4 addresses of plausible LAN interfaces: up,
// non-loopback, private (RFC1918) — the faces an IGD could sit behind.
func lanInterfaceIPs() []net.IP {
	var out []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 != nil && ip4.IsPrivate() {
				out = append(out, ip4)
			}
		}
	}
	return out
}

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

// defaultGateways parses /proc/net/route (Linux) for gateways of default
// routes, returning their IPs. The kernel writes addresses as little-endian
// hex per 32-bit word ("0100A8C0" = 192.168.0.1). Missing/unparseable file
// yields nil.
func defaultGateways() []net.IP {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	return gatewaysFromRouteTable(data)
}

// gatewaysFromRouteTable is the pure parser over /proc/net/route content
// (testable): header line first; per row, Destination (field 2) 00000000
// means default and Gateway (field 3) carries the gateway.
func gatewaysFromRouteTable(data []byte) []net.IP {
	var out []net.IP
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		hexgw := fields[2]
		if len(hexgw) != 8 {
			continue
		}
		ip := make([]byte, 4)
		ok := true
		for b := 0; b < 4; b++ {
			var v uint64
			for _, c := range []byte{hexgw[2*(3-b)], hexgw[2*(3-b)+1]} {
				v <<= 4
				switch {
				case c >= '0' && c <= '9':
					v |= uint64(c - '0')
				case c >= 'A' && c <= 'F':
					v |= uint64(c-'A') + 10
				case c >= 'a' && c <= 'f':
					v |= uint64(c-'a') + 10
				default:
					ok = false
				}
			}
			if !ok || v > 255 {
				ok = false
				break
			}
			ip[b] = byte(v)
		}
		if ok && !(ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
			out = append(out, ip) // ppp/point-to-point defaults carry 0.0.0.0
		}
	}
	return out
}

// parseLocation extracts the LOCATION header value from one SSDP response
// datagram (case-insensitive header, per HTTP). Only http:// URLs are
// accepted — everything else (https device descriptions do not exist in
// UPnP; garbage) is ignored by the caller.
func parseLocation(resp []byte) (string, bool) {
	for _, line := range strings.Split(string(resp), "\r\n") {
		if len(line) >= 9 && strings.EqualFold(line[:9], "LOCATION:") {
			loc := strings.TrimSpace(line[9:])
			if strings.HasPrefix(loc, "http://") {
				return loc, true
			}
		}
	}
	return "", false
}

// Discover SSDP-searches the LAN and returns every gateway whose device
// description yields a usable WAN connection control URL (best first —
// order follows discovery). Callers iterate and keep the first that maps.
func Discover(ctx context.Context, log Logger) ([]*Gateway, error) {
	if log == nil {
		log = nopLogger{}
	}
	locs, err := ssdpSearch(ctx)
	if err != nil {
		return nil, err
	}
	var out []*Gateway
	for i, loc := range locs {
		if i >= maxDevices {
			break
		}
		gw, err := probeGateway(loc, log)
		if err != nil {
			continue // not an IGD (a smart TV answered SSDP too): skip
		}
		out = append(out, gw)
	}
	return out, nil
}

// probeGateway fetches the device description at loc and resolves the WAN
// connection control URL.
func probeGateway(loc string, log Logger) (*Gateway, error) {
	base, err := url.Parse(loc)
	if err != nil {
		return nil, fmt.Errorf("upnp: bad LOCATION %q: %w", loc, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpWait)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upnp: device description %q: HTTP %d", loc, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	control, service, err := findWANControl(data)
	if err != nil {
		return nil, err
	}
	cu, err := base.Parse(control)
	if err != nil || cu.Scheme != "http" {
		return nil, fmt.Errorf("upnp: bad control URL %q", control)
	}
	return &Gateway{base: base, control: cu, service: service, log: log}, nil
}

// ---------------------------------------------------------------------------
// Device description XML
// ---------------------------------------------------------------------------

type xmlService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type xmlDevice struct {
	ServiceList []xmlService `xml:"serviceList>service"`
	DeviceList  []xmlDevice  `xml:"deviceList>device"`
}

type xmlRoot struct {
	Device xmlDevice `xml:"device"`
}

// wanServiceOrder prefers WANIPConnection (v2 then v1) over WANPPP.
var wanServiceOrder = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// findWANControl walks the (nested) device tree for a WAN connection
// service and returns its control URL + URN.
func findWANControl(data []byte) (controlURL, service string, err error) {
	var root xmlRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return "", "", fmt.Errorf("upnp: device XML: %w", err)
	}
	var walk func(d xmlDevice, acc *[]xmlService)
	walk = func(d xmlDevice, acc *[]xmlService) {
		*acc = append(*acc, d.ServiceList...)
		for _, sub := range d.DeviceList {
			walk(sub, acc)
		}
	}
	var found []xmlService
	walk(root.Device, &found)
	byType := make(map[string]xmlService)
	for _, s := range found {
		if strings.TrimSpace(s.ControlURL) != "" {
			if _, dup := byType[s.ServiceType]; !dup {
				byType[s.ServiceType] = s
			}
		}
	}
	for _, want := range wanServiceOrder {
		if s, ok := byType[want]; ok {
			return s.ControlURL, s.ServiceType, nil
		}
	}
	return "", "", errors.New("upnp: device description has no WANIPConnection/WANPPPConnection service")
}

// ---------------------------------------------------------------------------
// SOAP control
// ---------------------------------------------------------------------------

// soapError is an UPnP fault (HTTP 500 with errorCode/errorDescription).
type soapError struct {
	Code int
	Desc string
}

func (e *soapError) Error() string {
	return fmt.Sprintf("upnp: soap error %d: %s", e.Code, e.Desc)
}

// soapCall posts action with args (rendered as <u:Action><k>v</k>...</u:Action>)
// and returns the response body.
func (g *Gateway) soapCall(ctx context.Context, action string, args map[string]string) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "<u:%s xmlns:u=\"%s\">", action, g.service)
	for _, k := range sortedKeys(args) {
		fmt.Fprintf(&b, "<%s>%s</%s>", k, xmlEscape(args[k]), k)
	}
	fmt.Fprintf(&b, "</u:%s>", action)
	body := fmt.Sprintf(soapEnv, b.String())
	cctx, cancel := context.WithTimeout(ctx, httpWait)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, g.control.String(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, g.service, action))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		if code, desc, ok := parseFault(data); ok {
			return nil, &soapError{Code: code, Desc: desc}
		}
		return nil, fmt.Errorf("upnp: %s: HTTP %d", action, resp.StatusCode)
	}
	return data, nil
}

// parseFault extracts errorCode/errorDescription from a SOAP fault body.
func parseFault(data []byte) (code int, desc string, ok bool) {
	var fault struct {
		Body struct {
			Fault struct {
				Detail struct {
					UPnPError struct {
						ErrorCode        int    `xml:"errorCode"`
						ErrorDescription string `xml:"errorDescription"`
					} `xml:"UPnPError"`
				} `xml:"detail"`
			} `xml:"Fault"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(data, &fault); err != nil {
		return 0, "", false
	}
	if fault.Body.Fault.Detail.UPnPError.ErrorCode == 0 {
		return 0, "", false
	}
	return fault.Body.Fault.Detail.UPnPError.ErrorCode, fault.Body.Fault.Detail.UPnPError.ErrorDescription, true
}

// textOf extracts the first element's text by LOCAL name (SOAP response
// namespaces vary by router firmware, so namespace-agnostic matching).
func textOf(data []byte, local string) (string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if t.Name.Local == local && depth <= 4 {
				var v string
				if err := dec.DecodeElement(&v, &t); err == nil && v != "" {
					return v, true
				}
			}
		case xml.EndElement:
			depth--
		}
	}
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := 1; i < len(ks); i++ { // deterministic arg order
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

// Mapping is one live router port mapping: the DHT's UDP port forwarded to
// this host, plus the external address peers can dial.
type Mapping struct {
	gw           *Gateway
	externalIP   net.IP
	externalPort int
	internalIP   net.IP
	internalPort int
	desc         string // mapping description, reused by EnsureFresh re-maps
}

// probeMapping asks GetSpecificPortMappingEntry whether externalPort is
// still mapped (714 NoSuchEntryInArray ⇒ the router forgot it — reboot,
// firmware reset, lease purge).
func (g *Gateway) probeMapping(ctx context.Context, externalPort int) error {
	_, err := g.soapCall(ctx, "GetSpecificPortMappingEntry", map[string]string{
		"NewRemotePort": strconv.Itoa(externalPort),
		"NewProtocol":   "UDP",
	})
	return err
}

// EnsureFresh re-validates the mapping and heals it after router events:
//
//   - mapping GONE (714 — router reboot/reset): re-map from scratch on the
//     same gateway and report the replacement (changed = true). If the
//     re-map fails, returns (nil, false, nil): the mapping is confirmed
//     lost but not recoverable right now — the caller keeps the old
//     advertised address and retries on the next tick rather than flapping
//     to observed-source on a transient refusal.
//   - mapping alive but the EXTERNAL IP changed (dynamic PPPoE etc.):
//     returns a copy carrying the new address (changed = true).
//   - probe error (router unreachable mid-reboot): (nil, false, err) —
//     transient, nothing concluded.
//
// A mapping whose port the router moves on re-map is reported changed
// regardless (Addr differs).
func (m *Mapping) EnsureFresh(ctx context.Context) (*Mapping, bool, error) {
	err := m.gw.probeMapping(ctx, m.externalPort)
	if err != nil {
		var se *soapError
		if errors.As(err, &se) && se.Code == 714 {
			nm, merr := m.gw.MapUDP(ctx, m.internalPort, m.desc)
			if merr != nil {
				return nil, false, nil // lost and unrecoverable for now
			}
			return nm, true, nil
		}
		return nil, false, err
	}
	// Alive: follow external-address changes without touching the mapping.
	ip, iperr := m.gw.externalIP(ctx)
	if iperr != nil || ip.Equal(m.externalIP) {
		return m, false, nil
	}
	cp := *m
	cp.externalIP = ip
	return &cp, true, nil
}

// Map asks the LAN's gateway(s) (Discover) for a UDP mapping of internalPort
// to this host. The first gateway that succeeds wins. Every failure mode —
// no IGD, CGNAT-fronted answer, mapping refused — returns an error the
// caller treats as "fall to the next ladder rung".
func Map(ctx context.Context, internalPort int, description string, log Logger) (*Mapping, error) {
	gws, err := Discover(ctx, log)
	if err != nil {
		return nil, err
	}
	if len(gws) == 0 {
		return nil, errors.New("upnp: no Internet Gateway Device on the LAN")
	}
	var lastErr error
	for _, gw := range gws {
		m, err := gw.MapUDP(ctx, internalPort, description)
		if err == nil {
			return m, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("upnp: mapping failed")
	}
	return nil, lastErr
}

// MapUDP creates the mapping on this gateway: AddAnyPortMapping first (the
// router picks the external port and returns it — never conflicts), the
// IGDv1 AddPortMapping exact-port fallback second (with a small random-port
// retry on 718 conflict, in case another device holds our preferred port).
func (g *Gateway) MapUDP(ctx context.Context, internalPort int, description string) (*Mapping, error) {
	internalIP, err := g.lanIP()
	if err != nil {
		return nil, err
	}
	if externalIP, err := g.externalIP(ctx); err == nil && !externalIP.IsUnspecified() {
		// v2 path: AddAnyPortMapping; fall through to v1 on any refusal.
		if resp, err := g.soapCall(ctx, "AddAnyPortMapping", map[string]string{
			"NewProtocol":               "UDP",
			"NewExternalPort":           strconv.Itoa(internalPort),
			"NewInternalPort":           strconv.Itoa(internalPort),
			"NewInternalClient":         internalIP.String(),
			"NewEnabled":                "1",
			"NewPortMappingDescription": description,
			"NewLeaseDuration":          "0",
		}); err == nil {
			port := internalPort
			if v, ok := textOf(resp, "NewReservedPort"); ok {
				if p, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					port = p
				}
			}
			return &Mapping{gw: g, externalIP: externalIP, externalPort: port, internalIP: internalIP, internalPort: internalPort}, nil
		}
	}
	// IGDv1 exact-port; 718 conflict ⇒ random retries.
	ports := []int{internalPort, internalPort + 1}
	for i := 0; i < 3; i++ {
		ports = append(ports, 20000+rand.Intn(40000))
	}
	var lastErr error
	for _, ext := range ports {
		_, err := g.soapCall(ctx, "AddPortMapping", map[string]string{
			"NewProtocol":               "UDP",
			"NewExternalPort":           strconv.Itoa(ext),
			"NewInternalPort":           strconv.Itoa(internalPort),
			"NewInternalClient":         internalIP.String(),
			"NewEnabled":                "1",
			"NewPortMappingDescription": description,
			"NewLeaseDuration":          "0",
		})
		if err == nil {
			ip, iperr := g.externalIP(ctx)
			if iperr != nil {
				return nil, iperr
			}
			return &Mapping{gw: g, externalIP: ip, externalPort: ext, internalIP: internalIP, internalPort: internalPort}, nil
		}
		lastErr = err
		var se *soapError
		if errors.As(err, &se) && se.Code != 718 {
			break // a refusal that is not "port taken": stop hammering
		}
	}
	if lastErr == nil {
		lastErr = errors.New("upnp: mapping refused")
	}
	return nil, lastErr
}

// externalIP asks GetExternalIPAddress; a 0.0.0.0/empty answer (CGNAT-front
// or bridge-mode firmware) fails the mapping as meaningless.
func (g *Gateway) externalIP(ctx context.Context) (net.IP, error) {
	resp, err := g.soapCall(ctx, "GetExternalIPAddress", nil)
	if err != nil {
		return nil, err
	}
	v, ok := textOf(resp, "NewExternalIPAddress")
	if !ok {
		return nil, errors.New("upnp: GetExternalIPAddress: no address in response")
	}
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return nil, fmt.Errorf("upnp: gateway reports unusable external address %q", v)
	}
	return ip, nil
}

// lanIP derives this host's IP toward the gateway (a connected throwaway
// UDP socket reveals the routed source without sending a packet).
func (g *Gateway) lanIP() (net.IP, error) {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(g.base.Hostname()), Port: 80})
	if err != nil {
		return nil, fmt.Errorf("upnp: no route to gateway: %w", err)
	}
	defer c.Close()
	if la, err := net.ResolveUDPAddr("udp4", c.LocalAddr().String()); err == nil && la.IP != nil && !la.IP.IsUnspecified() {
		return la.IP, nil
	}
	return nil, errors.New("upnp: could not determine the LAN IP toward the gateway")
}

// Addr returns the advertised dial address ("ip:port") — feeds the same
// §6.2 plumbing as -advertise/-stun/-turn-relay.
func (m *Mapping) Addr() string {
	return net.JoinHostPort(m.externalIP.String(), strconv.Itoa(m.externalPort))
}

// ExternalPort returns the router-side UDP port of the mapping (may differ
// from the internal port — AddAnyPortMapping lets the router pick).
func (m *Mapping) ExternalPort() int { return m.externalPort }

// Release deletes the mapping (best-effort; a router that forgot it, or a
// shutdown race, is not an error worth failing on — the log tells the tale).
func (m *Mapping) Release() error {
	_, err := m.gw.soapCall(context.Background(), "DeletePortMapping", map[string]string{
		"NewProtocol":     "UDP",
		"NewExternalPort": strconv.Itoa(m.externalPort),
	})
	return err
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Debug(string, ...any) {}
