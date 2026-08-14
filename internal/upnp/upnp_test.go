package upnp

// upnp_test.go pins the IGD subset against an in-process fake gateway: the
// device-description walk (nested deviceList, service preference), the SOAP
// control paths (AddAnyPortMapping success with a moved reserved port, the
// IGDv1 fallback, 718-conflict retries, the CGNAT 0.0.0.0 refusal), fault
// parsing, Release, and SSDP via the injectable search hook. Malformed
// inputs must error, never panic.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeIGD serves a realistic IGD: /rootDesc.xml with the connection service
// nested two deviceLists deep, and /ctl as the SOAP endpoint dispatching on
// the SOAPACTION header. Behavior knobs select which protocol flavor and
// failures to emulate.
type fakeIGD struct {
	srv       *httptest.Server
	mu        sync.Mutex
	calls     []string     // SOAP actions seen, in order
	v2        bool         // support AddAnyPortMapping
	conflict  int          // emit 718 on the first N AddPortMapping calls
	extIP     string       // GetExternalIPAddress answer
	mappedExt int          // port AddAnyPortMapping reserves
	mapped    map[int]bool // live entries (external ports)
	refuseAdd bool         // fail all Add* (simulates a locked-down router)
}

func newFakeIGD(t *testing.T) *fakeIGD {
	t.Helper()
	f := &fakeIGD{v2: true, extIP: "203.0.113.7", mappedExt: 0, mapped: make(map[int]bool)}
	mux := http.NewServeMux()
	mux.HandleFunc("/rootDesc.xml", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <deviceList>
   <device>
    <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
    <deviceList>
     <device>
      <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
      <serviceList>
       <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl</controlURL>
       </service>
      </serviceList>
     </device>
    </deviceList>
   </device>
  </deviceList>
 </device>
</root>`)
	})
	mux.HandleFunc("/ctl", func(w http.ResponseWriter, r *http.Request) {
		action := strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("SOAPACTION"), `"urn:schemas-upnp-org:service:WANIPConnection:1#`), `"`)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		arg := func(name string) string {
			m := regexp.MustCompile("<" + name + ">([0-9]+)</" + name + ">").FindSubmatch(body)
			if m == nil {
				return ""
			}
			return string(m[1])
		}
		f.mu.Lock()
		f.calls = append(f.calls, action)
		v2, conflict, extIP, mappedExt := f.v2, f.conflict, f.extIP, f.mappedExt
		refuse := f.refuseAdd
		f.mu.Unlock()
		switch action {
		case "GetExternalIPAddress":
			fmt.Fprintf(w, `<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>%s</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`, extIP)
		case "AddAnyPortMapping":
			if !v2 || refuse {
				soapFault(w, 401, "InvalidAction")
				return
			}
			if mappedExt == 0 {
				mappedExt = 15353
			}
			f.mu.Lock()
			f.mapped[mappedExt] = true
			f.mu.Unlock()
			fmt.Fprintf(w, `<s:Envelope><s:Body><u:AddAnyPortMappingResponse><NewReservedPort>%d</NewReservedPort></u:AddAnyPortMappingResponse></s:Body></s:Envelope>`, mappedExt)
		case "AddPortMapping":
			if refuse {
				soapFault(w, 401, "InvalidAction")
				return
			}
			if conflict > 0 {
				f.mu.Lock()
				f.conflict--
				f.mu.Unlock()
				soapFault(w, 718, "ConflictInMappingEntry")
				return
			}
			f.mu.Lock()
			if p := arg("NewExternalPort"); p != "" {
				if n, err := strconv.Atoi(p); err == nil {
					f.mapped[n] = true
				}
			}
			f.mu.Unlock()
			fmt.Fprint(w, `<s:Envelope><s:Body><u:AddPortMappingResponse></u:AddPortMappingResponse></s:Body></s:Envelope>`)
		case "GetSpecificPortMappingEntry":
			p, _ := strconv.Atoi(arg("NewRemotePort"))
			f.mu.Lock()
			_, alive := f.mapped[p]
			f.mu.Unlock()
			if !alive {
				soapFault(w, 714, "NoSuchEntryInArray")
				return
			}
			fmt.Fprint(w, `<s:Envelope><s:Body><u:GetSpecificPortMappingEntryResponse><NewInternalPort>15353</NewInternalPort><NewInternalClient>127.0.0.1</NewInternalClient><NewEnabled>1</NewEnabled></u:GetSpecificPortMappingEntryResponse></s:Body></s:Envelope>`)
		case "DeletePortMapping":
			p, _ := strconv.Atoi(arg("NewExternalPort"))
			f.mu.Lock()
			delete(f.mapped, p)
			f.mu.Unlock()
			fmt.Fprint(w, `<s:Envelope><s:Body><u:DeletePortMappingResponse></u:DeletePortMappingResponse></s:Body></s:Envelope>`)
		default:
			soapFault(w, 401, "InvalidAction")
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func soapFault(w http.ResponseWriter, code int, desc string) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>%d</errorCode><errorDescription>%s</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`, code, desc)
}

// gwFor returns a Gateway pointed at the fake's root description.
func gwFor(t *testing.T, f *fakeIGD) *Gateway {
	t.Helper()
	gw, err := probeGateway(f.srv.URL+"/rootDesc.xml", nil)
	if err != nil {
		t.Fatalf("probeGateway: %v", err)
	}
	if gw.service != "urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Fatalf("service = %s", gw.service)
	}
	if !strings.HasSuffix(gw.control.String(), "/ctl") {
		t.Fatalf("control URL = %s", gw.control)
	}
	return gw
}

func TestMapAnyPort(t *testing.T) {
	f := newFakeIGD(t)
	f.mappedExt = 53535 // the router moved us
	gw := gwFor(t, f)
	m, err := gw.MapUDP(context.Background(), 15353, "freens")
	if err != nil {
		t.Fatalf("MapUDP: %v", err)
	}
	if m.Addr() != "203.0.113.7:53535" {
		t.Fatalf("Addr = %s, want 203.0.113.7:53535", m.Addr())
	}
	if m.externalPort != 53535 || m.internalPort != 15353 {
		t.Fatalf("ports ext=%d int=%d", m.externalPort, m.internalPort)
	}
	if !m.internalIP.IsLoopback() && m.internalIP == nil {
		t.Fatal("no internal IP derived")
	}
	if err := m.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	want := []string{"GetExternalIPAddress", "AddAnyPortMapping", "DeletePortMapping"}
	if len(f.calls) != len(want) {
		t.Fatalf("calls = %v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("call %d = %s, want %s (all: %v)", i, f.calls[i], want[i], f.calls)
		}
	}
}

func TestMapIGDv1Fallback(t *testing.T) {
	f := newFakeIGD(t)
	f.v2 = false // router rejects AddAnyPortMapping: IGDv1 only
	gw := gwFor(t, f)
	m, err := gw.MapUDP(context.Background(), 15353, "freens")
	if err != nil {
		t.Fatalf("MapUDP v1 fallback: %v", err)
	}
	if m.Addr() != "203.0.113.7:15353" {
		t.Fatalf("Addr = %s", m.Addr())
	}
}

func TestMapConflictRetries(t *testing.T) {
	f := newFakeIGD(t)
	f.v2 = false
	f.conflict = 2 // first two exact/random picks are taken
	gw := gwFor(t, f)
	m, err := gw.MapUDP(context.Background(), 15353, "freens")
	if err != nil {
		t.Fatalf("MapUDP with conflicts: %v", err)
	}
	if m.externalPort == 15353 || m.externalPort == 15354 {
		t.Fatalf("expected a retry port, got %d", m.externalPort)
	}
}

func TestMapCGNATRefused(t *testing.T) {
	f := newFakeIGD(t)
	f.extIP = "0.0.0.0" // CGNAT-front / bridge-mode firmware
	gw := gwFor(t, f)
	if _, err := gw.MapUDP(context.Background(), 15353, "freens"); err == nil {
		t.Fatal("mapping succeeded against a 0.0.0.0 external address")
	}
}

func TestDiscoverViaHook(t *testing.T) {
	f := newFakeIGD(t)
	f.mappedExt = 53535
	restore := ssdpSearch
	ssdpSearch = func(context.Context) ([]string, error) {
		return []string{f.srv.URL + "/rootDesc.xml"}, nil
	}
	t.Cleanup(func() { ssdpSearch = restore })
	m, err := Map(context.Background(), 15353, "freens", nil)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if m.Addr() != "203.0.113.7:53535" {
		t.Fatalf("Addr = %s", m.Addr())
	}
	// Discover with no IGD answering errors out (the ladder's next rung).
	ssdpSearch = func(context.Context) ([]string, error) { return nil, nil }
	if _, err := Map(context.Background(), 15353, "freens", nil); err == nil {
		t.Fatal("Map succeeded with no gateway")
	}
}

func TestFindWANControlMalformed(t *testing.T) {
	for name, data := range map[string]string{
		"empty":       ``,
		"not xml":     `nope`,
		"no services": `<?xml version="1.0"?><root><device/></root>`,
		"truncated":   `<?xml version="1.0"?><root><device><deviceList>`,
	} {
		if _, _, err := findWANControl([]byte(data)); err == nil {
			t.Fatalf("%s: findWANControl accepted malformed input", name)
		}
	}
}

func TestParseFaultAndTextOf(t *testing.T) {
	code, desc, ok := parseFault([]byte(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
	if !ok || code != 718 || desc != "ConflictInMappingEntry" {
		t.Fatalf("parseFault = %d %q %v", code, desc, ok)
	}
	if _, _, ok := parseFault([]byte(`<ok/>`)); ok {
		t.Fatal("parseFault accepted a non-fault body")
	}
	if v, ok := textOf([]byte(`<x:Envelope xmlns:x="u"><x:Body><m:Resp><NewReservedPort>7777</NewReservedPort></m:Resp></x:Body></x:Envelope>`), "NewReservedPort"); !ok || v != "7777" {
		t.Fatalf("textOf = %q %v", v, ok)
	}
	if _, ok := textOf([]byte(`<a/>`), "NewExternalIPAddress"); ok {
		t.Fatal("textOf found a missing element")
	}
}

func TestSortedKeysAndEscape(t *testing.T) {
	ks := sortedKeys(map[string]string{"b": "1", "a": "2", "c": "3"})
	if strings.Join(ks, "") != "abc" {
		t.Fatalf("sortedKeys = %v", ks)
	}
	if got := xmlEscape(`a<b>&"c"`); got != `a&lt;b&gt;&amp;&#34;c&#34;` {
		t.Fatalf("xmlEscape = %s", got)
	}
}

// reboot simulates the router restarting: every mapping is forgotten, the
// external address optionally changes (dynamic PPPoE), and the reserved
// port drifts (AddAnyPortMapping hands out a different one).
func (f *fakeIGD) reboot(newExtIP string, newReserved int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mapped = make(map[int]bool)
	if newExtIP != "" {
		f.extIP = newExtIP
	}
	f.mappedExt = newReserved
}

func (f *fakeIGD) setExtIP(ip string) {
	f.mu.Lock()
	f.extIP = ip
	f.mu.Unlock()
}

func TestEnsureFreshAliveUnchanged(t *testing.T) {
	f := newFakeIGD(t)
	f.mappedExt = 53535
	m, err := gwFor(t, f).MapUDP(context.Background(), 15353, "freens")
	if err != nil {
		t.Fatal(err)
	}
	nm, changed, err := m.EnsureFresh(context.Background())
	if err != nil || changed || nm == nil || nm.Addr() != m.Addr() {
		t.Fatalf("EnsureFresh on a healthy mapping: nm=%v changed=%v err=%v", nm, changed, err)
	}
}

func TestEnsureFreshFollowsIPChange(t *testing.T) {
	f := newFakeIGD(t)
	f.mappedExt = 53535
	m, _ := gwFor(t, f).MapUDP(context.Background(), 15353, "freens")
	f.setExtIP("198.51.100.9")
	nm, changed, err := m.EnsureFresh(context.Background())
	if err != nil || !changed || nm == nil {
		t.Fatalf("EnsureFresh missed an external IP change: %v %v %v", nm, changed, err)
	}
	if nm.Addr() != "198.51.100.9:53535" {
		t.Fatalf("Addr after IP change = %s", nm.Addr())
	}
}

func TestEnsureFreshRemapsAfterReboot(t *testing.T) {
	f := newFakeIGD(t)
	f.mappedExt = 53535
	m, _ := gwFor(t, f).MapUDP(context.Background(), 15353, "freens")
	// Router reboots: mappings forgotten, new external IP, new reserved port.
	f.reboot("198.51.100.99", 61000)
	nm, changed, err := m.EnsureFresh(context.Background())
	if err != nil || !changed || nm == nil {
		t.Fatalf("EnsureFresh did not heal a reboot: %v %v %v", nm, changed, err)
	}
	if nm.Addr() != "198.51.100.99:61000" {
		t.Fatalf("Addr after reboot-heal = %s, want 198.51.100.99:61000", nm.Addr())
	}
	// And the replacement is itself healthy.
	if _, changed, err := nm.EnsureFresh(context.Background()); err != nil || changed {
		t.Fatalf("re-made mapping not stable: %v %v", changed, err)
	}
}

func TestEnsureFreshLostAndUnrecoverable(t *testing.T) {
	f := newFakeIGD(t)
	f.mappedExt = 53535
	m, _ := gwFor(t, f).MapUDP(context.Background(), 15353, "freens")
	f.reboot("", 0)
	f.mu.Lock()
	f.refuseAdd = true // the locked-down rebooted router refuses re-mapping
	f.mu.Unlock()
	nm, changed, err := m.EnsureFresh(context.Background())
	if err != nil || changed || nm != nil {
		t.Fatalf("EnsureFresh on lost+refused mapping: nm=%v changed=%v err=%v (want nil,false,nil)", nm, changed, err)
	}
}
