// doh.go — `freens doh` (v0.14.0, spec §9.6): DNS-over-HTTPS enable/disable
// in one command, for both directions.
//
//	freens doh                        status: upstream mode + serve flag
//	freens doh upstream <preset|URL|off>
//	                                  encrypted upstream (presets: quad9,
//	                                  cloudflare, google); off reverts to
//	                                  plain DNS. Applied live via the admin
//	                                  /reload hot-swap when a daemon runs.
//	freens doh serve <on|off>         expose /dns-query on the webui's HTTPS
//	                                  listener (LAN-only by its CIDR gate).
//	freens doh test [name]            resolve <name> through the daemon's
//	                                  resolver via the admin wire-DNS relay
//	                                  (default name: example.com).
//
// Both setters edit <home>/freens.conf through internal/confedit — comment-
// preserving line surgery, one .pre-doh undo step — never a regenerated
// file. CLI edits apply to the standard config path, the same one setup
// writes and doctor reads (health.go's effectiveDNSAddr precedent).
package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/camalolo/freens/internal/admin"
	"github.com/camalolo/freens/internal/confedit"
	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/resolver"
	"github.com/miekg/dns"
)

func cmdDoh(args []string) error {
	if len(args) == 0 {
		return dohStatus()
	}
	switch args[0] {
	case "upstream":
		if len(args) != 2 {
			return usageErr("usage: freens doh upstream <quad9|cloudflare|google|https://…|off>")
		}
		return dohSetUpstream(args[1])
	case "serve":
		if len(args) != 2 || (args[1] != "on" && args[1] != "off") {
			return usageErr("usage: freens doh serve <on|off>")
		}
		return dohSetServe(args[1] == "on")
	case "test":
		name := "example.com"
		if len(args) > 2 {
			return usageErr("usage: freens doh test [name]")
		}
		if len(args) == 2 {
			name = args[1]
		}
		return dohTest(name)
	case "-h", "--help", "help":
		fmt.Println(usageDoh)
		return nil
	default:
		return usageErr("unknown doh subcommand %q (want: upstream, serve, test)", args[0])
	}
}

const usageDoh = `freens doh                        show upstream + serve state
freens doh upstream <preset|URL|off>   encrypted upstream (quad9, cloudflare, google, or a https://…/dns-query URL)
freens doh serve <on|off>         serve DoH on the webui HTTPS listener
freens doh test [name]            resolve a name through the daemon relay`

// dohStatus prints the two switches and — when a daemon runs — what it is
// ACTUALLY forwarding with right now (the config is the intent; the daemon
// is the truth).
func dohStatus() error {
	conf := home.ConfPath()
	upURL, hasUp, err := confedit.Get(conf, "upstream", "doh")
	if err != nil {
		return err
	}
	servers, _, err := confedit.Get(conf, "upstream", "servers")
	if err != nil {
		return err
	}
	serve, hasServe, err := confedit.Get(conf, "doh", "serve")
	if err != nil {
		return err
	}

	if hasUp {
		fmt.Printf("upstream: DoH %s (fallback: %s)\n", upURL, fallbackText(servers))
	} else {
		fmt.Printf("upstream: plain DNS (%s)\n", fallbackText(servers))
	}
	if parseServe(serve, hasServe) {
		fmt.Println("serve:    on — https://<this-box>:8090/dns-query (webui listener, LAN-gated)")
	} else {
		fmt.Println("serve:    off (enable with: freens doh serve on)")
	}

	if c := maybeAdmin(); c != nil {
		ctx, cancel := adminCtx()
		defer cancel()
		if _, err := c.Reload(ctx); err == nil {
			fmt.Println("daemon:   running (reload endpoint available)")
		} else {
			fmt.Printf("daemon:   running (older daemon — upstream changes need a restart: %v)\n", err)
		}
	} else {
		fmt.Println("daemon:   not running (settings take effect at next start)")
	}
	return nil
}

// fallbackText renders the plaintext fallback list for display. An empty
// conf list means the daemon runs on DefaultUpstreamServers (the same fill
// applyUpstreamDefault gives the real forwarder), so say THAT — "none
// configured" would be a lie about the running daemon.
func fallbackText(servers string) string {
	if strings.TrimSpace(servers) == "" {
		return strings.Join(resolver.DefaultUpstreamServers, ", ") + " (default)"
	}
	return servers
}

// dohSetUpstream resolves the argument (preset name, URL, or off) and writes
// the [upstream] doh key, then hot-applies via POST admin /reload.
func dohSetUpstream(arg string) error {
	arg = strings.TrimSpace(arg)
	conf := home.ConfPath()
	if strings.EqualFold(arg, "off") || arg == "" {
		if err := confedit.Set(conf, "upstream", "doh", ""); err != nil {
			return err
		}
		fmt.Println("upstream: plain DNS (doh line removed)")
		return reloadOrHint()
	}
	url, ok := resolver.DoHPresetURL(arg)
	if !ok {
		return usageErr("not a DoH endpoint: %q (want a preset name, an https://… URL, or \"off\")", arg)
	}
	if err := confedit.Set(conf, "upstream", "doh", url); err != nil {
		return err
	}
	fmt.Printf("upstream: DoH %s (fallback servers stay configured)\n", url)
	return reloadOrHint()
}

// dohSetServe writes the [doh] serve key. The WEBUI owns the listener, so
// the note differs from the upstream case: a running freens-web picks the
// new state up from the config within seconds; a stopped one at its next
// start.
func dohSetServe(on bool) error {
	val := "false"
	if on {
		val = "true"
	}
	if err := confedit.Set(home.ConfPath(), "doh", "serve", val); err != nil {
		return err
	}
	if on {
		fmt.Println("serve: on — the webui answers /dns-query (LAN CIDR gate applies)")
		fmt.Println("         clients need this box's root CA: freens doh test, or the webui Settings page")
	} else {
		fmt.Println("serve: off")
	}
	return nil
}

// dohTest resolves one A query through the daemon's resolver via the admin
// wire-DNS relay — the exact path a DoH client's query takes after the
// webui hands it over (everything except the HTTPS hop, which the webui's
// own Test button exercises).
func dohTest(name string) error {
	c := maybeAdmin()
	if c == nil {
		return fmt.Errorf("no running freens daemon (start one, or use the webui's Test button for the full HTTPS path)")
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	q.RecursionDesired = true
	payload, err := q.Pack()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), adminTimeout)
	defer cancel()
	respRaw, err := c.DNSQuery(ctx, payload)
	if err != nil {
		return fmt.Errorf("relay query failed: %w", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(respRaw); err != nil {
		return fmt.Errorf("bad relay response: %w", err)
	}
	switch {
	case resp.Rcode != dns.RcodeSuccess:
		return fmt.Errorf("%s → %s", name, dns.RcodeToString[resp.Rcode])
	case len(resp.Answer) == 0:
		fmt.Printf("%s → NOERROR (no answers)\n", name)
	default:
		for _, rr := range resp.Answer {
			fmt.Printf("%s → %s\n", name, strings.TrimSpace(rr.String()))
		}
	}
	if len(resp.Answer) > 0 {
		// Hex echo of the first A rdata keeps the output copy-pasteable for
		// cross-box comparisons during fleet tests.
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				fmt.Printf("(A rdata hex: %s)\n", hex.EncodeToString(a.A))
				break
			}
		}
	}
	return nil
}

// reloadOrHint hot-applies an upstream change through a running daemon, or
// explains the fallback. Best-effort by design: the config is already
// saved, so a missing/old daemon only changes WHEN it applies.
func reloadOrHint() error {
	c := maybeAdmin()
	if c == nil {
		fmt.Println("daemon not running — takes effect when it starts")
		return nil
	}
	ctx, cancel := adminCtx()
	defer cancel()
	msg, err := c.Reload(ctx)
	if err != nil {
		fmt.Printf("config saved; this daemon cannot hot-reload (%v) — restart it to apply\n", err)
		return nil
	}
	fmt.Printf("applied live: %s\n", msg)
	return nil
}

// parseServe normalizes the [doh] serve value (absent ⇒ off).
func parseServe(v string, present bool) bool {
	if !present {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

// doctorWarn prints doctor's ✱ warn line (package-level so the DoH checks
// share it without threading closures around).
func doctorWarn(format string, args ...any) {
	fmt.Printf("✱ %s\n", fmt.Sprintf(format, args...))
}

// doctorDoH is doctor's §9.6 block (warn-only, like certmgr's): when DoH is
// in use, prove the configured pieces still answer. Silent when the box
// doesn't use DoH at all — doctor's job is the operator's actual setup.
func doctorDoH(c *admin.Client) {
	conf := home.ConfPath()
	upURL, hasUp, err := confedit.Get(conf, "upstream", "doh")
	if err != nil {
		doctorWarn("doh: config unreadable (%v)", err)
		return
	}
	serve, hasServe, err := confedit.Get(conf, "doh", "serve")
	if err != nil {
		doctorWarn("doh: config unreadable (%v)", err)
		return
	}
	if !hasUp && !parseServe(serve, hasServe) {
		return // DoH unused on this box; nothing to check
	}

	if hasUp {
		ok := dohUpstreamAnswers(upURL, conf)
		if ok {
			fmt.Printf("✔ DoH upstream answers (%s)\n", upURL)
		} else {
			doctorWarn("DoH upstream %s did not answer — queries fall back to plain DNS until it recovers", upURL)
		}
	}
	if parseServe(serve, hasServe) {
		if c == nil {
			doctorWarn("DoH serve is on but the daemon is down — the webui relay will answer SERVFAIL")
			return
		}
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		q.RecursionDesired = true
		payload, perr := q.Pack()
		if perr != nil {
			return
		}
		ctx, cancel := adminCtx()
		defer cancel()
		raw, qerr := c.DNSQuery(ctx, payload)
		resp := new(dns.Msg)
		switch {
		case qerr != nil:
			doctorWarn("DoH relay check failed (admin /dns-query): %v", qerr)
		case resp.Unpack(raw) != nil || resp.Rcode != dns.RcodeSuccess:
			doctorWarn("DoH relay answered but the resolver path is unhealthy")
		default:
			fmt.Println("✔ DoH relay (daemon side) answers — the HTTPS leg is the webui Test button")
		}
	}
}

// dohUpstreamAnswers fires one real A query at the configured DoH endpoint
// (with the plaintext fallback servers as its bootstrap — the same shape
// the daemon's own forwarder uses).
func dohUpstreamAnswers(url, conf string) bool {
	servers, _, _ := confedit.Get(conf, "upstream", "servers")
	plainServers := resolver.DefaultUpstreamServers
	if strings.TrimSpace(servers) != "" {
		plainServers = strings.Fields(strings.ReplaceAll(servers, ",", " "))
	}
	plain := &resolver.DNSUpstream{Servers: plainServers}
	u := &resolver.DoHUpstream{URL: url, Fallback: plain}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.RecursionDesired = true
	resp, err := u.Forward(context.Background(), q)
	return err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess
}
