//go:build windows

package cli

// firewall_windows.go — the firewall-convergence half of `upgrade-migrate`.
// `setup` creates the full rule set, but a box that only ever runs
// `freens upgrade` never re-runs setup — so rules the CURRENT binary needs
// (added after the box was first set up) must be ensured at upgrade time.
// The upgrade verb runs this THROUGH THE NEW binary (that is what
// upgrade-migrate is), elevated like the rest of the migrate step, and
// scoped to os.Executable() — the same path the service runs from (the
// same-path swap), so no new firewall prompt for the program itself.

import (
	"fmt"
	"os"
)

// ensureFirewallRulesOnMigrate converges the firewall rule set: the DHT
// blob channel's inbound TCP rule (v0.19.9) is new relative to every
// pre-0.19.9 install. Delete-then-add keeps it idempotent exactly like
// windowsFirewallRule. Best-effort by design: a refusal (policy, AV)
// costs only the TCP serving path — the verb must never fail an upgrade
// over a cosmetic rule.
func ensureFirewallRulesOnMigrate() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	_ = windowsRelay("netsh", "advfirewall", "firewall", "delete", "rule", "name="+windowsFirewallTCPRuleName)
	if err := windowsRelay("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+windowsFirewallTCPRuleName,
		"dir=in", "action=allow",
		"program="+exe,
		"protocol=tcp", "localport=15353",
		"profile=any"); err != nil {
		return err
	}
	fmt.Println("firewall: inbound TCP 15353 allowed for the daemon (DHT blob channel)")
	return nil
}
