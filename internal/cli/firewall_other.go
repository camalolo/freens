//go:build !windows

package cli

// firewall_other.go — the non-Windows stub: firewall rules are a Windows
// setup concern (Linux ships iptables/nft guidance in setup's output and
// the DHT port needs no program-scoped rules).

func ensureFirewallRulesOnMigrate() error { return nil }
