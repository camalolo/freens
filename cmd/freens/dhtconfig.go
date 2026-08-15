package main

// dhtconfig.go — the daemon's [dht] config-file section. The -config file
// is the daemon's single configuration surface (resolver sections parsed by
// resolver.ParseConfig); this adds the DHT/network side so a systemd unit
// can carry ONE file instead of a flag wall. Precedence per setting:
// explicitly-passed flag > config value > built-in default — the same rule
// -listen/-upstream already follow.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// dhtConfig is every [dht] key the daemon understands. Zero values mean
// "not configured". Field names mirror the flags.
type dhtConfig struct {
	Listen    string // -dht
	NodeSeed  string // -node-seed (hex or @keyfile)
	Peers     string // -peers (comma list)
	PeersFile string // -peers-file
	Advertise string // -advertise
	Stun      string // -stun
	Turn      string // -turn
	TurnRelay string // -turn-relay
	Persist   string // -persist
	Passive   bool   // -passive
	UPnPOff   bool   // [dht] upnp = false (only the off switch is useful in a file)
}

// parseDHTConfig extracts the [dht] section of an INI-style config (same
// conventions as resolver.ParseConfig: full-line ;/# comments, key =
// value). Sections other than [dht] are ignored by this parser (the
// resolver owns them).
func parseDHTConfig(text string) (*dhtConfig, error) {
	cfg := &dhtConfig{}
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 4096), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				return nil, fmt.Errorf("[dht] config: unterminated section header %q", line)
			}
			section = strings.TrimSpace(line[1:end])
			continue
		}
		if section != "dht" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("[dht] config: want key = value, got %q", line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		switch key {
		case "listen":
			cfg.Listen = val
		case "node-seed":
			cfg.NodeSeed = val
		case "peers":
			cfg.Peers = val
		case "peers-file":
			cfg.PeersFile = val
		case "advertise":
			cfg.Advertise = val
		case "stun":
			cfg.Stun = val
		case "turn":
			cfg.Turn = val
		case "turn-relay":
			cfg.TurnRelay = val
		case "persist":
			cfg.Persist = val
		case "passive":
			if val != "true" && val != "false" {
				return nil, fmt.Errorf("[dht] config: passive = %q (want true|false)", val)
			}
			cfg.Passive = val == "true"
		case "upnp":
			if val == "false" {
				cfg.UPnPOff = true
			} else if val != "true" {
				return nil, fmt.Errorf("[dht] config: upnp = %q (want true|false)", val)
			}
		default:
			return nil, fmt.Errorf("[dht] config: unknown key %q", key)
		}
	}
	return cfg, sc.Err()
}

// loadDHTConfig reads the [dht] section from path ("" ⇒ empty config; a
// missing file is an error — the operator named it explicitly).
func loadDHTConfig(path string) (*dhtConfig, error) {
	if path == "" {
		return &dhtConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseDHTConfig(string(data))
}

// pickString resolves flag-vs-config precedence: an explicitly-set flag
// wins; otherwise the config value; otherwise the default.
func pickString(flagSet bool, flagVal, cfgVal, def string) string {
	switch {
	case flagSet:
		return flagVal
	case cfgVal != "":
		return cfgVal
	default:
		return def
	}
}

// pickBool is pickString for booleans (config participates only via its
// true-valued keys, so the tri-state stays simple: flag > config > default).
func pickBool(flagSet, flagVal, cfgVal, def bool) bool {
	if flagSet {
		return flagVal
	}
	if cfgVal {
		return true
	}
	return def
}
