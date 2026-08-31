package main

// tlsconfig.go — the daemon's [tls] config-file section (spec §9.5.4):
//
//	[tls]
//	trust-sync = true   ; cross-certify verified owner CAs into the local
//	                    ; trust stores (default true; false disables the
//	                    ; resolver hook entirely)
//
// Same INI conventions as the [dht] parser.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type tlsConfig struct {
	TrustSyncOff bool // [tls] trust-sync = false
}

func parseTLSConfig(text string) (*tlsConfig, error) {
	cfg := &tlsConfig{}
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
				return nil, fmt.Errorf("[tls] config: unterminated section header %q", line)
			}
			section = strings.TrimSpace(line[1:end])
			continue
		}
		if section != "tls" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("[tls] config: want key = value, got %q", line)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		switch key {
		case "trust-sync":
			if val != "true" && val != "false" {
				return nil, fmt.Errorf("[tls] config: trust-sync = %q (want true|false)", val)
			}
			cfg.TrustSyncOff = val == "false"
		default:
			return nil, fmt.Errorf("[tls] config: unknown key %q", key)
		}
	}
	return cfg, sc.Err()
}

// loadTLSConfig reads the [tls] section from path; absent file ⇒ defaults.
func loadTLSConfig(path string) (*tlsConfig, error) {
	if path == "" {
		return &tlsConfig{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &tlsConfig{}, nil
		}
		return nil, err
	}
	return parseTLSConfig(string(b))
}
