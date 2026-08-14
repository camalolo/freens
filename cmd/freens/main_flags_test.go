package main

// main_flags_test.go — flag-definition tests for the TURN flags (and the
// defineFlags extraction that made the definitions testable without a full
// daemon spin-up): names registered, defaults off, values parsed, and the
// help text carrying the precedence/fallback and defaults documentation the
// usage header promises.

import (
	"flag"
	"strings"
	"testing"
)

// TestTurnFlagsParse: -turn / -turn-relay values come back as parsed.
func TestTurnFlagsParse(t *testing.T) {
	fs := flag.NewFlagSet("freens", flag.ContinueOnError)
	f := defineFlags(fs)
	if err := fs.Parse([]string{
		"-dht", "127.0.0.1:15353",
		"-turn", "127.0.0.1:3478",
		"-turn-relay", "10.0.0.9:3478",
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *f.turnAddr != "127.0.0.1:3478" {
		t.Errorf("-turn = %q, want 127.0.0.1:3478", *f.turnAddr)
	}
	if *f.turnRelayAddr != "10.0.0.9:3478" {
		t.Errorf("-turn-relay = %q, want 10.0.0.9:3478", *f.turnRelayAddr)
	}
}

// TestTurnFlagsDefaultOff: both TURN flags must default to "" (off) so an
// untouched invocation behaves exactly as before the flags existed.
func TestTurnFlagsDefaultOff(t *testing.T) {
	fs := flag.NewFlagSet("freens", flag.ContinueOnError)
	f := defineFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *f.turnAddr != "" || *f.turnRelayAddr != "" {
		t.Fatalf("TURN flags must default off, got -turn=%q -turn-relay=%q",
			*f.turnAddr, *f.turnRelayAddr)
	}
}

// TestTurnFlagHelpText: the help strings carry the operator-facing contract
// — -turn documents the server knobs left to internal/turn defaults and the
// STUN-Binding doubling; -turn-relay documents precedence and fallback; the
// stale pre-TURN wording is gone from -stun.
func TestTurnFlagHelpText(t *testing.T) {
	fs := flag.NewFlagSet("freens", flag.ContinueOnError)
	defineFlags(fs)
	for name, want := range map[string][]string{
		"turn": {
			"requires -dht",
			"MaxAllocsPerIP", // knobs documented...
			"MaxPermissions", // ...and left to internal/turn defaults
			"STUN Binding",   // doubles as a -stun target
			"community",      // relay tier framing
		},
		"turn-relay": {
			"requires -dht",
			"Precedence: -advertise > -turn-relay > -stun",
			"falls back", // graceful degradation on allocation failure
			"RELAYED",
		},
	} {
		fl := fs.Lookup(name)
		if fl == nil {
			t.Errorf("flag -%s not registered", name)
			continue
		}
		for _, phrase := range want {
			if !strings.Contains(fl.Usage, phrase) {
				t.Errorf("-%s help missing %q:\n%s", name, phrase, fl.Usage)
			}
		}
	}
	stun := fs.Lookup("stun")
	if stun == nil {
		t.Fatal("flag -stun not registered")
	}
	if strings.Contains(stun.Usage, "ships no TURN") {
		t.Errorf("-stun help still claims freens ships no TURN relay:\n%s", stun.Usage)
	}
}

// TestUPnPFlagDefaults: -upnp is ON by default (the "when convenient"
// contract — silently skipped whenever a better rung or no -dht), and its
// help text states the skip conditions.
func TestUPnPFlagDefaults(t *testing.T) {
	fs := flag.NewFlagSet("freens", flag.ContinueOnError)
	f := defineFlags(fs)
	if !*f.upnpEnabled {
		t.Fatal("-upnp should default to true")
	}
	if err := fs.Parse([]string{"-upnp=false"}); err != nil {
		t.Fatal(err)
	}
	if *f.upnpEnabled {
		t.Fatal("-upnp=false did not stick")
	}
}
