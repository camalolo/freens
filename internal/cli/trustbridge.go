package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/camalolo/freens/internal/home"
)

// trustbridge.go — the §9.5.4 privileged bridge: a systemd PATH unit that
// watches the daemon's cross-cert spool (<home>/tls/spool) and, on any
// change, RE-SYNCS the system CA bundle from it: remove every
// freens-cross-*.crt from /usr/local/share/ca-certificates, then copy
// whatever the spool holds now (so rotation and purge both converge on the
// next trigger). The daemon itself is unprivileged; this unit is the ONLY
// privileged piece, installed once by setup, and it can ONLY install
// certificates the local daemon minted after verifying them through the
// §9.5.4 screened path. A purged alias's system entry also disappears on
// the next trigger (any other namespace's install/refresh); its cross-cert
// is lifetime-capped by the record expiry (§9.5.4) either way.

const trustBridgePathUnit = `[Unit]
Description=freens TLS trust bridge (§9.5 cross-cert spool watcher)
Documentation=https://github.com/camalolo/freens

[Path]
PathExistsGlob=%SPoolDir%/freens-cross-*.crt
PathModified=%SPoolDir%/freens-cross-*.crt
Unit=freens-trust.service
TriggerLimitIntervalSec=10s
TriggerLimitBurst=64

[Install]
WantedBy=multi-user.target
`

const trustBridgeServiceUnit = `[Unit]
Description=freens TLS trust bridge (refresh the system CA bundle from the §9.5 spool)
Documentation=https://github.com/camalolo/freens
# The daemon rewrites spool files on EVERY TLSCA re-verification, so this
# oneshot can legitimately fire several times a minute; the default
# StartLimitIntervalSec (5 starts / 10 s) tripped within a day on the
# fleet and left the path unit in failed state FOREVER — the system CA
# store then silently aged out while the spool stayed fresh (found live
# 2026-09-01: server's freens-trust.path failed with unit-start-limit-hit,
# minipc's store holding expired cross-certs). A merge of queued triggers
# is exactly what we want anyway: the service converges on whatever the
# spool holds when it runs.
StartLimitIntervalSec=0

[Service]
Type=oneshot
# Only FRESH certs reach the system store: a cross-cert whose notAfter has
# passed shares its owner CA's subject (and deterministic key) with the
# live one, so an expired copy in the store poisons verification of an
# otherwise-valid chain (found live: "certificate expired" for a name
# whose presented leaf AND CA were both in validity). The daemon sweeps
# the spool itself; this filter is the belt to those braces (covers the
# daemon being down while entries age past their validity).
ExecStart=/bin/sh -c 'mkdir -p /usr/local/share/ca-certificates && rm -f /usr/local/share/ca-certificates/freens-cross-*.crt && for f in %SPoolDir%/freens-cross-*.crt; do [ -f "$f" ] && openssl x509 -in "$f" -noout -checkend 0 >/dev/null 2>&1 && cp "$f" /usr/local/share/ca-certificates/; done; true'
ExecStart=/usr/sbin/update-ca-certificates
`

// trustBridgePaths computes the two unit files' contents for homeDir.
// Returns (pathUnitPath, pathUnit, svcUnitPath, svcUnit). The destination
// paths are var-gated (pathTrustBridge*) so tests can sandbox them, exactly
// like pathSystemctlUnit.
func trustBridgePaths(homeDir string) (string, string, string, string) {
	spool := filepath.Join(homeDir, "tls", "spool")
	pathUnit := strings.ReplaceAll(trustBridgePathUnit, "%SPoolDir%", spool)
	svcUnit := strings.ReplaceAll(trustBridgeServiceUnit, "%SPoolDir%", spool)
	return pathTrustBridgePathUnit, pathUnit, pathTrustBridgeSvcUnit, svcUnit
}

// Var-gated unit destinations (tests repoint these into a temp dir).
var (
	pathTrustBridgePathUnit = "/etc/systemd/system/freens-trust.path"
	pathTrustBridgeSvcUnit  = "/etc/systemd/system/freens-trust.service"
)

// installTrustBridge writes + enables the bridge units (privileged; prints
// the manual recipe when sudo fails). Called by setup after the main unit.
//
// REPAIR semantics (v0.14.1): the original skipped any existing unit file,
// which meant a fixed template could never reach the boxes whose units were
// installed by an older release — and the boxes that needed the fix are
// exactly the boxes that have units. Now: write when the on-disk content
// differs (or is missing), reset-failed a tripped bridge, then (re)start
// the path unit. Idempotent: matching files cause no writes.
func installTrustBridge() {
	pu, puContent, su, suContent := trustBridgePaths(home.Dir())
	wrote := false
	if b, err := os.ReadFile(pu); err != nil || string(b) != puContent {
		if err := sysWriteEtc(pu, []byte(puContent), 0o644); err != nil {
			printManualCommands("freens-trust.path (§9.5 cross-cert bridge)", []string{
				"sudo cp <freens-trust-path-unit> " + pu,
				"---\n" + puContent + "---",
				"sudo cp <freens-trust-service-unit> " + su,
				"---\n" + suContent + "---",
				"sudo systemctl daemon-reload && sudo systemctl reset-failed freens-trust.path freens-trust.service; sudo systemctl enable --now freens-trust.path",
			})
			return
		}
		wrote = true
	}
	if b, err := os.ReadFile(su); err != nil || string(b) != suContent {
		if err := sysWriteEtc(su, []byte(suContent), 0o644); err != nil {
			return
		}
		wrote = true
	}
	if !wrote {
		// Content already current: nothing to reload, but a bridge that is
		// sitting in failed state (start-limit-hit from an older unit) must
		// still be revived.
		_ = sudoRun("reviving freens-trust.path (reset-failed + start)", "systemctl",
			"reset-failed", "freens-trust.path", "freens-trust.service")
		_ = sudoRun("starting freens-trust.path", "systemctl", "start", "freens-trust.path")
		return
	}
	if err := sudoRun("reloading systemd (freens-trust bridge)", "systemctl", "daemon-reload"); err != nil {
		return
	}
	_ = sudoRun("reviving freens-trust.path (reset-failed + restart)", "systemctl",
		"reset-failed", "freens-trust.path", "freens-trust.service")
	_ = sudoRun("restarting freens-trust.path", "systemctl", "restart", "freens-trust.path")
}
