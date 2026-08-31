package cli

import (
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

[Install]
WantedBy=multi-user.target
`

const trustBridgeServiceUnit = `[Unit]
Description=freens TLS trust bridge (refresh the system CA bundle from the §9.5 spool)
Documentation=https://github.com/camalolo/freens

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'mkdir -p /usr/local/share/ca-certificates && rm -f /usr/local/share/ca-certificates/freens-cross-*.crt && cp %SPoolDir%/freens-cross-*.crt /usr/local/share/ca-certificates/ 2>/dev/null; true'
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
func installTrustBridge() {
	pu, puContent, su, suContent := trustBridgePaths(home.Dir())
	wrote := true
	if !sysStatExists(pu) {
		if err := sysWriteEtc(pu, []byte(puContent), 0o644); err != nil {
			printManualCommands("freens-trust.path (§9.5 cross-cert bridge)", []string{
				"sudo cp <freens-trust-path-unit> " + pu,
				"---\n" + puContent + "---",
				"sudo cp <freens-trust-service-unit> " + su,
				"---\n" + suContent + "---",
				"sudo systemctl daemon-reload && sudo systemctl enable --now freens-trust.path",
			})
			wrote = false
		}
	}
	if wrote && !sysStatExists(su) {
		if err := sysWriteEtc(su, []byte(suContent), 0o644); err != nil {
			wrote = false
		}
	}
	if !wrote {
		return
	}
	if err := sudoRun("reloading systemd (freens-trust bridge)", "systemctl", "daemon-reload"); err != nil {
		return
	}
	_ = sudoRun("enabling freens-trust.path", "systemctl", "enable", "--now", "freens-trust.path")
}
