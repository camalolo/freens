// Package winsvc isolates the Windows Service Control Manager (SCM)
// integration: install/remove/start/stop/query of the "freens" service and
// the elevation check setup needs.
//
// The non-windows build gets inert stubs (errors that say so), so the CLI
// can reference the API from shared setup/upgrade code and the whole tree
// still compiles on every GOOS. The real implementation only links
// golang.org/x/sys/windows when building FOR windows.
//
// Service model (mirrors setup's Linux systemd system unit): the daemon is
// machine infrastructure — it must start at boot with no user logged in,
// so the service runs as LocalSystem with the machine-wide state dir
// (%ProgramData%\freens, see internal/home) shared with the CLI and
// freens-web. The daemon binds no privileged ports (Windows has no
// <1024 restriction), so LocalSystem buys boot-time start, restart-on-
// failure recovery, and isolation — nothing else.
package winsvc

// Name is the SCM service name (and the short name net start/stop accept).
const Name = "freens"

// DisplayName is the human-readable name in services.msc.
const DisplayName = "freens daemon"

// Description shows on the service's properties page.
const Description = "freens resolver + DHT daemon (self-certifying DNS, spec §9.1). " +
	"Installs the machine-wide state in %ProgramData%\\freens and serves the OS " +
	"resolver on 127.0.0.1:53. Manage with `freens setup -uninstall` or services.msc."

// The freens-web service (the LAN management UI) — same model, own SCM
// identity so the daemon's availability never depends on the UI.
const (
	WebName        = "freens-web"
	WebDisplayName = "freens web UI"
	WebDescription = "freens LAN management web UI (port 8090). Reads the same " +
		"machine-wide state (%ProgramData%\\freens) as the freens daemon. " +
		"Manage with `freens uninstall` or services.msc."
)

// InstallOptions describes one service (re)install.
type InstallOptions struct {
	// Binary is the absolute path of the executable the service runs.
	Binary string
	// Args are the service's arguments (argv after the binary), e.g.
	// ["daemon", "-config", `<home>\freens.conf`].
	Args []string
}
