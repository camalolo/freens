// testmain_test.go — the windows half of the cli package's TestMain (the
// plaintext-key opt-in lives in passphrase_policy_test.go).
//
// Why (found live on the desktop test box, v0.11.0 test day): the box's ssh
// session carries an UNFILTERED administrator token, so winsvc.IsElevated()
// is true inside tests and every "windows branch" is REAL — a test that
// forgets to stub can (and one did) stop/delete the machine's actual freens
// service, re-point adapter DNS or touch firewall rules. These defaults make
// forgetfulness safe: tests that exercise these flows swap in their own
// fakes as before, and linux is unaffected (the whole block is GOOS-gated).
package cli

import (
	"errors"
	"runtime"

	"github.com/camalolo/freens/internal/winsvc"
)

// errStubbedOSHook is the safety-net stubs' answer (a test that reaches one
// without re-stubbing gets a loud, identifiable failure instead of a real
// machine mutation).
var errStubbedOSHook = errors.New("windows OS plumbing stubbed for tests (re-stub in the test to exercise it)")

// stubWindowsOSHooks force-stubs every OS-touching hook on windows AND pins
// the platform dispatch to the linux flows: the pre-existing setup/upgrade
// tests were written against the linux implementation (they stub sysRun,
// sudo, systemctl …) and must keep exercising it on a windows dev box. The
// windows flows get their own direct-call tests (setupwin_test.go), which
// re-stub the hooks per test; TestSetupRoutesByPlatform covers the dispatch.
func stubWindowsOSHooks() {
	if runtime.GOOS != "windows" {
		return
	}
	platform = "linux"
	goosWindows = false
	winPowerShell = func(string) (string, error) { return "[]", nil }
	windowsRelay = func(args ...string) error { return errStubbedOSHook }
	winSvcElevated = func() bool { return false }
	winSvcInstall = func(winsvc.InstallOptions) error { return errStubbedOSHook }
	winSvcRemove = func() error { return errStubbedOSHook }
	winSvcRunning = func() bool { return false }
	winSvcStop = func() error { return errStubbedOSHook }
	winSvcStart = func() error { return errStubbedOSHook }
	winRunElevatedGate = func(args ...string) error { return errStubbedOSHook }
}
