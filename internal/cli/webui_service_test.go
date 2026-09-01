// webui_service_test.go — "the UI should be always there": setup installs
// the freens-web unit on linux (systemd), the LaunchAgent on darwin
// (launchd), and webui.Server drains cleanly on Shutdown (the SCM/console
// stop path).
package cli

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/webui"
)

// fakeWebuiBin plants a freens-web binary next to the stubbed executable
// (installWebUIUnit's layout rule) and returns its path.
func fakeWebuiBin(t *testing.T) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "freens")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	webBin := exe + "-web"
	if err := os.WriteFile(webBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldExe := sysExecutable
	sysExecutable = func() (string, error) { return exe, nil }
	t.Cleanup(func() { sysExecutable = oldExe })
	return webBin
}

func TestSetupInstallsWebUIUnit(t *testing.T) {
	tempHome(t) // sets FREENS_HOME → the unit must carry the env line
	rec := stubSysForTest(t)
	webBin := fakeWebuiBin(t)

	out, err := captureStdout(t, func() error { return cmdSetup([]string{}) })
	if err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	unitPath := filepath.Join(filepath.Dir(pathSystemctlUnit), "freens-web.service")
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("freens-web.service not written: %v\n%s", err, out)
	}
	for _, want := range []string{
		"ExecStart=" + webBin,
		"User=",
		"Environment=FREENS_HOME=",
		"After=network-online.target freens.service",
		"Restart=on-failure",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("webui unit missing %q:\n%s", want, unit)
		}
	}
	if !rec.ran("sudo", "-n", "systemctl", "enable", "--now", "freens-web.service") {
		t.Errorf("freens-web.service not enabled: %v", rec.cmds)
	}
}

func TestSetupSkipsWebUIUnitWithoutBinary(t *testing.T) {
	tempHome(t)
	rec := stubSysForTest(t)
	// No freens-web planted: a hand-built freens without the UI is fine.
	oldExe := sysExecutable
	exe := filepath.Join(t.TempDir(), "freens")
	os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755)
	sysExecutable = func() (string, error) { return exe, nil }
	t.Cleanup(func() { sysExecutable = oldExe })

	if _, err := captureStdout(t, func() error { return cmdSetup([]string{}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(pathSystemctlUnit), "freens-web.service")); !os.IsNotExist(err) {
		t.Error("webui unit written although no freens-web binary exists")
	}
	_ = rec
}

func TestSetupDarwinWebUIAgent(t *testing.T) {
	dir := tempHome(t)
	oldDarwin := goosDarwin
	goosDarwin = true
	t.Cleanup(func() { goosDarwin = oldDarwin })

	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	fakeWebuiBin(t)

	var launchctlCmds [][]string
	oldRun := sysRun
	sysRun = func(name string, args ...string) error {
		if name == "launchctl" {
			launchctlCmds = append(launchctlCmds, args)
		}
		return nil
	}
	t.Cleanup(func() { sysRun = oldRun })

	out, err := captureStdout(t, func() error { return cmdSetup([]string{}) })
	if err != nil {
		t.Fatalf("setup (darwin): %v\n%s", err, out)
	}
	plist, err := os.ReadFile(filepath.Join(fakeHome, "Library", "LaunchAgents", "com.freens.webui.plist"))
	if err != nil {
		t.Fatalf("LaunchAgent plist not written: %v", err)
	}
	for _, want := range []string{"com.freens.webui", "freens-web", "KeepAlive", "EnvironmentVariables"} {
		if !strings.Contains(string(plist), want) {
			t.Errorf("plist missing %q:\n%s", want, plist)
		}
	}
	if len(launchctlCmds) < 2 {
		t.Errorf("launchctl calls = %v; want unload + load", launchctlCmds)
	}
	_ = dir
}

func TestWebuiShutdownDrains(t *testing.T) {
	dir := t.TempDir()
	cfg := &webui.Config{Listen: "127.0.0.1:0", Allow: "any"}
	srv, err := webui.New(cfg, filepath.Join(dir, "admin.sock"), nil)
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	// The stop path (SCM Stop / SIGTERM): Shutdown drains and Serve
	// returns ErrServerClosed — the caller maps that to a clean exit.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("serve returned %v; want ErrServerClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after Shutdown")
	}
}
