//go:build !windows

// Off-windows the service entry points are inert: the daemon is started by
// systemd (Linux) or launchd manually (darwin) — never by an SCM.

package main

// windowsServiceRequested always reports false off-windows.
func windowsServiceRequested() bool { return false }

// windowsRunService is unreachable off-windows (the gate above is false).
func windowsRunService() int { return 0 }
