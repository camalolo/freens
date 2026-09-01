//go:build !windows

// Non-windows build of the freens-web service seam: there is no SCM, so
// the service entry never triggers and there is no log sink to swap.

package main

// windowsServiceRequested reports whether the SCM launched us — never on
// non-windows platforms.
func windowsServiceRequested() bool { return false }

// windowsRunService never runs off-windows (the SCM entry is guarded by
// windowsServiceRequested).
func windowsRunService() int { return 0 }
