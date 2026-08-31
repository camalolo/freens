//go:build !windows

// Inert stubs so non-windows builds compile; every entry point says
// "windows only" if somehow reached (the CLI dispatches on runtime.GOOS
// long before calling into here).

package winsvc

import "errors"

// errWindowsOnly is every stub's answer.
var errWindowsOnly = errors.New("service management is only implemented on windows")

// IsService always reports false off-windows.
func IsService() bool { return false }

// IsElevated always reports false off-windows.
func IsElevated() bool { return false }

// Install is not available off-windows.
func Install(InstallOptions) error { return errWindowsOnly }

// Remove is not available off-windows.
func Remove() error { return errWindowsOnly }

// Start is not available off-windows.
func Start() error { return errWindowsOnly }

// Stop is not available off-windows.
func Stop() error { return errWindowsOnly }

// Running always reports false off-windows.
func Running() bool { return false }
