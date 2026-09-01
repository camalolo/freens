//go:build windows

// The real SCM integration (see package doc). Every function here is a thin
// wrapper over golang.org/x/sys/windows/svc(mgr) — the interesting policy
// (when to install, what to wire) lives in internal/cli's windows setup.

package winsvc

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// errNotStopped is the give-up after Stop() waited past its deadline.
var errNotStopped = errors.New("service did not reach the STOPPED state in time")

// IsService reports whether this process was launched BY the SCM (i.e. is
// the running service). The daemon entry point checks this before anything
// else.
func IsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// IsElevated reports whether the current token has administrator rights —
// everything in here needs them (SCM writes, per-adapter DNS, firewall).
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Install (re)creates the service: an existing copy is stopped and deleted
// first (idempotent re-runs and binary-path updates both land here), the
// new service is created with automatic start and restart-on-failure
// recovery, and started. Starting an already-running service is not an
// error (the SCM returns ERROR_SERVICE_ALREADY_RUNNING for the race).
func Install(opts InstallOptions) error {
	return installService(Name, DisplayName, Description, opts)
}

// InstallWeb (re)creates the freens-web UI service (same model as the
// daemon's: automatic start, restart-on-failure) and starts it.
func InstallWeb(opts InstallOptions) error {
	return installService(WebName, WebDisplayName, WebDescription, opts)
}

func installService(name, display, desc string, opts InstallOptions) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(name); err == nil {
		// Replace: stop (best effort — it may be stopped already) and
		// delete; the SCM removes a marked service once its last handle
		// closes, so close ours before creating the replacement.
		_ = stopAndWait(s, 15*time.Second)
		if err := s.Delete(); err != nil {
			s.Close()
			return fmt.Errorf("deleting the previous %s service: %w", name, err)
		}
		s.Close()
		// A service freshly marked for deletion cannot be re-created until
		// the SCM finishes processing it; poll briefly.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := m.OpenService(name); err != nil {
				break // gone — the common case
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	s, err := m.CreateService(name, opts.Binary, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: display,
		Description: desc,
		// Recovery: a crashed daemon comes back in 2 s, then 5 s; after
		// that the SCM leaves it down (a config error restart-looping
		// forever is worse than down-and-diagnosable via doctor). The
		// failure counter resets after a day of quiet.
	}, opts.Args...)
	if err != nil {
		return fmt.Errorf("creating the %s service: %w", name, err)
	}
	defer s.Close()

	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.NoAction},
	}, 86400)

	if err := s.Start(); err != nil {
		// A service left RUNNING by a race with the delete above (or
		// started by someone else mid-install) is success, not failure.
		var errno syscall.Errno
		if !errors.As(err, &errno) || errno != 1056 /* ERROR_SERVICE_ALREADY_RUNNING */ {
			return fmt.Errorf("starting the %s service: %w", name, err)
		}
	}
	return nil
}

// Remove stops the service (best effort) and deletes it. A missing service
// is success (uninstall is idempotent).
func Remove() error {
	return removeService(Name)
}

// RemoveWeb stops and deletes the freens-web UI service. A missing service
// is success (uninstall is idempotent).
func RemoveWeb() error {
	return removeService(WebName)
}

func removeService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return nil // not installed — nothing to do
	}
	defer s.Close()
	_ = stopAndWait(s, 15*time.Second)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("deleting the %s service: %w", name, err)
	}
	return nil
}

// Start starts the service (idempotent: already-running is success).
func Start() error { return startService(Name) }

// StartWeb starts the freens-web UI service (idempotent).
func StartWeb() error { return startService(WebName) }

func startService(name string) error {
	s, err := openRunningNamed(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == 1056 {
			return nil
		}
		return fmt.Errorf("starting the %s service: %w", Name, err)
	}
	return nil
}

// Stop stops the service (idempotent: a stopped/missing service is
// success). Used by upgrade before swapping the binary — Windows locks a
// running image against replace.
func Stop() error { return stopService(Name) }

// StopWeb stops the freens-web UI service (idempotent).
func StopWeb() error { return stopService(WebName) }

func stopService(name string) error {
	s, err := openRunningNamed(name)
	if err != nil {
		if errors.Is(err, errNotInstalled) {
			return nil
		}
		return err
	}
	defer s.Close()
	return stopAndWait(s, 20*time.Second)
}

// Running reports whether the service exists and is in the RUNNING state.
func Running() bool { return runningService(Name) }

// RunningWeb reports whether the freens-web UI service exists and runs.
func RunningWeb() bool { return runningService(WebName) }

func runningService(name string) bool {
	s, err := openRunningNamed(name)
	if err != nil {
		return false
	}
	defer s.Close()
	st, err := s.Query()
	return err == nil && st.State == svc.Running
}

// errNotInstalled reports the service does not exist.
var errNotInstalled = errors.New("service not installed")

// openRunning connects to the manager and opens the default daemon
// service in one go.
func openRunning() (*mgr.Service, error) {
	return openRunningNamed(Name)
}

// openRunningNamed connects to the manager and opens the named service.
func openRunningNamed(name string) (*mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("connecting to the service manager: %w", err)
	}
	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		return nil, errNotInstalled
	}
	// s owns the manager connection's lifetime too; Close on the service
	// is enough for our process-lifetime usage.
	return s, nil
}

// stopAndWait asks for STOP and polls until Stopped (or deadline).
func stopAndWait(s *mgr.Service, d time.Duration) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		// Already stopping is fine.
		if st.State != svc.StopPending {
			return fmt.Errorf("stopping the %s service: %w", s.Name, err)
		}
	}
	deadline := time.Now().Add(d)
	for {
		st, err = s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return errNotStopped
		}
		time.Sleep(250 * time.Millisecond)
	}
}
