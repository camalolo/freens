//go:build windows

// service_windows.go — the SCM integration for `freens daemon`: when the
// Windows service manager launches us, answer its control protocol while
// the ordinary daemon runs unchanged in a goroutine.
//
// The service entry is `freens.exe daemon -config <home>\freens.conf` (the
// args setup configures at install time). Stop/shutdown requests close
// serviceStop, which run()'s signal select treats exactly like SIGTERM —
// one shutdown sequence serves console and service alike. slog output
// goes to <home>/daemon.log (a service has no console; field debugging
// depends on this file).

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/winsvc"
	"golang.org/x/sys/windows/svc"
)

// windowsServiceRequested reports whether the SCM launched us.
func windowsServiceRequested() bool { return winsvc.IsService() }

// The service runs as LocalSystem: the machine trust store is always
// writable from here (and the interactive fallback lives in trustsync).
func init() { systemStoreWritable = func() bool { return true } }

// daemonLogRotateSize is the daemon.log size at which a fresh service
// start rotates the previous log aside (daemon.log.1) instead of growing
// one file forever.
const daemonLogRotateSize = 8 << 20

// windowsRunService rotates the log sink into place and blocks in the SCM
// control loop until the service stops. Returns a process exit code.
func windowsRunService() int {
	daemonLogSink = openDaemonLog()
	svc.Run(winsvc.Name, &freensService{})
	return 0 // svc.Run only returns after Execute finished; the code was already reported
}

// openDaemonLog opens <home>/daemon.log for appending, rotating an
// oversized previous log aside first. Best effort: a nil return just means
// the daemon logs to the (service) null console.
func openDaemonLog() (w *os.File) {
	path := filepath.Join(home.Dir(), "daemon.log")
	if info, err := os.Stat(path); err == nil && info.Size() > daemonLogRotateSize {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	return f
}

// freensService is the svc.Handler: StartPending → run the daemon in a
// goroutine → Running (AcceptStop|AcceptShutdown) → on stop, close
// serviceStop and wait for the daemon's orderly shutdown → Stopped.
type freensService struct{}

func (s *freensService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// ARG DELIVERY (found live on the desktop test box, v0.11.0): the SCM
	// hands Execute the SERVICE NAME — ["freens"], not the ImagePath
	// arguments. The real command line exists only in os.Args. Prefer it;
	// the SCM-provided args are the fallback for an argument-less start.
	svcArgs := os.Args[1:]
	if len(svcArgs) == 0 {
		svcArgs = args
	}
	args = daemonArgs(svcArgs)

	stopOnce := new(sync.Once)
	serviceStop = make(chan struct{})
	signalStop := func() { stopOnce.Do(func() { close(serviceStop) }) }

	done := make(chan error, 1)
	go func() { done <- run(args) }()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			changes <- svc.Status{State: svc.Stopped}
			if err != nil {
				fmt.Fprintf(os.Stderr, "freens service: daemon exited: %v\n", err)
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				signalStop()
			}
		}
	}
}
