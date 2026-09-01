//go:build windows

// service_windows.go — the SCM integration for `freens-web`: when the
// Windows service manager launches us (the "freens-web" service setup
// installs), answer its control protocol while the ordinary UI runs
// unchanged in a goroutine.
//
// Stop/shutdown requests drain the server (bounded) and only then report
// Stopped. slog output goes to <home>\webui.log (a service has no console;
// field debugging depends on this file, rotated like the daemon's).

package main

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/camalolo/freens/internal/home"
	"github.com/camalolo/freens/internal/winsvc"
	"golang.org/x/sys/windows/svc"
)

// windowsServiceRequested reports whether the SCM launched us.
func windowsServiceRequested() bool { return winsvc.IsService() }

// webuiLogRotateSize is the webui.log size at which a fresh service start
// rotates the previous log aside (webui.log.1) instead of growing one file
// forever.
const webuiLogRotateSize = 8 << 20

// windowsRunService rotates the log sink into place and blocks in the SCM
// control loop until the service stops. Returns a process exit code.
func windowsRunService() int {
	logSink = openWebuiLog()
	svc.Run(winsvc.WebName, &webuiService{})
	return 0 // svc.Run only returns after Execute finished; the code was already reported
}

// openWebuiLog opens <home>\webui.log for appending, rotating an oversized
// previous log aside first. Best effort: a nil return just means the UI
// logs to the (service) null console.
func openWebuiLog() (w *os.File) {
	path := filepath.Join(home.Dir(), "webui.log")
	if info, err := os.Stat(path); err == nil && info.Size() > webuiLogRotateSize {
		_ = os.Remove(path + ".1")
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	return f
}

// webuiService is the svc.Handler: StartPending → run the UI in a
// goroutine → Running (AcceptStop|AcceptShutdown) → on stop, close the
// stop channel and wait for the drained shutdown → Stopped.
type webuiService struct{}

func (s *webuiService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// ARG DELIVERY (same SCM behavior the daemon documents): the SCM hands
	// Execute the SERVICE NAME, never the ImagePath arguments. The real
	// command line exists only in os.Args; fall back to the SCM-provided
	// args for an argument-less start.
	svcArgs := os.Args[1:]
	if len(svcArgs) == 0 {
		svcArgs = args
	}

	stopOnce := new(sync.Once)
	stop := make(chan struct{})
	signalStop := func() { stopOnce.Do(func() { close(stop) }) }
	done := make(chan error, 1)
	go func() { done <- consoleRun(svcArgs, stop) }()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			changes <- svc.Status{State: svc.Stopped}
			if err != nil {
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
