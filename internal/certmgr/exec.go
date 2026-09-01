// exec.go — the shell/process plumbing certmgr needs (deploy hooks and
// nginx validation/reload), with the timeout + capture every caller wants
// and a test seam (execRunner) so no test ever spawns a real nginx.
package certmgr

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"time"
)

// ExecResult is one captured command run.
type ExecResult struct {
	Stdout string
	Stderr string
}

// execRunner runs name+args and captures output. Var so tests substitute a
// fake; the package's real entry points (RunHook, nginx validate/reload,
// discovery) all funnel through here.
var execRunner = func(ctx context.Context, name string, args ...string) (ExecResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return ExecResult{Stdout: out.String(), Stderr: errb.String()}, err
}

// runShell runs one shell line (sh -c on unix, cmd /c on windows) with a
// hard timeout; on timeout the error names the deadline.
func runShell(line string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var res ExecResult
	var err error
	if runtime.GOOS == "windows" {
		res, err = execRunner(ctx, "cmd", "/c", line)
	} else {
		res, err = execRunner(ctx, "sh", "-c", line)
	}
	out := res.Stdout + res.Stderr
	if ctx.Err() == context.DeadlineExceeded {
		return out, ctx.Err()
	}
	return out, err
}

// runWithTimeout is runShell for a name+args command (no shell parsing).
func runWithTimeout(timeout time.Duration, name string, args ...string) (ExecResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := execRunner(ctx, name, args...)
	if ctx.Err() == context.DeadlineExceeded {
		return res, ctx.Err()
	}
	return res, err
}

// execLookPath is a seam over exec.LookPath (the binary-resolution test
// swaps the candidate list instead in practice, but tests may stub this).
var execLookPath = exec.LookPath
