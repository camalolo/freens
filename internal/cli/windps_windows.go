//go:build windows

// The real PowerShell runner (see windns.go for the orchestration).
// -NoProfile skips the user's profile (slower, may print noise);
// -NonInteractive never prompts.

package cli

func init() {
	winPowerShell = func(script string) (string, error) {
		return sysOutput("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	}
}
