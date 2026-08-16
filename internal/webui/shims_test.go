package webui

// shims_test.go — small stdlib shims for the ops tests (separate file so
// the main test file reads cleanly).

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/camalolo/freens/internal/claims"
	"github.com/camalolo/freens/internal/crypto"
)

func powDifficultyInit() int { return claims.PoWDifficultyInit }
func powDifficultySet(v int) func() {
	claims.PoWDifficultyInit = 8
	return func() { claims.PoWDifficultyInit = v }
}
func statFile(p string) (os.FileInfo, error) { return os.Stat(p) }
func mkdirAllImpl(p string, mode os.FileMode) error {
	return os.MkdirAll(p, mode)
}
func fmtSprintf(f string, a ...any) string    { return fmt.Sprintf(f, a...) }
func errorsAsImpl(err error, target any) bool { return errors.As(err, target) }
func genKP(t *testing.T) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}
