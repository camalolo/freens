// addrrr_test.go — the "-ip is v4 OR v6" rule of the easy buttons.
package cli

import (
	"testing"

	"github.com/camalolo/freens/internal/wire"
)

func TestAddrRR(t *testing.T) {
	a, err := addrRR("203.0.113.42", 300)
	if err != nil || a.Type != wire.RRTypeA || len(a.Rdata) != 4 {
		t.Fatalf("v4: %v %+v", err, a)
	}
	aaaa, err := addrRR("fd00::42", 300)
	if err != nil || aaaa.Type != wire.RRTypeAAAA || len(aaaa.Rdata) != 16 {
		t.Fatalf("v6: %v %+v", err, aaaa)
	}
	// Bracketed and canonical v6 forms.
	if _, err := addrRR("::1", 300); err != nil {
		t.Errorf("::1 rejected: %v", err)
	}
	if _, err := addrRR("not-an-ip", 300); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := addrRR("203.0.113.999", 300); err == nil {
		t.Error("bad v4 accepted")
	}
}
