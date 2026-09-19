// upnpprobe — operator diagnostic: run the exact UPnP ladder the daemon
// runs (Discover -> Map UDP -> MapTCPExact) and print every step.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/camalolo/freens/internal/upnp"
)

func main() {
	port := 15353
	if len(os.Args) > 1 {
		fmt.Sscanf(os.Args[1], "%d", &port)
	}
	logf := probeLogger{}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	fmt.Println("discover...")
	gws, err := upnp.Discover(ctx, logf)
	if err != nil {
		fmt.Println("discover error:", err)
		return
	}
	fmt.Printf("gateways found: %d\n", len(gws))
	_ = gws
	for range gws {
		mctx, mcancel := context.WithTimeout(context.Background(), 8*time.Second)
		m, merr := upnp.Map(mctx, port, "freens-probe", logf)
		mcancel()
		if merr != nil {
			fmt.Printf("  UDP map: FAILED: %v\n", merr)
			continue
		}
		fmt.Printf("  UDP map: OK external=%s\n", m.Addr())
		tctx, tcancel := context.WithTimeout(context.Background(), 8*time.Second)
		tm, terr := m.MapTCP(tctx, port)
		tcancel()
		if terr != nil {
			fmt.Printf("  TCP map: FAILED: %v\n", terr)
			continue
		}
		fmt.Printf("  TCP map: OK external=%s\n", tm.Addr())
	}
}

type probeLogger struct{}

func (probeLogger) Info(msg string, args ...any)  { fmt.Printf("INFO "+msg+"\n", args...) }
func (probeLogger) Warn(msg string, args ...any)  { fmt.Printf("WARN "+msg+"\n", args...) }
func (probeLogger) Debug(msg string, args ...any) { fmt.Printf("DEBUG "+msg+"\n", args...) }
