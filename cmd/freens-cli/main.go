// Command freens-cli is the developer front-end for freens — now a thin
// COMPAT SHIM over the shared implementation in internal/cli (the same code
// the `freens` binary dispatches to). It keeps the historical binary name,
// its own ldflags version stamp, and the classic exit-code conventions:
// 0 success, 1 usage/io error, 2 crypto/validation failure.
//
// See internal/cli for the subcommand table (gen-key, mine-claim,
// make-record, publish, resolve, get, name, transfer, rotate, recover,
// verify-recovery, register, setup, status, doctor, demo, version).
package main

import (
	"fmt"
	"os"

	"github.com/laurent/freens/internal/cli"
)

// cliVersion is stamped at build time (-X main.cliVersion=...); "dev" marks
// a local build.
var cliVersion = "dev"

func main() {
	os.Exit(shimMain(os.Args))
}

// shimMain is the testable shim body. -version/--version/version answer
// from THIS binary's own stamp (so the shim's ldflags version wins over the
// cli package's); everything else defers to cli.Main under the "freens-cli"
// program name for byte-compatible output.
func shimMain(argv []string) int {
	if len(argv) > 1 {
		switch argv[1] {
		case "version", "-version", "--version":
			fmt.Println("freens-cli", cliVersion)
			return 0
		}
	}
	cli.ProgName = "freens-cli"
	return cli.Main(argv[1:])
}
