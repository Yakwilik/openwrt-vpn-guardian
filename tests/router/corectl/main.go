// corectl is an operator-only fault-injection helper for router acceptance tests.
// It is not installed by the package.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Yakwilik/openwrt-vpn-guardian/internal/v2raya"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: corectl start|stop")
		os.Exit(2)
	}
	method := http.MethodPost
	switch os.Args[1] {
	case "start":
	case "stop":
		method = http.MethodDelete
	default:
		fmt.Fprintln(os.Stderr, "unknown action")
		os.Exit(2)
	}
	if _, err := v2raya.CallAPI("acceptance-test", method, "v2ray", nil, 10*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
