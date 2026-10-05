package netstate

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

var procNetFiles = []struct {
	path       string
	tcp        bool
	listenOnly bool
}{
	{path: "/proc/net/tcp", tcp: true, listenOnly: true},
	{path: "/proc/net/tcp6", tcp: true, listenOnly: true},
	{path: "/proc/net/udp", tcp: false, listenOnly: false},
	{path: "/proc/net/udp6", tcp: false, listenOnly: false},
}

// PortListening reports whether the host currently owns a TCP listening socket
// or UDP socket bound to port. It is deliberately passive: callers must not
// actively connect to transparent-proxy ports such as Xray dokodemo-door,
// because doing so can create a self-referential routing loop.
func PortListening(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}

	for _, source := range procNetFiles {
		file, err := os.Open(source.path)
		if err != nil {
			continue
		}
		found := scanProcNet(file, port, source.listenOnly)
		_ = file.Close()
		if found {
			return true
		}
	}
	return false
}

func scanProcNet(scannerSource interface{ Read([]byte) (int, error) }, port int, listenOnly bool) bool {
	scanner := bufio.NewScanner(scannerSource)
	wantPort := strings.ToUpper(fmt.Sprintf("%04X", port))

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[0] == "sl" {
			continue
		}

		local := fields[1]
		state := fields[3]
		colon := strings.LastIndexByte(local, ':')
		if colon < 0 || colon == len(local)-1 {
			continue
		}
		if strings.ToUpper(local[colon+1:]) != wantPort {
			continue
		}

		if listenOnly && state != "0A" {
			continue
		}
		return true
	}
	return false
}
