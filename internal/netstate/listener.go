package netstate

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

var tcpProcFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}
var udpProcFiles = []string{"/proc/net/udp", "/proc/net/udp6"}

// TCPListening reports whether the host currently owns a TCP listening socket
// on port. It is deliberately passive: callers must not actively connect to
// transparent-proxy ports such as Xray dokodemo-door, because doing so can
// create a self-referential routing loop.
func TCPListening(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	for _, path := range tcpProcFiles {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		found := scanProcNet(file, port, true)
		_ = file.Close()
		if found {
			return true
		}
	}
	return false
}

// PortBound reports whether either a TCP listener or UDP socket is bound to
// port. Use TCPListening when a TCP listener is the actual readiness signal.
func PortBound(port int) bool {
	if TCPListening(port) {
		return true
	}
	for _, path := range udpProcFiles {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		found := scanProcNet(file, port, false)
		_ = file.Close()
		if found {
			return true
		}
	}
	return false
}

func scanProcNet(reader io.Reader, port int, listenOnly bool) bool {
	if port < 1 || port > 65535 {
		return false
	}

	scanner := bufio.NewScanner(reader)
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
