// Standalone native-daemon integration fixture. All listeners use loopback and
// ephemeral ports. It neither installs a package nor changes system DNS/DHCP.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type upstream struct {
	udp    net.PacketConn
	tcp    net.Listener
	port   int
	marker byte
	mu     sync.Mutex
	counts map[string]int
}

func startUpstream(marker byte) (*upstream, error) {
	u, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t, err := net.Listen("tcp4", u.LocalAddr().String())
	if err != nil {
		u.Close()
		return nil, err
	}
	s := &upstream{udp: u, tcp: t, port: u.LocalAddr().(*net.UDPAddr).Port, marker: marker, counts: make(map[string]int)}
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := u.ReadFrom(buffer)
			if err != nil {
				return
			}
			response, err := s.answer(buffer[:n])
			if err == nil {
				_, _ = u.WriteTo(response, peer)
			}
		}
	}()
	go func() {
		for {
			conn, err := t.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				for {
					var header [2]byte
					if _, err := io.ReadFull(conn, header[:]); err != nil {
						return
					}
					request := make([]byte, binary.BigEndian.Uint16(header[:]))
					if _, err := io.ReadFull(conn, request); err != nil {
						return
					}
					response, err := s.answer(request)
					if err != nil {
						return
					}
					binary.BigEndian.PutUint16(header[:], uint16(len(response)))
					if _, err := conn.Write(append(header[:], response...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return s, nil
}
func (s *upstream) stop() { _ = s.udp.Close(); _ = s.tcp.Close() }
func (s *upstream) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[strings.ToLower(name)]
}
func question(message []byte) (string, int, uint16, error) {
	if len(message) < 12 {
		return "", 0, 0, fmt.Errorf("short DNS header")
	}
	p := 12
	labels := []string{}
	for p < len(message) {
		n := int(message[p])
		p++
		if n == 0 {
			if p+4 > len(message) {
				break
			}
			return strings.Join(labels, "."), p + 4, binary.BigEndian.Uint16(message[p:]), nil
		}
		if n > 63 || p+n > len(message) {
			break
		}
		labels = append(labels, string(message[p:p+n]))
		p += n
	}
	return "", 0, 0, fmt.Errorf("invalid question")
}
func (s *upstream) answer(request []byte) ([]byte, error) {
	name, end, kind, err := question(request)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.counts[strings.ToLower(name)]++
	s.mu.Unlock()
	response := make([]byte, 12)
	copy(response[:2], request[:2])
	binary.BigEndian.PutUint16(response[2:], 0x8180)
	binary.BigEndian.PutUint16(response[4:], 1)
	binary.BigEndian.PutUint16(response[6:], 1)
	response = append(response, request[12:end]...)
	data := []byte{192, 0, 2, s.marker}
	switch kind {
	case 28:
		data = make([]byte, 16)
		copy(data, []byte{0x20, 0x01, 0x0d, 0xb8})
		data[15] = s.marker
	case 16:
		data = []byte{1, s.marker}
	}
	rr := make([]byte, 12)
	binary.BigEndian.PutUint16(rr, 0xc00c)
	binary.BigEndian.PutUint16(rr[2:], kind)
	binary.BigEndian.PutUint16(rr[4:], 1)
	binary.BigEndian.PutUint16(rr[10:], uint16(len(data)))
	response = append(response, rr...)
	response = append(response, data...)
	return response, nil
}

var requestID uint32

func query(port int, name string, kind uint16, tcp bool, timeout time.Duration) ([]byte, error) {
	request := make([]byte, 12)
	binary.BigEndian.PutUint16(request, uint16(atomic.AddUint32(&requestID, 1)))
	binary.BigEndian.PutUint16(request[2:], 0x0100)
	binary.BigEndian.PutUint16(request[4:], 1)
	for _, label := range strings.Split(name, ".") {
		request = append(request, byte(len(label)))
		request = append(request, label...)
	}
	request = append(request, 0, byte(kind>>8), byte(kind), 0, 1)
	network := "udp4"
	if tcp {
		network = "tcp4"
	}
	conn, err := net.DialTimeout(network, fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if tcp {
		frame := []byte{byte(len(request) >> 8), byte(len(request))}
		frame = append(frame, request...)
		if _, err = conn.Write(frame); err != nil {
			return nil, err
		}
		var header [2]byte
		if _, err = io.ReadFull(conn, header[:]); err != nil {
			return nil, err
		}
		response := make([]byte, binary.BigEndian.Uint16(header[:]))
		_, err = io.ReadFull(conn, response)
		return response, err
	}
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	return response[:n], err
}
func responseMarker(response []byte) (byte, error) {
	if len(response) < 12 || binary.BigEndian.Uint16(response[2:])&15 != 0 || binary.BigEndian.Uint16(response[6:]) == 0 {
		return 0, fmt.Errorf("DNS failure/empty answer: %x", response)
	}
	_, p, kind, err := question(response)
	if err != nil {
		return 0, err
	}
	if p+2 > len(response) {
		return 0, fmt.Errorf("short answer")
	}
	if response[p]&0xc0 == 0xc0 {
		p += 2
	} else {
		for p < len(response) && response[p] != 0 {
			p += 1 + int(response[p])
		}
		p++
	}
	if p+10 > len(response) {
		return 0, fmt.Errorf("short RR")
	}
	n := int(binary.BigEndian.Uint16(response[p+8:]))
	p += 10
	if p+n > len(response) || n == 0 {
		return 0, fmt.Errorf("short RDATA")
	}
	switch kind {
	case 1, 28, 16:
		return response[p+n-1], nil
	}
	return 0, fmt.Errorf("unknown RR")
}
func writeSelectors(path string, proxy int, revision int) error {
	lines := []string{}
	if revision == 0 {
		patterns := []string{
			`^exact[.]test$`, `^proxy[0-9]+[.]exact[.]test$`,
			`^github-production-release-asset-[0-9a-zA-Z]{6}\.s3\.amazonaws\.com$`,
			`^chatgpt-async-webps-prod-[^ ]+-[0-9]+\.webpubsub\.azure\.com$`,
			`^.*[.]private[.]test$`, `^.*[.]direct[.]test$`, `^.*[.]home[.]arpa$`,
		}
		for _, pattern := range patterns {
			lines = append(lines, fmt.Sprintf("server=/regex:%s/127.0.0.1#%d", pattern, proxy))
		}
		lines = append(lines, fmt.Sprintf("server=/suffix.test/127.0.0.1#%d", proxy))
	} else {
		lines = append(lines, fmt.Sprintf("server=/regex:^new-[a-z]+[.]test$/127.0.0.1#%d", proxy))
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func run(binary string) error {
	version, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil {
		return err
	}
	if !strings.Contains(string(version), "regex-server") {
		return fmt.Errorf("binary lacks regex-server capability")
	}
	ubusObject := os.Getenv("DNSMASQ_TEST_UBUS")
	if ubusObject != "" {
		if !strings.Contains(string(version), "regex-server-ack") {
			return fmt.Errorf("binary lacks regex-server-ack capability")
		}
		if ubusObject != "dnsmasq.guardian-canary" && !strings.HasPrefix(ubusObject, "dnsmasq.guardian-canary.") {
			return fmt.Errorf("DNSMASQ_TEST_UBUS must use the dnsmasq.guardian-canary namespace")
		}
		for _, c := range ubusObject {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
				return fmt.Errorf("invalid DNSMASQ_TEST_UBUS object")
			}
		}
		output, e := exec.Command("ubus", "-t", "10", "list").CombinedOutput()
		if e != nil {
			return fmt.Errorf("cannot inspect UBus canary namespace: %w: %s", e, output)
		}
		for _, existing := range strings.Split(string(output), "\n") {
			if strings.TrimSpace(existing) == ubusObject {
				return fmt.Errorf("refusing to reuse an existing UBus object: %s", ubusObject)
			}
		}
	}
	direct, err := startUpstream(11)
	if err != nil {
		return err
	}
	defer direct.stop()
	proxy, err := startUpstream(22)
	if err != nil {
		return err
	}
	defer proxy.stop()
	private, err := startUpstream(33)
	if err != nil {
		return err
	}
	defer private.stop()
	dir, err := os.MkdirTemp("", "dnsmasq-guardian-wire-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	managed := filepath.Join(dir, "selectors.conf")
	if err = writeSelectors(managed, proxy.port, 0); err != nil {
		return err
	}
	reservation, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := reservation.LocalAddr().(*net.UDPAddr).Port
	_ = reservation.Close()
	conf := filepath.Join(dir, "dnsmasq.conf")
	text := fmt.Sprintf("no-resolv\nno-hosts\ncache-size=0\nport=%d\nlisten-address=127.0.0.1\nbind-interfaces\nuser=root\nserver=127.0.0.1#%d\nserver=/private.test/127.0.0.1#%d\nserver=/direct.test/#\nlocal=/home.arpa/\nhost-record=known.home.arpa,192.0.2.99\nservers-file=%s\n", port, direct.port, private.port, managed)
	if mark := os.Getenv("DNSMASQ_TEST_MARK"); mark != "" {
		if strings.ContainsAny(mark, "\r\n") {
			return fmt.Errorf("invalid DNSMASQ_TEST_MARK")
		}
		text += "mark=" + mark + "\n"
	}
	if ubusObject != "" {
		text += "enable-ubus=" + ubusObject + "\n"
	}
	if err = os.WriteFile(conf, []byte(text), 0600); err != nil {
		return err
	}
	if output, err := exec.Command(binary, "--test", "--conf-file="+conf).CombinedOutput(); err != nil {
		return fmt.Errorf("config validation: %w: %s", err, output)
	}
	logfile, err := os.Create(filepath.Join(dir, "daemon.log"))
	if err != nil {
		return err
	}
	defer logfile.Close()
	cmd := exec.Command(binary, "--keep-in-foreground", "--conf-file="+conf, "--pid-file=", "--log-facility=-")
	cmd.Stdout = logfile
	cmd.Stderr = logfile
	if err = cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	ready := false
	for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); {
		if reply, e := query(port, "startup.test", 1, false, 200*time.Millisecond); e == nil {
			if marker, e := responseMarker(reply); e == nil && marker == 11 {
				ready = true
				break
			}
		}
		select {
		case e := <-done:
			done <- e
			data, _ := os.ReadFile(logfile.Name())
			return fmt.Errorf("native daemon exited: %v: %s", e, data)
		default:
		}
	}
	if !ready {
		return fmt.Errorf("native daemon did not become ready")
	}
	reload := func() error {
		if ubusObject == "" {
			return cmd.Process.Signal(syscall.SIGHUP)
		}
		output, e := exec.Command("ubus", "-t", "10", "call", ubusObject, "reload_servers").CombinedOutput()
		if e != nil {
			return fmt.Errorf("UBus reload_servers: %w: %s", e, output)
		}
		return nil
	}
	checks := 0
	assertRoute := func(name string, kind uint16, tcp bool, want byte) error {
		before := [3]int{direct.count(name), proxy.count(name), private.count(name)}
		response, err := query(port, name, kind, tcp, time.Second)
		if err != nil {
			return fmt.Errorf("%s type=%d tcp=%v: %w", name, kind, tcp, err)
		}
		marker, err := responseMarker(response)
		if err != nil || marker != want {
			return fmt.Errorf("%s type=%d tcp=%v marker=%d want=%d: %v", name, kind, tcp, marker, want, err)
		}
		after := [3]int{direct.count(name), proxy.count(name), private.count(name)}
		for i, m := range []byte{11, 22, 33} {
			delta := after[i] - before[i]
			if (m == want && delta < 1) || (m != want && delta != 0) {
				return fmt.Errorf("%s wrong upstream counters before=%v after=%v", name, before, after)
			}
		}
		checks++
		return nil
	}
	cases := []struct {
		name string
		want byte
	}{
		{"olvbkozcufcbptfogatw.supabase.co", 11}, {"suffix.test", 22}, {"child.suffix.test", 22}, {"notsuffix.test", 11},
		{"exact.test", 22}, {"EXACT.TEST", 22}, {"child.exact.test", 11}, {"proxy12.exact.test", 22},
		{"github-production-release-asset-aB09Z1.s3.amazonaws.com", 22}, {"github-production-release-asset-abcde.s3.amazonaws.com", 11}, {"github-production-release-asset-abcdefg.s3.amazonaws.com", 11}, {"unrelated.s3.amazonaws.com", 11},
		{"chatgpt-async-webps-prod-abc-def-12.webpubsub.azure.com", 22}, {"chatgpt-async-webps-prod-abc-def-x.webpubsub.azure.com", 11}, {"unrelated.webpubsub.azure.com", 11},
		{"child.private.test", 33}, {"child.direct.test", 11}, {"known.home.arpa", 99},
	}
	for _, c := range cases {
		for _, tcp := range []bool{false, true} {
			if err = assertRoute(c.name, 1, tcp, c.want); err != nil {
				return err
			}
		}
	}
	for _, kind := range []uint16{28, 16} {
		for _, tcp := range []bool{false, true} {
			if err = assertRoute("exact.test", kind, tcp, 22); err != nil {
				return err
			}
			if err = assertRoute("plain-type.test", kind, tcp, 11); err != nil {
				return err
			}
		}
	}
	for _, tcp := range []bool{false, true} {
		response, e := query(port, "unknown.home.arpa", 1, tcp, time.Second)
		if e != nil {
			return e
		}
		if len(response) < 12 || response[3]&15 != 3 {
			return fmt.Errorf("unknown local name not NXDOMAIN")
		}
		if direct.count("unknown.home.arpa")+proxy.count("unknown.home.arpa")+private.count("unknown.home.arpa") != 0 {
			return fmt.Errorf("local query reached upstream")
		}
		checks++
	}
	for i := 0; i < 8; i++ {
		revision := 1
		if i%2 == 1 {
			revision = 0
		}
		if err = writeSelectors(managed, proxy.port, revision); err != nil {
			return err
		}
		if err = reload(); err != nil {
			return err
		}
		probe := "new-ready.test"
		if revision == 0 {
			probe = "exact.test"
		}
		applied := false
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
			reply, e := query(port, probe, 1, false, 200*time.Millisecond)
			if e == nil {
				marker, e := responseMarker(reply)
				if e == nil && marker == 22 {
					applied = true
					break
				}
			}
			if ubusObject != "" {
				return fmt.Errorf("reload %d acknowledged before the new policy was observable", i)
			}
		}
		if !applied {
			return fmt.Errorf("reload %d not applied", i)
		}
		old, new := byte(11), byte(22)
		if revision == 0 {
			old, new = 22, 11
		}
		if err = assertRoute("exact.test", 1, false, old); err != nil {
			return err
		}
		if err = assertRoute("new-proxy.test", 1, true, new); err != nil {
			return err
		}
		if err = assertRoute("after-reload-direct.test", 1, false, 11); err != nil {
			return err
		}
	}
	// Malformed reload must retain the whole active policy, including entries
	// parsed successfully before the bad line in the replacement file.
	bad := fmt.Sprintf("server=/regex:^partial[.]test$/127.0.0.1#%d\nserver=/regex:[bad/127.0.0.1#%d\n", proxy.port, proxy.port)
	if err = os.WriteFile(managed, []byte(bad), 0600); err != nil {
		return err
	}
	if err = reload(); ubusObject != "" {
		if err == nil {
			return fmt.Errorf("UBus acknowledged malformed selectors")
		}
	} else if err != nil {
		return err
	}
	rejected := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		data, _ := os.ReadFile(logfile.Name())
		if strings.Contains(string(data), "servers-file reload rejected") {
			rejected = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !rejected {
		return fmt.Errorf("malformed reload not rejected")
	}
	if err = assertRoute("exact.test", 1, false, 22); err != nil {
		return err
	}
	if err = assertRoute("partial.test", 1, true, 11); err != nil {
		return err
	}
	proxy.stop()
	failure := make(chan error, 1)
	go func() {
		reply, e := query(port, "proxy99.exact.test", 1, false, 700*time.Millisecond)
		if e == nil && len(reply) >= 12 && reply[3]&15 == 0 {
			failure <- fmt.Errorf("protected query succeeded with proxy upstream stopped")
		} else {
			failure <- nil
		}
	}()
	if err = assertRoute("direct-after-proxy-stop.test", 1, false, 11); err != nil {
		return err
	}
	if err = <-failure; err != nil {
		return err
	}
	if direct.count("proxy99.exact.test") != 0 || private.count("proxy99.exact.test") != 0 {
		return fmt.Errorf("protected query fell back to direct upstream")
	}
	checks++
	reloadMode := "HUP"
	if ubusObject != "" {
		reloadMode = "UBus-ack"
	}
	fmt.Printf("PASS: %d UDP/TCP/AAAA/TXT/local/upstream-counter/%s/failure checks\n", checks, reloadMode)
	return nil
}
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: transport DNSMASQ_BINARY")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
