package netstate

import (
	"strings"
	"testing"
)

func TestScanProcNetTCPListening(t *testing.T) {
	const sample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4EC5 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
   1: 0100007F:CC7A 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12346 1
`
	if !scanProcNet(strings.NewReader(sample), 20165, true) {
		t.Fatal("expected listening TCP port to be detected")
	}
	if scanProcNet(strings.NewReader(sample), 52346, true) {
		t.Fatal("established TCP socket must not count as a listener")
	}
}

func TestScanProcNetUDPBound(t *testing.T) {
	const sample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  42: 00000000:CC7A 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 23456 2
`
	if !scanProcNet(strings.NewReader(sample), 52346, false) {
		t.Fatal("expected bound UDP port to be detected")
	}
}

func TestScanProcNetIgnoresOtherPorts(t *testing.T) {
	const sample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:4EC5 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1
`
	if scanProcNet(strings.NewReader(sample), 52346, true) {
		t.Fatal("unexpected port match")
	}
}
