package control

import (
	"strings"
	"testing"
)

func TestSetAllowedTransportsFrontRejectsEmptySelection(t *testing.T) {
	err := SetAllowedTransportsFront(nil)
	if err == nil {
		t.Fatal("empty transport selection must be rejected")
	}
	if !strings.Contains(err.Error(), "selection.allowedTransports") {
		t.Fatalf("unexpected error: %v", err)
	}
}
