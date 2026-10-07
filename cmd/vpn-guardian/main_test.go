package main

import "testing"

func TestDispatchRejectsMissingAndInvalidArguments(t *testing.T) {
	tests := [][]string{nil, {}, {"unknown"}, {"stack"}, {"restore"}, {"restore", "a", "b"}, {"bootstrap", "--invalid"}, {"selftest", "extra"}, {"api-key"}, {"api-key", "create"}}
	for _, args := range tests {
		if err := run(args); err == nil {
			t.Errorf("run(%q) unexpectedly succeeded", args)
		}
	}
}
