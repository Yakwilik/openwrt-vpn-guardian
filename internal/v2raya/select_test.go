package v2raya

import (
	"context"
	"testing"
	"time"
)

func TestSelectWaitsForIdentityNotListeningSocket(t *testing.T) {
	want := Candidate{Key: "sub:stable", TouchID: 27, Sub: 1, Name: "wanted"}
	fresh := want
	fresh.TouchID = 14
	old := Candidate{Key: "sub:old", TouchID: 2, Sub: 1, Name: "old"}
	reads := 0
	requests := 0
	read := func(context.Context) (selectionSnapshot, error) {
		reads++
		active := NodeTouch{ID: old.TouchID, Sub: old.Sub}
		if reads >= 3 {
			active = NodeTouch{ID: fresh.TouchID, Sub: fresh.Sub}
		}
		return selectionSnapshot{Nodes: []Candidate{old, fresh}, Active: active, Connected: true}, nil
	}
	send := func(_ context.Context, c Candidate) error {
		requests++
		if c.TouchID != 14 || c.Key != want.Key {
			t.Fatalf("stale index sent: %+v", c)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := selectConfirmed(ctx, want, read, send, func(context.Context) bool { return true })
	if err != nil || got.Key != want.Key || reads < 3 || requests != 1 {
		t.Fatalf("selection = %+v reads=%d requests=%d err=%v", got, reads, requests, err)
	}
}
func TestSelectRejectsWrongIdentityWithSameName(t *testing.T) {
	want := Candidate{Key: "wanted", TouchID: 1, Name: "same-name"}
	wrong := Candidate{Key: "wrong", TouchID: 2, Name: "same-name"}
	read := func(context.Context) (selectionSnapshot, error) {
		return selectionSnapshot{Nodes: []Candidate{want, wrong}, Active: NodeTouch{ID: 2}, Connected: true}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := selectConfirmed(ctx, want, read, func(context.Context, Candidate) error { return nil }, func(context.Context) bool { return true }); err == nil {
		t.Fatal("wrong node accepted")
	}
}
func TestNodeIdentityIgnoresOrderAndDisplayMetadata(t *testing.T) {
	a := stableNodeKey(2, `{"serverObj":{"protocol":"vless","add":"node.example","port":443,"id":"credential","ps":"old"},"pingLatency":"1ms"}`)
	b := stableNodeKey(2, `{"serverObj":{"ps":"renamed","port":443,"add":"node.example","protocol":"vless","id":"credential"}}`)
	if a == "" || a != b {
		t.Fatalf("unstable identity %s %s", a, b)
	}
	c := stableNodeKey(3, `{"protocol":"vless","add":"node.example","port":443}`)
	if c == a {
		t.Fatal("subscription identity lost")
	}
	d := stableNodeKey(2, `{"protocol":"vless","add":"node.example","port":443,"id":"different-credential"}`)
	if d == a {
		t.Fatal("different credentials must not collapse into same node identity")
	}
}
