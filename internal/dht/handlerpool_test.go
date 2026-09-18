package dht

// handlerpool_test.go — the heavy-handler worker pool (put/witness/
// blob.get off the single-threaded read loop) with inline fallback when
// the pool is saturated: backpressure degrades to the old behavior, it
// never drops a peer's packet.

import (
	"context"
	"testing"
	"time"
)

func TestHeavyHandlerPoolSaturatedFallsBackInline(t *testing.T) {
	srv := startFlagTestNode(t, false)
	cli := startFlagTestNode(t, false)

	// Swap in an UNBUFFERED pool with no workers: dispatchHeavy can never
	// deliver (no receiver ever ready), so every heavy query determinis-
	// tically exercises the inline fallback. (Stuffing the real queue
	// with blocking fillers cannot do this deterministically — a queued
	// task sits FIFO behind the fillers instead of falling back, which is
	// the correct bounded-queue behavior, just not what this test pins.)
	srv.mu.Lock()
	srv.handlerPool = make(chan func()) // unbuffered, workerless ⇒ always saturated
	srv.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := srv.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	// A put: the gate sequence answers 302 (invalid token) — ANY
	// structured response proves the handler ran inline despite the
	// unusable pool.
	resp, err := cli.sendQuery(ctx, addr, srv.ID(), "put", map[string]any{})
	if err != nil {
		t.Fatalf("put under a saturated pool: %v (inline fallback must answer)", err)
	}
	if resp == nil {
		t.Fatal("nil response under a saturated pool")
	}
	if code, _ := asUint64(resp.A["code"]); code != 302 {
		t.Fatalf("inline put code = %d, want 302", code)
	}
}

func TestHeavyHandlerPoolDispatches(t *testing.T) {
	srv := startFlagTestNode(t, false)
	if srv.handlerPool == nil {
		t.Fatal("Start did not start the handler pool")
	}
	// A normal put round trip still answers with the pool active (the
	// task took the pooled path — nothing observable distinguishes it,
	// so this pins the non-regression: pooled answers still arrive).
	cli := startFlagTestNode(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := srv.LocalAddr()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.sendQuery(ctx, addr, srv.ID(), "put", map[string]any{})
	if err != nil || resp == nil {
		t.Fatalf("pooled put round trip: %v", err)
	}
	if code, _ := asUint64(resp.A["code"]); code != 302 {
		t.Fatalf("pooled put code = %d, want 302 (invalid token)", code)
	}
}
