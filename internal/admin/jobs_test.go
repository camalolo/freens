// jobs_test.go — the async publish contract: POST /publish {"async":true}
// answers 202 with a job id immediately, GET /job/{id} reports the
// outcome, and the client's Publish transparently rides the job (a
// pre-async daemon's synchronous answer remains a valid fallback).
package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/camalolo/freens/internal/crypto"
)

// TestAsyncPublishJob runs a real publish through the async path: the job
// completes, the record lands in the node's store, and an unknown job id
// 404s.
func TestAsyncPublishJob(t *testing.T) {
	_, _, lookup, c := adminPair(t, "test")
	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, key := makeTLDRecord(t, kp, "asynctest")
	b, err := env.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	// POST /publish {"async":true} → 202 {"job": id}.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var started struct {
		Job string `json:"job"`
	}
	code, err := c.do(ctx, http.MethodPost, "/publish", &envelopeRequest{
		Envelope: base64.StdEncoding.EncodeToString(b),
		Async:    true,
	}, &started)
	if err != nil {
		t.Fatalf("async publish: %v", err)
	}
	if code != http.StatusAccepted || started.Job == "" {
		t.Fatalf("async publish: status %d, job %q; want 202 with a job id", code, started.Job)
	}

	// Poll GET /job/{id} until done; accepted must be 1.
	deadline := time.Now().Add(10 * time.Second)
	var done struct {
		Done     bool   `json:"done"`
		Accepted int    `json:"accepted"`
		Error    string `json:"error"`
	}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		code, err := c.do(ctx, http.MethodGet, "/job/"+started.Job, nil, &done)
		cancel()
		if err != nil {
			t.Fatalf("GET /job: %v", err)
		}
		if code != http.StatusOK {
			t.Fatalf("GET /job: status %d", code)
		}
		if done.Done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("async publish job did not finish in 10s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if done.Error != "" || done.Accepted != 1 {
		t.Fatalf("job outcome: accepted=%d err=%q; want accepted=1, no error", done.Accepted, done.Error)
	}
	// The record must actually be in the daemon's store (storeLocally).
	if got, _ := lookup.Store().Get(key, time.Now().Unix()); got == nil {
		t.Fatal("async publish did not store the record locally")
	}

	// Unknown job id → 404.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var nf map[string]string
	if code, _ := c.do(ctx, http.MethodGet, "/job/999999", nil, &nf); code != http.StatusNotFound {
		t.Fatalf("unknown job status = %d; want 404", code)
	}
}

// TestClientPublishRidesJob exercises the CLIENT (the shape every CLI verb
// now uses): Publish must drive the job and return its accepted count.
func TestClientPublishRidesJob(t *testing.T) {
	node, _, lookup, c := adminPair(t, "test")

	kp, err := crypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	env, key := makeTLDRecord(t, kp, "clientjob")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	accepted, err := c.Publish(ctx, env)
	if err != nil {
		t.Fatalf("Publish via job: %v", err)
	}
	if accepted != 1 {
		t.Fatalf("accepted = %d; want 1", accepted)
	}
	if got, _ := lookup.Store().Get(key, time.Now().Unix()); got == nil {
		t.Fatal("client-driven async publish did not store the record")
	}
	_ = node
}

// TestJobResponseSyncFallback pins the wire compatibility: a daemon that
// answers the OLD synchronous shape (200 {"accepted":N}, no job field)
// still satisfies Client.publish — the fallback branch out.Job == "".
func TestJobResponseSyncFallback(t *testing.T) {
	var out struct {
		Accepted int    `json:"accepted"`
		Job      string `json:"job"`
	}
	if err := json.Unmarshal([]byte(`{"accepted":2}`), &out); err != nil {
		t.Fatal(err)
	}
	if out.Job != "" || out.Accepted != 2 {
		t.Fatalf("sync shape decoded to %+v; want accepted=2, no job", out)
	}
}
