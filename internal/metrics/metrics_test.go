package metrics

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestRegistryGoldenFormat pins the exact exposition output: HELP/TYPE header
// per family, families sorted by name, series sorted by label values, HELP and
// label-value escaping, unlabeled series without braces.
func TestRegistryGoldenFormat(t *testing.T) {
	r := New()
	// Register out of name order to prove WriteTo sorts by metric name.
	q := r.NewCounter("dns_queries_total", "DNS queries answered, by qtype and\nstatus.", "qtype", "status")
	up := r.NewGauge("uptime_seconds", "Seconds since start.")
	hits := r.NewCounter("cache_hits_total", "Cache hits.")

	up.With().Set(12.5)
	hits.With().Inc()
	q.With("A", "noerror").Inc()
	q.With("TXT", "nxdomain").Add(3)
	q.With("A", "servfail").Inc()
	q.With("TXT", "noerror").Inc() // same cell as above? no: distinct label tuple

	var buf bytes.Buffer
	if _, err := r.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	want := strings.Join([]string{
		// cache_hits_total < dns_queries_total < uptime_seconds (name order)
		`# HELP cache_hits_total Cache hits.`,
		`# TYPE cache_hits_total counter`,
		`cache_hits_total 1`,
		`# HELP dns_queries_total DNS queries answered, by qtype and\nstatus.`,
		`# TYPE dns_queries_total counter`,
		// series sorted by (qtype, status) tuple: A/noerror, A/servfail, TXT/noerror, TXT/nxdomain
		`dns_queries_total{qtype="A",status="noerror"} 1`,
		`dns_queries_total{qtype="A",status="servfail"} 1`,
		`dns_queries_total{qtype="TXT",status="noerror"} 1`,
		`dns_queries_total{qtype="TXT",status="nxdomain"} 3`,
		`# HELP uptime_seconds Seconds since start.`,
		`# TYPE uptime_seconds gauge`,
		`uptime_seconds 12.5`,
		``,
	}, "\n")
	if got := buf.String(); got != want {
		t.Errorf("WriteTo output mismatch:\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

// TestLabelValueEscaping checks backslash/newline/quote escaping in label
// values and backslash/newline in HELP.
func TestLabelValueEscaping(t *testing.T) {
	r := New()
	c := r.NewCounter("weird_total", `a \ and a newline`, "l")
	c.With(`v"1\`).Inc()
	var buf bytes.Buffer
	if _, err := r.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	want := `# HELP weird_total a \\ and a newline` + "\n" +
		`# TYPE weird_total counter` + "\n" +
		`weird_total{l="v\"1\\"} 1` + "\n"
	if got := buf.String(); got != want {
		t.Errorf("escaped output mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// TestEmptyRegistryWritesNothing: a registry with families but no touched
// cells still emits HELP/TYPE; a fresh registry emits nothing at all.
func TestEmptyRegistryWritesNothing(t *testing.T) {
	r := New()
	var buf bytes.Buffer
	if _, err := r.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("fresh registry wrote %q, want empty", buf.String())
	}

	r2 := New()
	r2.NewGauge("g", "never set")
	buf.Reset()
	if _, err := r2.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	want := "# HELP g never set\n# TYPE g gauge\n"
	if buf.String() != want {
		t.Errorf("untouched family output = %q, want %q", buf.String(), want)
	}
}

// TestDuplicateNamePanics: registering the same name twice (or as a different
// type) panics.
func TestDuplicateNamePanics(t *testing.T) {
	r := New()
	r.NewCounter("dup_total", "first")
	for _, tc := range []struct {
		desc string
		fn   func()
	}{
		{"counter over counter", func() { r.NewCounter("dup_total", "second") }},
		{"gauge over counter", func() { r.NewGauge("dup_total", "second") }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: expected panic", tc.desc)
				}
			}()
			tc.fn()
		}()
	}
}

// TestInvalidNamesPanics: bad metric names and bad/duplicate label names panic.
func TestInvalidNamesPanics(t *testing.T) {
	r := New()
	cases := []struct {
		desc string
		fn   func()
	}{
		{"metric name with space", func() { r.NewCounter("bad name_total", "x") }},
		{"metric name starting with digit", func() { r.NewCounter("9bad", "x") }},
		{"metric name empty", func() { r.NewCounter("", "x") }},
		{"label name with colon", func() { r.NewCounter("ok_total", "x", "a:b") }},
		{"label name starting with digit", func() { r.NewCounter("ok2_total", "x", "1a") }},
		{"duplicate label name", func() { r.NewCounter("ok3_total", "x", "a", "a") }},
	}
	for _, tc := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: expected panic", tc.desc)
				}
			}()
			tc.fn()
		}()
	}
}

// TestLabelCountValidated: With panics on wrong label value counts, and
// returns the same cell for repeated calls.
func TestLabelCountValidated(t *testing.T) {
	r := New()
	c := r.NewCounter("c_total", "help", "a", "b")
	if cell := c.With("x", "y"); cell != c.With("x", "y") {
		t.Errorf("With should return the same cell for the same label values")
	}
	for _, fn := range []func(){
		func() { c.With("x") },
		func() { c.With("x", "y", "z") },
		func() { c.With() },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("expected panic on wrong label value count")
				}
			}()
			fn()
		}()
	}

	g := r.NewGauge("g", "help", "a")
	func() {
		defer func() {
			if recover() == nil {
				t.Error("gauge: expected panic on wrong label value count")
			}
		}()
		g.With("x", "y")
	}()
}

// TestConcurrentIncAddSet exercises the race-detector path: many goroutines
// creating cells lazily and mutating them while a reader renders. The final
// counter total must equal the number of Inc/Add operations exactly.
func TestConcurrentIncAddSet(t *testing.T) {
	r := New()
	c := r.NewCounter("race_total", "raced counter", "w")
	g := r.NewGauge("race_gauge", "raced gauge", "w")

	const workers, iters = 8, 500
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < iters; n++ {
				c.With(fmt.Sprintf("w%d", i%4)).Inc()
				g.With(fmt.Sprintf("w%d", i%4)).Set(float64(n))
				if n%100 == 0 {
					var buf bytes.Buffer
					_, _ = r.WriteTo(&buf)
				}
			}
		}(i)
	}
	wg.Wait()

	// workers*iters increments spread over 4 label values.
	var total float64
	for i := 0; i < 4; i++ {
		total += c.With(fmt.Sprintf("w%d", i)).value()
	}
	if total != workers*iters {
		t.Errorf("counter total = %v, want %v", total, workers*iters)
	}
}

// TestNilRegistry: instruments obtained from NilRegistry work (accept
// mutations without panic) and WriteTo emits nothing.
func TestNilRegistry(t *testing.T) {
	r := NilRegistry()
	c := r.NewCounter("nil_total", "help", "l")
	c.With("v").Inc()
	g := r.NewGauge("nil_gauge", "help")
	g.With().Set(1)
	// Duplicate names on a nil registry must not panic (nothing is tracked).
	r.NewCounter("nil_total", "again")
	var buf bytes.Buffer
	if _, err := r.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("NilRegistry wrote %q, want empty", buf.String())
	}
}

// TestFloatFormatting pins sample-value rendering for integers, fractions,
// large values, Inf, and NaN.
func TestFloatFormatting(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{4096, "4096"},
		{0.5, "0.5"},
		{1e9, "1e+09"},
		{inf(1), "+Inf"},
	} {
		if got := formatValue(tc.in); got != tc.want {
			t.Errorf("formatValue(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func inf(sign int) float64 {
	var z float64
	if sign < 0 {
		return -1 / z
	}
	return 1 / z
}
