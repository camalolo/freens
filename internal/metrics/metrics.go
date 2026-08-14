// Package metrics is a hand-rolled, dependency-free Prometheus text-exposition
// registry (format version 0.0.4). It provides counters and gauges with
// optional label dimensions, lazy per-label-value cell creation, and a
// thread-safe WriteTo that renders the canonical "# HELP / # TYPE / series"
// layout: metric families sorted by name, series within a family sorted by
// label values.
//
// A nil-safe no-op registry is available via NilRegistry so instrumented
// call sites never need `if metrics != nil` guards.
//
// Counters follow the modern exposition convention: callers name them with a
// "_total" suffix (the package does not auto-suffix).
package metrics

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// metricNameRE is the Prometheus metric-name grammar (colon allowed for
// recording-rule-style names).
var metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// labelNameRE is the Prometheus label-name grammar (no colons).
var labelNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Registry holds a set of metric families. It is safe for concurrent use:
// registration is guarded by a mutex, and each family's cells carry their own
// locks, so the hot Inc/Add/Set path never contends with WriteTo.
type Registry struct {
	mu     sync.Mutex
	fams   []*family // creation order; WriteTo sorts by name
	byName map[string]bool
	noop   bool // true for NilRegistry: instruments work, nothing is retained
}

// family is one named metric (a Counter or a Gauge) plus its type tag.
type family struct {
	name string
	help string
	typ  string // "counter" or "gauge"
	c    *Counter
	g    *Gauge
}

// New returns an empty, usable Registry.
func New() *Registry {
	return &Registry{byName: map[string]bool{}}
}

// NilRegistry returns a no-op registry: NewCounter/NewGauge return working
// (untracked) instruments, and WriteTo emits nothing. Passing it to a SetMetrics
// hook disables metrics without requiring nil guards at the call sites.
func NilRegistry() *Registry {
	return &Registry{noop: true}
}

// Compile-time check that Registry satisfies io.WriterTo.
var _ io.WriterTo = (*Registry)(nil)

// validateName checks the metric name grammar and rejects duplicates.
func (r *Registry) validateName(name string) {
	if !metricNameRE.MatchString(name) {
		panic(fmt.Sprintf("metrics: invalid metric name %q", name))
	}
	if r.byName[name] {
		panic(fmt.Sprintf("metrics: duplicate metric name %q", name))
	}
}

func validateLabelNames(name string, labelNames []string) {
	seen := map[string]bool{}
	for _, l := range labelNames {
		if !labelNameRE.MatchString(l) {
			panic(fmt.Sprintf("metrics: metric %q: invalid label name %q", name, l))
		}
		if seen[l] {
			panic(fmt.Sprintf("metrics: metric %q: duplicate label name %q", name, l))
		}
		seen[l] = true
	}
}

// NewCounter registers a counter metric. Counters must be named with a
// "_total" suffix by the caller (the exposition format's series-name
// convention); this package does not auto-suffix. It panics on an invalid or
// duplicate name.
func (r *Registry) NewCounter(name, help string, labelNames ...string) *Counter {
	c := &Counter{name: name, help: help, labels: append([]string(nil), labelNames...), cells: map[string]*counterCell{}}
	if r.noop {
		return c
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.validateName(name)
	validateLabelNames(name, labelNames)
	r.byName[name] = true
	r.fams = append(r.fams, &family{name: name, help: help, typ: "counter", c: c})
	return c
}

// NewGauge registers a gauge metric. It panics on an invalid or duplicate
// name.
func (r *Registry) NewGauge(name, help string, labelNames ...string) *Gauge {
	g := &Gauge{name: name, help: help, labels: append([]string(nil), labelNames...), cells: map[string]*gaugeCell{}}
	if r.noop {
		return g
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.validateName(name)
	validateLabelNames(name, labelNames)
	r.byName[name] = true
	r.fams = append(r.fams, &family{name: name, help: help, typ: "gauge", g: g})
	return g
}

// WriteTo renders the registry in the Prometheus text exposition format
// (version 0.0.4): families sorted by metric name, series within a family
// sorted by label values. HELP text is escaped per the spec (backslash and
// newline); label values are escaped for backslash, newline, and quote.
//
// It implements [io.WriterTo] (the conventional (int64, error) signature —
// a bare `error` return trips go vet's stdmethods check), which also lets the
// registry be passed straight to io.Copy.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	fams := append([]*family(nil), r.fams...)
	r.mu.Unlock()
	if r.noop || len(fams) == 0 {
		return 0, nil
	}
	sort.Slice(fams, func(i, j int) bool { return fams[i].name < fams[j].name })

	var buf strings.Builder
	for _, f := range fams {
		fmt.Fprintf(&buf, "# HELP %s %s\n", f.name, escapeHelp(f.help))
		fmt.Fprintf(&buf, "# TYPE %s %s\n", f.name, f.typ)
		if f.c != nil {
			f.c.writeSeries(&buf)
		} else {
			f.g.writeSeries(&buf)
		}
	}
	n, err := io.WriteString(w, buf.String())
	return int64(n), err
}

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

// Counter is a monotonically increasing metric with optional labels. Obtain
// per-label-value cells via With; a nil *Counter is not usable (registries
// always return live values from NewCounter, including NilRegistry).
type Counter struct {
	name   string
	help   string
	labels []string

	mu    sync.Mutex
	cells map[string]*counterCell
}

// counterCell is one series of a counter (a concrete label-value tuple, or the
// single unlabeled series).
type counterCell struct {
	values []string // label values, fixed at creation
	mu     sync.Mutex
	v      float64
}

// With returns the counter cell for the given label values, creating it
// lazily. It panics unless exactly one value per declared label is given.
func (c *Counter) With(labelValues ...string) *counterCell {
	if len(labelValues) != len(c.labels) {
		panic(fmt.Sprintf("metrics: counter %q: got %d label values, want %d", c.name, len(labelValues), len(c.labels)))
	}
	key := strings.Join(labelValues, "\xff")
	c.mu.Lock()
	defer c.mu.Unlock()
	if cell, ok := c.cells[key]; ok {
		return cell
	}
	cell := &counterCell{values: append([]string(nil), labelValues...)}
	c.cells[key] = cell
	return cell
}

// Inc increments the cell by one.
func (c *counterCell) Inc() { c.Add(1) }

// Add increments the cell by v (v >= 0 for a semantically valid counter).
func (c *counterCell) Add(v float64) {
	c.mu.Lock()
	c.v += v
	c.mu.Unlock()
}

// value reads the cell's current value.
func (c *counterCell) value() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.v
}

// writeSeries emits `name{label="value",...} value` lines sorted by label
// values (tuple order, not joined-string order).
func (c *Counter) writeSeries(buf *strings.Builder) {
	c.mu.Lock()
	cells := make([]*counterCell, 0, len(c.cells))
	for _, cell := range c.cells {
		cells = append(cells, cell)
	}
	c.mu.Unlock()
	sortCells(cells)
	for _, cell := range cells {
		writeSeriesLine(buf, c.name, c.labels, cell.values, cell.value())
	}
}

// ---------------------------------------------------------------------------
// Gauge
// ---------------------------------------------------------------------------

// Gauge is a metric that can go up and down, with optional labels.
type Gauge struct {
	name   string
	help   string
	labels []string

	mu    sync.Mutex
	cells map[string]*gaugeCell
}

// gaugeCell is one series of a gauge.
type gaugeCell struct {
	values []string
	mu     sync.Mutex
	v      float64
}

// With returns the gauge cell for the given label values, creating it lazily.
// It panics unless exactly one value per declared label is given.
func (g *Gauge) With(labelValues ...string) *gaugeCell {
	if len(labelValues) != len(g.labels) {
		panic(fmt.Sprintf("metrics: gauge %q: got %d label values, want %d", g.name, len(labelValues), len(g.labels)))
	}
	key := strings.Join(labelValues, "\xff")
	g.mu.Lock()
	defer g.mu.Unlock()
	if cell, ok := g.cells[key]; ok {
		return cell
	}
	cell := &gaugeCell{values: append([]string(nil), labelValues...)}
	g.cells[key] = cell
	return cell
}

// Set sets the cell's value.
func (g *gaugeCell) Set(v float64) {
	g.mu.Lock()
	g.v = v
	g.mu.Unlock()
}

// value reads the cell's current value.
func (g *gaugeCell) value() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.v
}

// writeSeries emits the gauge's series lines sorted by label values.
func (g *Gauge) writeSeries(buf *strings.Builder) {
	g.mu.Lock()
	cells := make([]*gaugeCell, 0, len(g.cells))
	for _, cell := range g.cells {
		cells = append(cells, cell)
	}
	g.mu.Unlock()
	sort.Slice(cells, func(i, j int) bool { return lessValues(cells[i].values, cells[j].values) })
	for _, cell := range cells {
		writeSeriesLine(buf, g.name, g.labels, cell.values, cell.value())
	}
}

// ---------------------------------------------------------------------------
// formatting helpers
// ---------------------------------------------------------------------------

// sortCells orders counter cells by their label values (tuple order).
func sortCells(cells []*counterCell) {
	sort.Slice(cells, func(i, j int) bool { return lessValues(cells[i].values, cells[j].values) })
}

// lessValues reports tuple lexicographic order of two equal-length label
// value slices.
func lessValues(a, b []string) bool {
	for k := range a {
		if a[k] != b[k] {
			return a[k] < b[k]
		}
	}
	return false
}

// writeSeriesLine emits one exposition line: `name{label="value",...} value`
// (braces omitted for unlabeled metrics).
func writeSeriesLine(buf *strings.Builder, name string, labels, values []string, v float64) {
	if len(labels) == 0 {
		fmt.Fprintf(buf, "%s %s\n", name, formatValue(v))
		return
	}
	var parts []string
	for i, l := range labels {
		parts = append(parts, l+`="`+escapeLabelValue(values[i])+`"`)
	}
	fmt.Fprintf(buf, "%s{%s} %s\n", name, strings.Join(parts, ","), formatValue(v))
}

// formatValue renders a sample value per the exposition format (plain ints
// stay plain; Inf/NaN use the format's literals).
func formatValue(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// escapeHelp escapes backslashes and newlines in HELP text per the spec.
func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "\n", `\n`)
}

// escapeLabelValue escapes a label value for double-quoted context.
func escapeLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, `"`, `\"`)
}
