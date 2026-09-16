// jobs.go — the async job runner (register's PoW+witness+publish takes up
// to ~a minute; the browser polls /api/job/{id} for a live progress card).
// At most one job runs at a time (a second start is refused) — keychain
// writes must not race.
package webui

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// job is one background operation.
type job struct {
	ID      string
	Label   string
	Started time.Time
	Done    bool
	Err     string
	Result  any

	mu    sync.Mutex
	steps []string // newest last
	pct   int
}

// jobStepView is a rendered step line (class drives the styling).
type jobStepView struct {
	Text  string
	Class string // done|current|""
}

// startJob refuses concurrency and returns the new job's ID.
func (s *Server) startJob(label string, run func(ctx context.Context, progress func(string)) (any, error)) string {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if j := s.runningLocked(); j != nil {
		return j.ID // a job is already running: attach to it
	}
	// Bound the map: finished jobs are pruned on dashboard render
	// (recentJobs), but a UI that never visits the dashboard would grow
	// the map forever — drop hour-old finished jobs past a floor here too.
	if len(s.jobs) > maxJobsRetained {
		cutoff := time.Now().Add(-time.Hour)
		for id, j := range s.jobs {
			if done, _ := j.state(); done && j.Started.Before(cutoff) {
				delete(s.jobs, id)
			}
		}
	}
	s.jobSeq++
	j := &job{ID: strconv.Itoa(s.jobSeq), Label: label, Started: time.Now()}
	s.jobs[j.ID] = j
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		j.mu.Lock()
		j.steps = []string{"started"}
		j.pct = 5
		j.mu.Unlock()
		res, err := run(ctx, func(msg string) {
			j.mu.Lock()
			j.steps = append(j.steps, msg)
			j.pct = min(j.pct+20, 90)
			j.mu.Unlock()
		})
		j.mu.Lock()
		j.Done = true
		if err != nil {
			j.Err = err.Error()
		} else {
			j.Result = res
			j.pct = 100
			j.steps = append(j.steps, "finished")
		}
		j.mu.Unlock()
	}()
	return j.ID
}

// maxJobsRetained bounds the jobs map between dashboard renders (startJob
// prunes hour-old finished jobs past this floor; recentJobs prunes on every
// render regardless).
const maxJobsRetained = 64

func (s *Server) job(id string) *job {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	return s.jobs[id]
}

func (s *Server) runningLocked() *job {
	// Caller holds jobsMu. Done is still read through j.state(): the
	// runner owns it under j.mu, and jobsMu does not cover it.
	for _, j := range s.jobs {
		if done, _ := j.state(); !done {
			return j
		}
	}
	return nil
}

// latestJob returns the most recently started job (finished or not) for the
// register page's re-attach. Only the runner-IMMUTABLE fields (ID/Label/
// Started — all set before the job enters the map) are read here.
func (s *Server) latestJob() *job {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	var out *job
	for _, j := range s.jobs {
		if out == nil || j.Started.After(out.Started) {
			out = j
		}
	}
	return out
}

// recentJobs renders the dashboard's list (newest first, max 5, finished
// older than an hour are pruned).
func (s *Server) recentJobs() []recentJob {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	var out []recentJob
	var ids []*job
	for _, j := range s.jobs {
		if time.Since(j.Started) > time.Hour {
			delete(s.jobs, j.ID)
			continue
		}
		ids = append(ids, j)
	}
	// newest first (insertion sort; job count is tiny)
	for i := 1; i < len(ids); i++ {
		for k := i; k > 0 && ids[k].Started.After(ids[k-1].Started); k-- {
			ids[k], ids[k-1] = ids[k-1], ids[k]
		}
	}
	for i, j := range ids {
		if i == 5 {
			break
		}
		done, jobErr := j.state() // snapshot the runner-owned fields under j.mu
		state := "running"
		if done {
			if jobErr != "" {
				state = "failed"
			} else {
				state = "done"
			}
		}
		out = append(out, recentJob{When: j.Started.Format("15:04:05"), Label: j.Label, State: state})
	}
	return out
}

// jobView is the jobfragment template's data. The polled fragment endpoint
// (renderJobFragment) and the register page's inline render share it — the
// page MUST pass THIS, not the page data: jobfragment evaluates fields the
// page struct does not have, and a missing struct field is a template
// EXECUTION error (the v0.6.0-era inline call passed registerPageData, so
// every re-attached progress card 500'd with "render error" — found live
// 2026-09-04, the first real browser registration attempt).
type jobView struct {
	JobID     string
	JobLabel  string
	JobPct    int
	JobDone   bool
	JobError  string
	JobResult *RegisterResult
	JobSteps  []jobStepView
}

// state snapshots the runner-owned fields (Done/Err) under the job's own
// mutex. The runner writes them in its final critical section; readers that
// hold only jobsMu (recentJobs, runningLocked, the startJob pruner) must go
// through here — two mutexes guarding one field is exactly the shape -race
// flags on every dashboard render.
func (j *job) state() (done bool, errText string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Done, j.Err
}

// viewOf snapshots j's render state under its mutex (the runner writes
// steps/pct/Err/Result in its final critical section).
func (s *Server) viewOf(j *job) jobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	steps := make([]jobStepView, 0, len(j.steps))
	for i, st := range j.steps {
		v := jobStepView{Text: st}
		if j.Done {
			v.Class = "done"
		} else if i == len(j.steps)-1 {
			v.Class = "current"
		} else {
			v.Class = "done"
		}
		steps = append(steps, v)
	}
	var res *RegisterResult
	if rr, ok := j.Result.(*RegisterResult); ok { // read under j.mu: the runner writes Result in its final critical section
		res = rr
	}
	return jobView{
		JobID:     j.ID,
		JobLabel:  j.Label,
		JobPct:    j.pct,
		JobDone:   j.Done,
		JobError:  j.Err,
		JobResult: res,
		JobSteps:  steps,
	}
}

// renderJobFragment executes the jobfragment template standalone.
func (s *Server) renderJobFragment(w http.ResponseWriter, j *job) {
	s.fragment(w, "jobfragment", s.viewOf(j))
}

// fragment renders a named fragment template (not a full layout) — for
// htmx swaps. Fragments are parsed on demand and cached like pages.
func (s *Server) fragment(w http.ResponseWriter, name string, data any) {
	t, ok := pageTemplates[name]
	if !ok {
		http.Error(w, "no such fragment", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store") // see render(): stale HTML lies
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("webui: fragment", "tpl", name, "err", err)
	}
}

// ops builds the operations environment (kept per-call: cheap).
func (s *Server) ops() *opsEnv {
	return &opsEnv{keysDir: s.keysDir, d: s.d}
}

// ctxBg is a background context alias for version() display calls.
func ctxBg() context.Context { return context.Background() }
