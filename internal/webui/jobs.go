// jobs.go — the async job runner (register's PoW+witness+publish takes up
// to ~a minute; the browser polls /api/job/{id} for a live progress card).
// At most one job runs at a time (a second start is refused) — keychain
// writes must not race.
package webui

import (
	"context"
	"net/http"
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
	s.jobSeq++
	j := &job{ID: itoa(s.jobSeq), Label: label, Started: time.Now()}
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

func (s *Server) job(id string) *job {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	return s.jobs[id]
}

func (s *Server) runningLocked() *job {
	for _, j := range s.jobs {
		if !j.Done {
			return j
		}
	}
	return nil
}

// latestJob returns the most recently started job (finished or not) for the
// register page's re-attach.
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
		state := "running"
		if j.Done {
			if j.Err != "" {
				state = "failed"
			} else {
				state = "done"
			}
		}
		out = append(out, recentJob{When: j.Started.Format("15:04:05"), Label: j.Label, State: state})
	}
	return out
}

// renderJobFragment executes the jobfragment template standalone.
func (s *Server) renderJobFragment(w http.ResponseWriter, j *job) {
	j.mu.Lock()
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
	pct := j.pct
	errText := j.Err
	done := j.Done
	j.mu.Unlock()

	var res *RegisterResult
	if rr, ok := j.Result.(*RegisterResult); ok {
		res = rr
	}
	data := struct {
		JobID     string
		JobLabel  string
		JobPct    int
		JobDone   bool
		JobError  string
		JobResult *RegisterResult
		JobSteps  []jobStepView
	}{j.ID, j.Label, pct, done, errText, res, steps}
	s.fragment(w, "jobfragment", data)
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ctxBg is a background context alias for version() display calls.
func ctxBg() context.Context { return context.Background() }
