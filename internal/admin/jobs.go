// jobs.go — the admin async-publish registry. A keyed §8.4 publish (the
// K_claim leg walks its own keyspace) can run for tens of seconds on a
// node with a large routing table — longer than any sane HTTP budget — so
// POST /publish accepts {"async":true} and hands the caller a job id to
// poll (GET /job/{id}). The synchronous shape is unchanged: no async field
// means exactly the old behavior (the webui and pre-async CLIs keep
// working unchanged).
package admin

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/camalolo/freens/internal/wire"
)

// jobPublishBudget bounds ONE daemon-side async publish (both keyspace
// legs included). Generous by design: the caller polls, nothing hangs a
// socket open while the walk runs.
const jobPublishBudget = 2 * time.Minute

// jobTTL is how long a finished job stays answerable before the next
// insert prunes it.
const jobTTL = time.Hour

// maxJobs bounds the registry between prunes.
const maxJobs = 64

// adminJob is one async publish's state.
type adminJob struct {
	ID       string
	Kind     string
	Started  time.Time
	Done     bool
	Err      string
	Accepted int
}

// startPublishJob runs the publish core in the background and returns the
// job id to poll.
func (s *Server) startPublishJob(env *wire.SignedEnvelope, claimOnly bool) string {
	s.jobsMu.Lock()
	s.pruneJobsLocked()
	s.jobSeq++
	id := strconv.FormatUint(s.jobSeq, 10)
	j := &adminJob{ID: id, Kind: "publish", Started: time.Now()}
	s.jobs[id] = j
	s.jobsMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), jobPublishBudget)
		defer cancel()
		accepted, _, err := s.runPublish(ctx, env, claimOnly)
		s.jobsMu.Lock()
		defer s.jobsMu.Unlock()
		j.Done = true
		j.Accepted = accepted
		if err != nil {
			j.Err = err.Error()
		}
	}()
	return id
}

// pruneJobsLocked drops finished jobs past the TTL (and, if still over the
// cap, the oldest finished ones). Caller holds jobsMu.
func (s *Server) pruneJobsLocked() {
	now := time.Now()
	for id, j := range s.jobs {
		if j.Done && now.Sub(j.Started) > jobTTL {
			delete(s.jobs, id)
		}
	}
	if len(s.jobs) <= maxJobs {
		return
	}
	var oldest *adminJob
	oldestID := ""
	for id, j := range s.jobs {
		if !j.Done {
			continue
		}
		if oldest == nil || j.Started.Before(oldest.Started) {
			oldest, oldestID = j, id
		}
	}
	if oldestID != "" {
		delete(s.jobs, oldestID)
	}
}

// handleJob answers GET /job/{id} with the job's current state.
func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.jobsMu.Lock()
	j := s.jobs[id]
	var out struct {
		ID       string `json:"id"`
		Kind     string `json:"kind"`
		Done     bool   `json:"done"`
		Accepted int    `json:"accepted"`
		Error    string `json:"error,omitempty"`
	}
	if j != nil {
		out.ID, out.Kind, out.Done, out.Accepted, out.Error = j.ID, j.Kind, j.Done, j.Accepted, j.Err
	}
	s.jobsMu.Unlock()
	if j == nil {
		writeErr(w, http.StatusNotFound, "no such job: "+id)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
