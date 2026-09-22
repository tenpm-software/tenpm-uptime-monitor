package monitor

import (
	"context"
	"log/slog"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

const (
	// reportBatchSize matches the server's per-request cap; reportOnce loops
	// until the buffer is drained rather than sending only one batch per tick.
	reportBatchSize = 500
	// sentRetentionAge is how long already-uploaded rows are kept before
	// being purged, giving a window to debug recent activity from the local DB.
	sentRetentionAge = 7 * 24 * time.Hour
)

// Reporter drains the local results buffer to the server. Rows stay unsent
// (and so get retried next cycle) until the server confirms a batch with
// 2xx; if the server is unreachable, the buffer just grows.
type Reporter struct {
	store    *Store
	client   *Client
	interval time.Duration
	logger   *slog.Logger

	// flushCh, when wired (see agent.go), lets the Runner wake Run
	// immediately on a check's status transition instead of waiting for
	// the next jittered interval. nil - the default for every existing
	// NewReporter call site - just never becomes ready, so Run's select
	// falls back to its two original cases unchanged.
	flushCh chan struct{}
}

func NewReporter(store *Store, client *Client, interval time.Duration, logger *slog.Logger) *Reporter {
	return &Reporter{store: store, client: client, interval: interval, logger: logger}
}

// Run uploads buffered results every interval (jittered ±10%), or
// immediately whenever flushCh signals a check's status transition, until
// ctx is cancelled, purging old already-sent rows once per cycle. On
// cancellation it makes one final drain attempt so a shutdown flushes what
// it can. A triggered flush reports the exact same reportOnce as a
// scheduled one - including intervalSec, still computed from the
// configured interval rather than actual elapsed time - so it changes
// nothing about how the server reads report_interval_sec.
func (r *Reporter) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			r.finalDrain()
			return
		case <-time.After(jitter(r.interval)):
		case <-r.flushCh:
		}

		if err := r.reportOnce(ctx); err != nil {
			r.logger.Error("report results", "error", err)
		}
		if err := r.store.PurgeSentOlderThan(time.Now().Add(-sentRetentionAge)); err != nil {
			r.logger.Error("purge sent results", "error", err)
		}
	}
}

// finalDrain makes one last upload attempt at shutdown so buffered results
// leave with the process when the server is reachable. It needs a short
// detached context because the run context is already cancelled. Failure
// is harmless: rows stay unsent and upload idempotently after the next
// start.
func (r *Reporter) finalDrain() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.reportOnce(ctx); err != nil {
		r.logger.Warn("final result drain failed; unsent rows will upload after restart", "error", err)
	}
}

// reportOnce drains the buffer in capped batches until it's empty or a
// batch fails, so a monitor that's been offline for a while can catch up in
// a single cycle instead of trickling one batch per interval. It always
// calls the server at least once per cycle, even with zero buffered
// results: that empty call is what makes report_interval_sec a real
// heartbeat the server's liveness sweep can rely on, rather than a call
// that only happens when there's something new to say.
func (r *Reporter) reportOnce(ctx context.Context) error {
	intervalSec := int(r.interval.Seconds())
	first := true
	for {
		rows, err := r.store.ListUnsent(reportBatchSize)
		if err != nil {
			return err
		}
		if len(rows) == 0 && !first {
			return nil
		}
		first = false

		results := make([]model.Result, len(rows))
		ids := make([]int64, len(rows))
		for i, row := range rows {
			results[i] = row.result
			ids[i] = row.id
		}

		if _, err := r.client.PostResults(ctx, results, intervalSec); err != nil {
			return err
		}
		if err := r.store.MarkSent(ids); err != nil {
			return err
		}

		if len(rows) < reportBatchSize {
			return nil
		}
	}
}
