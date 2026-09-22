package monitor

import (
	"context"
	"log/slog"
	"time"
)

// Syncer periodically pulls the check-set delta from the server and applies
// it to the local mirror.
type Syncer struct {
	store    *Store
	client   *Client
	interval time.Duration
	logger   *slog.Logger
}

func NewSyncer(store *Store, client *Client, interval time.Duration, logger *slog.Logger) *Syncer {
	return &Syncer{store: store, client: client, interval: interval, logger: logger}
}

// Run polls every interval (jittered ±10% so many monitors don't thunder-herd
// the server in lockstep) until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(s.interval)):
		}
		if err := s.syncOnce(ctx); err != nil {
			s.logger.Error("sync checks", "error", err)
		}
	}
}

// WaitForInitialSync blocks, retrying with exponential backoff, until the
// first sync succeeds or ctx is cancelled. The runner has nothing to
// execute and the reporter nothing meaningful to report until the local
// check mirror reflects the server at least once.
func (s *Syncer) WaitForInitialSync(ctx context.Context) error {
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		if err := s.syncOnce(ctx); err == nil {
			return nil
		} else {
			s.logger.Warn("initial sync failed, retrying", "error", err, "retry_in", backoff)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (s *Syncer) syncOnce(ctx context.Context) error {
	since, err := s.store.GetLastSyncedAt()
	if err != nil {
		return err
	}

	serverTime, checks, err := s.client.FetchChecks(ctx, since)
	if err != nil {
		return err
	}

	if err := s.store.ApplyChecksDelta(checks, serverTime); err != nil {
		return err
	}
	if len(checks) > 0 {
		s.logger.Info("synced checks", "count", len(checks))
	}
	return nil
}
