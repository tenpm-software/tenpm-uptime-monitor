package monitor

import (
	"hash/fnv"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

// effectiveIntervalSeconds is check-scheduling-plan.md's effective_interval:
// interval_sec scaled by the check's monitor_count, so the union of every
// assigned monitor's own schedule fires the check once per interval_sec in
// aggregate rather than once per interval_sec per monitor. MonitorCount <= 1
// (including the zero value a pre-migration row or an older server that
// hasn't synced this field yet would carry) degenerates to interval_sec
// itself - today's un-round-robined behavior, with no scheduling change.
func effectiveIntervalSeconds(c model.Check) int64 {
	n := int64(c.MonitorCount)
	if n < 1 {
		n = 1
	}
	return int64(c.IntervalSec) * n
}

// checkPhaseSeconds is check-scheduling-plan.md's phase, corrected
// 2026-09-12 for cross-check clustering: rank*interval_sec places this
// monitor's own slot one interval_sec after the previous rank's, and the
// added hash(check.GUID) term - reduced mod effectiveInterval, not
// interval_sec, so it can move a check's whole rotation anywhere across the
// grid, not just within one monitor's own slice of it - rotates two
// different checks sharing the same interval_sec and monitor_count onto
// different slots instead of the identical one rank*interval_sec alone would
// produce. Adding the same hash offset to every rank of one check only
// rotates that check's whole schedule in time; the interval_sec spacing
// between its own monitors is unaffected.
func checkPhaseSeconds(c model.Check, effectiveInterval int64) int64 {
	if effectiveInterval <= 0 {
		return 0
	}
	rankOffset := int64(c.MonitorRank) * int64(c.IntervalSec)
	h := fnv.New32a()
	_, _ = h.Write([]byte(c.GUID)) // fnv32a.Write never errors
	hashOffset := int64(h.Sum32()) % effectiveInterval
	return mod64(rankOffset+hashOffset, effectiveInterval)
}

// nextSlotAfter returns the smallest epoch-anchored slot (phase,
// phase+effectiveInterval, phase+2*effectiveInterval, ... measured from the
// Unix epoch) that is >= now - check-scheduling-plan.md's "epoch-anchored
// grid" rather than "time since this monitor started", which is what lets
// every monitor assigned to a check agree on the same global slot with no
// direct coordination between them.
func nextSlotAfter(now time.Time, phase, effectiveInterval int64) time.Time {
	if effectiveInterval <= 0 {
		return now
	}
	nowSec := now.Unix()
	rem := mod64(nowSec-phase, effectiveInterval)
	if rem == 0 {
		return now
	}
	return time.Unix(nowSec+(effectiveInterval-rem), 0)
}

// mod64 is Go's % with the sign of the divisor rather than the dividend, so
// a negative a (nowSec - phase, when phase exceeds a small test now) still
// lands in [0, n).
func mod64(a, n int64) int64 {
	m := a % n
	if m < 0 {
		m += n
	}
	return m
}
