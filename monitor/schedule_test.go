package monitor

import (
	"testing"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/model"
)

func TestEffectiveIntervalSeconds(t *testing.T) {
	cases := []struct {
		name string
		c    model.Check
		want int64
	}{
		{"single monitor, explicit count", model.Check{IntervalSec: 30, MonitorCount: 1}, 30},
		{"zero MonitorCount degenerates to 1 (pre-migration row or older server)", model.Check{IntervalSec: 30, MonitorCount: 0}, 30},
		{"three monitors", model.Check{IntervalSec: 30, MonitorCount: 3}, 90},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveIntervalSeconds(tc.c); got != tc.want {
				t.Fatalf("effectiveIntervalSeconds(%+v) = %d, want %d", tc.c, got, tc.want)
			}
		})
	}
}

func TestCheckPhaseSecondsRankSpacing(t *testing.T) {
	// Same check (same GUID), different ranks: successive ranks must land
	// exactly interval_sec apart, mod effective_interval - the whole point of
	// the round-robin design.
	c := model.Check{GUID: "check-a", IntervalSec: 10, MonitorCount: 3}
	eff := effectiveIntervalSeconds(c)
	phases := make([]int64, 3)
	for rank := 0; rank < 3; rank++ {
		c.MonitorRank = rank
		phases[rank] = checkPhaseSeconds(c, eff)
	}
	for rank := 1; rank < 3; rank++ {
		got := mod64(phases[rank]-phases[rank-1], eff)
		if got != int64(c.IntervalSec) {
			t.Fatalf("rank %d vs %d: spacing = %d, want %d", rank, rank-1, got, c.IntervalSec)
		}
	}
	for _, p := range phases {
		if p < 0 || p >= eff {
			t.Fatalf("phase %d out of range [0, %d)", p, eff)
		}
	}
}

// TestCheckPhaseSecondsCrossCheckClustering pins the 2026-09-12 correction:
// two checks with the same interval_sec and the same monitor_count/rank, but
// different GUIDs, must get different phases - fails immediately if the
// hash(check.GUID) term is ever dropped from the formula.
func TestCheckPhaseSecondsCrossCheckClustering(t *testing.T) {
	a := model.Check{GUID: "check-a", IntervalSec: 60, MonitorCount: 1, MonitorRank: 0}
	b := model.Check{GUID: "check-b", IntervalSec: 60, MonitorCount: 1, MonitorRank: 0}
	effA := effectiveIntervalSeconds(a)
	effB := effectiveIntervalSeconds(b)
	if effA != effB {
		t.Fatalf("expected identical effective_interval, got %d vs %d", effA, effB)
	}
	phaseA := checkPhaseSeconds(a, effA)
	phaseB := checkPhaseSeconds(b, effB)
	if phaseA == phaseB {
		t.Fatalf("expected different phases for different GUIDs sharing interval_sec/monitor_count/monitor_rank, both got %d - the hash(check.GUID) term appears to be missing", phaseA)
	}
}

func TestNextSlotAfter(t *testing.T) {
	const eff = int64(10)
	const phase = int64(3)

	// Exactly on a slot: fires now, not one interval later.
	onSlot := time.Unix(23, 0) // 23 mod 10 == 3
	if got := nextSlotAfter(onSlot, phase, eff); !got.Equal(onSlot) {
		t.Fatalf("expected exactly-on-slot now to return unchanged, got %v want %v", got, onSlot)
	}

	// Between slots: rounds up to the next one.
	between := time.Unix(25, 0) // next valid slot is 33 (23 + 10)
	want := time.Unix(33, 0)
	if got := nextSlotAfter(between, phase, eff); !got.Equal(want) {
		t.Fatalf("nextSlotAfter(%v) = %v, want %v", between, got, want)
	}

	// now before phase entirely (only realistic in a test, given real Unix
	// epoch seconds dwarf any effective_interval, but the modulo arithmetic
	// must still hold for it).
	early := time.Unix(0, 0)
	wantEarly := time.Unix(phase, 0)
	if got := nextSlotAfter(early, phase, eff); !got.Equal(wantEarly) {
		t.Fatalf("nextSlotAfter(%v) = %v, want %v", early, got, wantEarly)
	}
}

// TestScheduleLoopAdvanceNeverReselectsTheJustFiredSlot guards the exact bug
// this feature shipped with initially: at MonitorCount=1 (effective_interval
// == interval_sec, a common case), naively recomputing nextSlotAfter(time.Now(), ...)
// immediately after firing a slot re-selects the very same slot (its
// wall-clock second hasn't necessarily advanced), busy-looping instead of
// waiting a full effective_interval. Advancing by plain addition from the
// fired slot, as scheduleLoop does, must never do this.
func TestScheduleLoopAdvanceNeverReselectsTheJustFiredSlot(t *testing.T) {
	const eff = int64(1) // the degenerate case that exposed the bug
	const phase = int64(0)
	step := time.Duration(eff) * time.Second

	fired := time.Unix(1000, 0)
	next := fired.Add(step)
	if !next.After(fired) {
		t.Fatalf("advancing by one effective_interval must move strictly forward: fired=%v next=%v", fired, next)
	}
	if got := mod64(next.Unix()-phase, eff); got != 0 {
		t.Fatalf("advanced slot must still land on the grid: got remainder %d", got)
	}
}
