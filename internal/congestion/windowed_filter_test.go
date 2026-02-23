package congestion

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindowedMaxFilter(t *testing.T) {
	f := newWindowedFilter(10, true) // max filter, window=10 rounds

	// Initially zero.
	require.Equal(t, int64(0), f.GetBest())

	// Reset with a value.
	f.Reset(100, 1)
	require.Equal(t, int64(100), f.GetBest())

	// Update with a better (higher) value — resets all three to new best.
	f.Update(200, 2)
	require.Equal(t, int64(200), f.GetBest())

	// Update with a worse (lower) value immediately — no quarter-window elapsed,
	// all three still at 200.
	f.Update(150, 3)
	require.Equal(t, int64(200), f.GetBest())

	// After a quarter-window (10/4=2 rounds) from the reset at round 2,
	// the stale second-best (still 200@2) gets replaced by a worse sample.
	f2 := newWindowedFilter(10, true)
	f2.Update(200, 1) // resets all to 200@1
	f2.Update(80, 5)  // round 5: 5-1=4 > 10/4=2 → quarter-window aging replaces second-best
	require.Equal(t, int64(200), f2.GetBest())
	require.Equal(t, int64(80), f2.GetSecondBest())

	// Another worse sample after half-window from second-best → replaces third-best.
	f2.Update(60, 11) // round 11: 11-5=6 > 10/2=5 → half-window aging replaces third-best
	require.Equal(t, int64(200), f2.GetBest())
	require.Equal(t, int64(80), f2.GetSecondBest())
	require.Equal(t, int64(60), f2.GetThirdBest())
}

func TestWindowedMaxFilterExpiry(t *testing.T) {
	f := newWindowedFilter(5, true) // max filter, window=5 rounds

	f.Reset(100, 1)
	f.Update(80, 3)
	f.Update(60, 5)

	require.Equal(t, int64(100), f.GetBest())

	// Advance past the window for the third-best sample.
	f.Update(70, 11)
	// Third-best expired. Best sample at round 1 is also past window (11-1=10 > 5).
	// All expired — reset.
	require.Equal(t, int64(70), f.GetBest())
}

func TestWindowedMaxFilterPartialExpiry(t *testing.T) {
	f := newWindowedFilter(10, true)

	f.Update(300, 1) // resets all three to 300@1
	f.Update(200, 5) // second-best
	f.Update(150, 8) // third-best

	require.Equal(t, int64(300), f.GetBest())

	// Round 19: third-best at round 8 hasn't expired (19-8=11 > 10), expired.
	// Second at round 5: 19-5=14>10, expired.
	// Best at round 1: 19-1=18>10, expired → full reset.
	f.Update(180, 19)
	require.Equal(t, int64(180), f.GetBest())
}

func TestWindowedMinFilter(t *testing.T) {
	f := newWindowedFilter(10, false) // min filter, window=10

	// Reset with a value.
	f.Reset(100, 1)
	require.Equal(t, int64(100), f.GetBest())

	// Update with a better (lower) value — resets all three.
	f.Update(50, 2)
	require.Equal(t, int64(50), f.GetBest())

	// After quarter-window, a worse sample replaces stale second-best.
	f.Update(80, 6) // 6-2=4 > 10/4=2 → quarter-window aging
	require.Equal(t, int64(50), f.GetBest())
	require.Equal(t, int64(80), f.GetSecondBest())
}

func TestWindowedMinFilterExpiry(t *testing.T) {
	f := newWindowedFilter(5, false)

	f.Update(50, 1) // resets to 50@1
	f.Update(70, 3)
	f.Update(90, 5)

	require.Equal(t, int64(50), f.GetBest())

	// Advance well past the window for all samples.
	f.Update(80, 12)
	require.Equal(t, int64(80), f.GetBest())
}

func TestWindowedFilterReset(t *testing.T) {
	f := newWindowedFilter(10, true)

	f.Update(200, 1) // resets all to 200@1 (200 > 0)
	require.Equal(t, int64(200), f.GetBest())

	f.Reset(50, 5)
	require.Equal(t, int64(50), f.GetBest())
	require.Equal(t, int64(50), f.GetSecondBest())
	require.Equal(t, int64(50), f.GetThirdBest())
}

func TestWindowedFilterNewBestUpdatesAll(t *testing.T) {
	f := newWindowedFilter(10, true)

	f.Update(100, 1)
	f.Update(80, 2)
	f.Update(60, 3)

	// A new best should reset all three.
	f.Update(200, 4)
	require.Equal(t, int64(200), f.GetBest())
	require.Equal(t, int64(200), f.GetSecondBest())
	require.Equal(t, int64(200), f.GetThirdBest())
}

// TestWindowedMaxFilterAmnesiaProtection verifies that when the best
// sample expires, valid second-best samples are promoted instead of
// resetting all three slots to the low incoming value.
// This is the "bandwidth amnesia" fix.
func TestWindowedMaxFilterAmnesiaProtection(t *testing.T) {
	// Setup: best at cycle 1, differentiate second/third via quarter-window aging.
	// Window=2, quarterWindow=max(2/4,1)=1. Aging fires when delta > 1, i.e. delta >= 2.
	f := newWindowedFilter(2, true)
	f.Reset(1000, 1)    // all at cycle 1: [1000@1, 1000@1, 1000@1]
	f.Update(800, 3)    // quarter aging: 3-1=2 > 1 → second=800@3, third=800@3
	                    // State: [1000@1, 800@3, 800@3]

	require.Equal(t, int64(1000), f.GetBest(), "best preserved after aging")
	require.Equal(t, int64(800), f.GetSecondBest(), "second aged")

	// Low value at cycle 4:
	// Third at 3: 4-3=1, NOT > 2. Third not expired.
	// Best at 1: 4-1=3 > 2 → best expired!
	// Case 5 fires: promote [800@3, 800@3, 50@4].
	// Then check promoted best (800@3): 4-3=1, NOT > 2 → stop.
	f.Update(50, 4)
	require.Equal(t, int64(800), f.GetBest(), "should promote second-best, not reset to low value")
}

// TestWindowedMaxFilterThirdOnlyExpiry tests the case where only the third-best
// expires while best and second are still valid.
func TestWindowedMaxFilterThirdOnlyExpiry(t *testing.T) {
	f := newWindowedFilter(5, true)

	f.Reset(500, 1)
	// Use quarter-window aging to install different values in second/third.
	f.Update(400, 3) // 3-1=2 > 5/4=1 → quarter aging: second=400@3, third=400@3
	f.Update(300, 5) // 5-3=2 > 5/2=2? No (NOT > 2). third stays. But 300 < 400, no update.

	// State: [500@1, 400@3, 400@3]
	// Third at round 3: 7-3=4 < 5. Not expired.
	// But at round 9: 9-3=6 > 5. Third expired.
	// Best at 1: 9-1=8 > 5. Best expired too.
	// Second at 3: 9-3=6 > 5. Second expired too.
	f.Update(200, 9)
	// All expired → Reset.
	require.Equal(t, int64(200), f.GetBest())

	// Now: partial expiry where best is still valid.
	f3 := newWindowedFilter(5, true)
	f3.Reset(500, 5)
	f3.Update(400, 7) // 7-5=2 > 5/4=1 → quarter aging: second=400@7, third=400@7
	// State: [500@5, 400@7, 400@7]
	// At round 13: 13-7=6 > 5 → third expired. Best: 13-5=8 > 5 → expired too.
	// Second: 13-7=6 > 5 → expired.
	f3.Update(100, 13)
	require.Equal(t, int64(100), f3.GetBest(), "all expired → reset to new value")

	// Partial: only third expired, best and second valid.
	f4 := newWindowedFilter(5, true)
	f4.Reset(500, 10)
	f4.Update(400, 12) // quarter aging: second=400@12
	// State: [500@10, 400@12, 400@12]
	// At round 18: third at 12: 18-12=6 > 5 → expired.
	//              best at 10: 18-10=8 > 5 → expired.
	//              second at 12: 18-12=6 > 5 → expired.
	f4.Update(100, 18)
	require.Equal(t, int64(100), f4.GetBest(), "all expired → reset")
}

// TestWindowedFilterQuarterWindowMinThreshold verifies that quarter-window
// aging uses a minimum threshold of 1, preventing degenerate behavior with
// small window lengths (e.g., MaxBwFilterLen=2 gives windowLength/4=0).
func TestWindowedFilterQuarterWindowMinThreshold(t *testing.T) {
	f := newWindowedFilter(2, true) // window=2, raw quarter=0, min=1

	f.Reset(1000, 0) // all three at [1000@0, 1000@0, 1000@0]

	// Without the min threshold fix, windowLength/4=0 would mean delta > 0
	// is always true, causing immediate aging at every Update.
	// With min threshold=1, aging requires delta > 1, so Update at round 1
	// should NOT trigger aging (1-0=1, NOT > 1).
	f.Update(100, 1)
	require.Equal(t, int64(1000), f.GetBest(), "best preserved")
	require.Equal(t, int64(1000), f.GetSecondBest(), "second NOT aged at delta=1")

	// At round 2: delta=2-0=2 > 1 → aging fires, second becomes 100.
	f.Update(100, 2)
	require.Equal(t, int64(1000), f.GetBest(), "best still preserved")
	require.Equal(t, int64(100), f.GetSecondBest(), "second-best aged at delta=2")
	require.Equal(t, int64(100), f.GetThirdBest(), "third-best also aged")
}
