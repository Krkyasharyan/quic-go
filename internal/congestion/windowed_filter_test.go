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
