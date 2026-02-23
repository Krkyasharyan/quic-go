package congestion

// windowedFilter implements a windowed min or max filter.
// It tracks the best, second-best, and third-best values within a sliding window.
// This is modeled after the Chromium WindowedFilter used in BBR.
//
// For max-bandwidth tracking, use isMax=true (window = round-trip count).
// For min-RTT tracking, use isMax=false (window = wall-clock nanoseconds).

// windowedSample holds a value and the round/time at which it was recorded.
type windowedSample struct {
	value int64
	round int64 // round number or timestamp (depending on filter type)
}

// windowedFilter is a generic windowed min or max filter.
// Set isMax=true for a max filter, isMax=false for a min filter.
type windowedFilter struct {
	windowLength int64
	isMax        bool
	samples      [3]windowedSample // best, second-best, third-best
}

func newWindowedFilter(windowLength int64, isMax bool) *windowedFilter {
	return &windowedFilter{
		windowLength: windowLength,
		isMax:        isMax,
	}
}

// better returns true if a is "better" than b (greater for max, lesser for min).
func (f *windowedFilter) better(a, b int64) bool {
	if f.isMax {
		return a >= b
	}
	return a <= b
}

// GetBest returns the best (max or min) value in the window.
func (f *windowedFilter) GetBest() int64 {
	return f.samples[0].value
}

// GetSecondBest returns the second-best value in the window.
func (f *windowedFilter) GetSecondBest() int64 {
	return f.samples[1].value
}

// GetThirdBest returns the third-best value in the window.
func (f *windowedFilter) GetThirdBest() int64 {
	return f.samples[2].value
}

// Reset resets the filter to the given value at the given round.
func (f *windowedFilter) Reset(value, round int64) {
	s := windowedSample{value: value, round: round}
	f.samples[0] = s
	f.samples[1] = s
	f.samples[2] = s
}

// Update updates the filter with a new sample.
// This implements the Kathleen Nichols windowed min/max algorithm with a
// fix for the "bandwidth amnesia" problem: when the oldest sample expires
// and the incoming value is NOT a new best, we promote remaining valid
// samples rather than resetting all three slots to the (potentially low)
// incoming value. This prevents a single low-quality sample from wiping
// out high-quality historical measurements in the max filter.
func (f *windowedFilter) Update(value, round int64) {
	newSample := windowedSample{value: value, round: round}

	// Case 1: Not initialized — accept unconditionally.
	if f.samples[0].value == 0 {
		f.Reset(value, round)
		return
	}

	// Case 2: New best — replace everything.
	if f.better(value, f.samples[0].value) {
		f.Reset(value, round)
		return
	}

	// Case 3: Expiration handling. Check each slot from oldest (third) to
	// newest (best) and handle expired samples by promoting what's left.
	// This avoids the original algorithm's unconditional Reset on third-best
	// expiry, which caused "bandwidth amnesia" in max filters.
	if round-f.samples[2].round > f.windowLength {
		if round-f.samples[0].round > f.windowLength {
			// All three expired. No valid historical data remains.
			f.Reset(value, round)
			return
		}
		if round-f.samples[1].round > f.windowLength {
			// Best still valid, second and third expired.
			f.samples[1] = newSample
			f.samples[2] = newSample
		} else {
			// Best and second still valid, only third expired.
			f.samples[2] = newSample
		}
		return
	}

	// Case 4: No expiration — try to update second and third best.
	if f.better(value, f.samples[1].value) {
		f.samples[1] = newSample
		f.samples[2] = newSample
	} else if f.better(value, f.samples[2].value) {
		f.samples[2] = newSample
	}

	// Case 5: Best has expired (but third hasn't — this happens when best
	// is much older than second/third). Promote and replace.
	if round-f.samples[0].round > f.windowLength {
		f.samples[0] = f.samples[1]
		f.samples[1] = f.samples[2]
		f.samples[2] = newSample
		// Check again: if the promoted best (formerly second) also expired.
		if round-f.samples[0].round > f.windowLength {
			f.samples[0] = f.samples[1]
			f.samples[1] = newSample
		}
		return
	}

	// Case 6: Quarter-window aging — if second-best still equals best and
	// enough time has passed, replace it with the current sample as a more
	// recent fallback. Ensure minimum threshold of 1 to prevent degenerate
	// behavior when windowLength is small (e.g., MaxBwFilterLen=2 gives
	// windowLength/4=0, causing immediate aging).
	quarterWindow := f.windowLength / 4
	if quarterWindow < 1 {
		quarterWindow = 1
	}
	if f.samples[1].value == f.samples[0].value &&
		round-f.samples[1].round > quarterWindow {
		f.samples[1] = newSample
		f.samples[2] = newSample
		return
	}

	// Case 7: Half-window aging — same for third-best relative to second-best.
	halfWindow := f.windowLength / 2
	if halfWindow < 1 {
		halfWindow = 1
	}
	if f.samples[2].value == f.samples[1].value &&
		round-f.samples[2].round > halfWindow {
		f.samples[2] = newSample
	}
}
