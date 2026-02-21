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
// This follows the Chromium WindowedFilter algorithm.
func (f *windowedFilter) Update(value, round int64) {
	// Reset if: not initialized, new best, or third-best expired.
	if f.samples[0].value == 0 ||
		f.better(value, f.samples[0].value) ||
		round-f.samples[2].round > f.windowLength {
		f.Reset(value, round)
		return
	}

	// Try to update second and third best.
	if f.better(value, f.samples[1].value) {
		f.samples[1] = windowedSample{value: value, round: round}
		f.samples[2] = f.samples[1]
	} else if f.better(value, f.samples[2].value) {
		f.samples[2] = windowedSample{value: value, round: round}
	}

	// Expire and promote estimates as needed.
	if round-f.samples[0].round > f.windowLength {
		// Best has expired — promote.
		f.samples[0] = f.samples[1]
		f.samples[1] = f.samples[2]
		f.samples[2] = windowedSample{value: value, round: round}
		// Check again: if the new best (formerly second-best) also expired.
		if round-f.samples[0].round > f.windowLength {
			f.samples[0] = f.samples[1]
			f.samples[1] = f.samples[2]
		}
		return
	}

	// Quarter-window aging: if second-best still equals best and enough time
	// has passed, replace it with the current sample as a more recent fallback.
	if f.samples[1].value == f.samples[0].value &&
		round-f.samples[1].round > f.windowLength/4 {
		f.samples[1] = windowedSample{value: value, round: round}
		f.samples[2] = f.samples[1]
		return
	}

	// Half-window aging: same for third-best relative to second-best.
	if f.samples[2].value == f.samples[1].value &&
		round-f.samples[2].round > f.windowLength/2 {
		f.samples[2] = windowedSample{value: value, round: round}
	}
}
