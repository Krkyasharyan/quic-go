package congestion

import (
	"runtime"
	"sync/atomic"
)

// CongestionSeqLock is a single-producer / multiple-reader sequence lock for
// publishing CongestionSnapshot data on the hot path with zero heap allocations.
//
// Memory layout (3 cache lines, 192 bytes):
//
//	Cache Line 0:  [seq atomic.Uint64] [56 bytes padding]
//	Cache Line 1:  [CongestionSnapshot — 64 bytes]
//	Cache Line 2:  [64 bytes trailing padding — isolation]
//
// The sequence counter and snapshot data are on SEPARATE cache lines so the
// writer's counter-store does not invalidate the reader's data-read.
type CongestionSeqLock struct {
	seq   atomic.Uint64
	_pad0 [56]byte           // isolate seq on its own cache line
	snap  CongestionSnapshot // exactly 64 bytes — its own cache line
	_pad1 [64]byte           // prevent false sharing with adjacent struct fields
}

// BeginWrite marks the start of a write. The caller MUST call EndWrite after
// writing fields into Snap(). Only one goroutine (the run-loop) may call this.
func (sl *CongestionSeqLock) BeginWrite() {
	sl.seq.Add(1) // seq becomes odd → write in progress
}

// EndWrite marks the end of a write, making the snapshot visible to readers.
func (sl *CongestionSeqLock) EndWrite() {
	sl.seq.Add(1) // seq becomes even → consistent
}

// Snap returns a pointer to the embedded snapshot for the writer to fill.
// Only valid between BeginWrite and EndWrite calls.
func (sl *CongestionSeqLock) Snap() *CongestionSnapshot {
	return &sl.snap
}

// ReadSnapshot copies the current snapshot into dst. Returns true if a
// consistent (non-torn) read was obtained, false if the writer was active
// during all retry attempts. Callers should retry on the next poll cycle
// if false is returned.
//
// Bounded to 4 retries to avoid unbounded spinning (Go GC STW can pause
// the writer goroutine).
func (sl *CongestionSeqLock) ReadSnapshot(dst *CongestionSnapshot) bool {
	for i := 0; i < 4; i++ {
		s1 := sl.seq.Load()
		if s1&1 != 0 {
			// Writer in progress — yield and retry.
			runtime.Gosched()
			continue
		}
		// 64-byte value copy (compiler emits MOV instructions).
		*dst = sl.snap
		s2 := sl.seq.Load()
		if s1 == s2 {
			return true
		}
	}
	return false
}
