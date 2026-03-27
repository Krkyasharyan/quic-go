package congestion

import "unsafe"

// ---------- CongestionSnapshot ----------
// A cache-line-packed (64-byte) flat struct for lock-free telemetry extraction.
// ALL fields are fixed-size primitives: zero pointers, zero strings, zero slices.
// This struct is designed to be read/written via a SeqLock with zero GC pressure.

// CongestionSnapshot holds a point-in-time snapshot of congestion controller state.
// Layout is carefully ordered for strict alignment and fits in a single 64-byte
// L1 cache line.
//
//	Offset  Size  Field
//	------  ----  ---------------------
//	 0       8    CongestionWindow
//	 8       8    BytesInFlight
//	16       8    MaxBw
//	24       8    PacingRate
//	32       8    SlowStartThreshold
//	40       8    SmoothedRTT
//	48       8    MinRTT
//	56       1    BBRMode
//	57       1    ProbeBWPhase
//	58       1    Algorithm
//	59       5    _pad (explicit)
//	------  ----
//	Total: 64 bytes
type CongestionSnapshot struct {
	CongestionWindow   uint64 // bytes
	BytesInFlight      uint64 // bytes
	MaxBw              uint64 // bits per second (Bandwidth); 0 for CUBIC
	PacingRate         uint64 // bits per second (Bandwidth); 0 for CUBIC
	SlowStartThreshold uint64 // bytes; 0 for BBRv3
	SmoothedRTT        int64  // nanoseconds
	MinRTT             int64  // nanoseconds
	BBRMode            uint8  // see BBRMode* constants; BBRModeNA for CUBIC
	ProbeBWPhase       uint8  // see ProbeBWPhase* constants; ProbeBWPhaseNA for CUBIC
	Algorithm          uint8  // AlgoBBRv3 or AlgoCubic
	_pad               [5]byte
}

// Compile-time assertion: CongestionSnapshot must be exactly 64 bytes.
const _ = uint(64-unsafe.Sizeof(CongestionSnapshot{})) + uint(unsafe.Sizeof(CongestionSnapshot{})-64)

// ---------- Enum constants (uint8, zero-alloc) ----------

// BBR mode constants (maps 1:1 from internal bbrMode iota).
const (
	BBRModeStartup  uint8 = 0    // bbrStartup
	BBRModeDrain    uint8 = 1    // bbrDrain
	BBRModeProbeBW  uint8 = 2    // bbrProbeBW
	BBRModeProbeRTT uint8 = 3    // bbrProbeRTT
	BBRModeNA       uint8 = 0xFF // not applicable (CUBIC)
)

// ProbeBW sub-phase constants (maps 1:1 from internal probeBWPhase iota).
const (
	ProbeBWPhaseDown   uint8 = 0    // probeBWDown
	ProbeBWPhaseCruise uint8 = 1    // probeBWCruise
	ProbeBWPhaseRefill uint8 = 2    // probeBWRefill
	ProbeBWPhaseUp     uint8 = 3    // probeBWUp
	ProbeBWPhaseNA     uint8 = 0xFF // not applicable (CUBIC or non-ProbeBW mode)
)

// Congestion control algorithm identifier.
const (
	AlgoBBRv3 uint8 = 0
	AlgoCubic uint8 = 1
)
