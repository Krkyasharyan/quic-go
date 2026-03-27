package congestion

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/quic-go/quic-go/internal/protocol"
)

func TestCongestionSnapshotSize(t *testing.T) {
	if sz := unsafe.Sizeof(CongestionSnapshot{}); sz != 64 {
		t.Fatalf("CongestionSnapshot is %d bytes, want 64", sz)
	}
}

func TestCongestionSnapshotAlignment(t *testing.T) {
	if align := unsafe.Alignof(CongestionSnapshot{}); align < 8 {
		t.Fatalf("CongestionSnapshot alignment is %d, want >= 8", align)
	}
}

func TestSeqLockReadWriteConsistency(t *testing.T) {
	var sl CongestionSeqLock

	// Write a known pattern.
	sl.BeginWrite()
	snap := sl.Snap()
	snap.CongestionWindow = 42000
	snap.BytesInFlight = 10000
	snap.MaxBw = 500000
	snap.PacingRate = 400000
	snap.SlowStartThreshold = 0
	snap.SmoothedRTT = 50_000_000 // 50ms
	snap.MinRTT = 10_000_000      // 10ms
	snap.BBRMode = BBRModeProbeBW
	snap.ProbeBWPhase = ProbeBWPhaseCruise
	snap.Algorithm = AlgoBBRv3
	sl.EndWrite()

	// Read it back.
	var dst CongestionSnapshot
	ok := sl.ReadSnapshot(&dst)
	if !ok {
		t.Fatal("ReadSnapshot failed")
	}
	if dst.CongestionWindow != 42000 {
		t.Fatalf("CongestionWindow = %d, want 42000", dst.CongestionWindow)
	}
	if dst.BytesInFlight != 10000 {
		t.Fatalf("BytesInFlight = %d, want 10000", dst.BytesInFlight)
	}
	if dst.MaxBw != 500000 {
		t.Fatalf("MaxBw = %d, want 500000", dst.MaxBw)
	}
	if dst.PacingRate != 400000 {
		t.Fatalf("PacingRate = %d, want 400000", dst.PacingRate)
	}
	if dst.SmoothedRTT != 50_000_000 {
		t.Fatalf("SmoothedRTT = %d, want 50000000", dst.SmoothedRTT)
	}
	if dst.MinRTT != 10_000_000 {
		t.Fatalf("MinRTT = %d, want 10000000", dst.MinRTT)
	}
	if dst.BBRMode != BBRModeProbeBW {
		t.Fatalf("BBRMode = %d, want %d", dst.BBRMode, BBRModeProbeBW)
	}
	if dst.ProbeBWPhase != ProbeBWPhaseCruise {
		t.Fatalf("ProbeBWPhase = %d, want %d", dst.ProbeBWPhase, ProbeBWPhaseCruise)
	}
	if dst.Algorithm != AlgoBBRv3 {
		t.Fatalf("Algorithm = %d, want %d", dst.Algorithm, AlgoBBRv3)
	}
}

func TestSeqLockConcurrentNoTornReads(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("SeqLock uses intentional non-synchronized reads; skip under -race")
	}
	var sl CongestionSeqLock
	const iterations = 1_000_000
	var tornReads atomic.Uint64
	var failedReads atomic.Uint64
	var successReads atomic.Uint64
	var stop atomic.Bool

	// Writer: alternates between two distinct patterns.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			sl.BeginWrite()
			snap := sl.Snap()
			if i%2 == 0 {
				snap.CongestionWindow = 1000
				snap.BytesInFlight = 1000
				snap.MaxBw = 1000
				snap.BBRMode = BBRModeStartup
				snap.Algorithm = AlgoBBRv3
			} else {
				snap.CongestionWindow = 2000
				snap.BytesInFlight = 2000
				snap.MaxBw = 2000
				snap.BBRMode = BBRModeProbeBW
				snap.Algorithm = AlgoBBRv3
			}
			sl.EndWrite()
			// Yield occasionally to give the reader time.
			if i%100 == 0 {
				runtime.Gosched()
			}
		}
	}()

	// Reader: checks that fields are internally consistent.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var dst CongestionSnapshot
		for i := 0; i < iterations; i++ {
			ok := sl.ReadSnapshot(&dst)
			if !ok {
				failedReads.Add(1)
				continue
			}
			successReads.Add(1)
			// Consistency check: all fields should belong to the same pattern.
			if dst.CongestionWindow == 1000 {
				if dst.BytesInFlight != 1000 || dst.MaxBw != 1000 || dst.BBRMode != BBRModeStartup {
					tornReads.Add(1)
				}
			} else if dst.CongestionWindow == 2000 {
				if dst.BytesInFlight != 2000 || dst.MaxBw != 2000 || dst.BBRMode != BBRModeProbeBW {
					tornReads.Add(1)
				}
			}
			if i%100 == 0 {
				runtime.Gosched()
			}
		}
		stop.Store(true)
	}()

	wg.Wait()

	if torn := tornReads.Load(); torn > 0 {
		t.Fatalf("detected %d torn reads out of %d successful reads", torn, successReads.Load())
	}
	if success := successReads.Load(); success == 0 {
		t.Fatal("no successful reads completed")
	}
	failed := failedReads.Load()
	success := successReads.Load()
	successRate := float64(success) / float64(success+failed) * 100
	t.Logf("SeqLock: %d successful, %d failed (%.2f%% success rate)", success, failed, successRate)
	if successRate < 90.0 {
		t.Fatalf("success rate %.2f%% is below 90%% threshold", successRate)
	}
}

func TestSeqLockReaderReturnsFalseDuringWrite(t *testing.T) {
	var sl CongestionSeqLock
	sl.BeginWrite() // leave write open — seq is odd

	var dst CongestionSnapshot
	ok := sl.ReadSnapshot(&dst)
	if ok {
		t.Fatal("ReadSnapshot should return false when writer is permanently active")
	}
}

func TestBBRModeConstants(t *testing.T) {
	// Verify the uint8 constants match the internal iota values.
	if BBRModeStartup != uint8(bbrStartup) {
		t.Fatalf("BBRModeStartup=%d != bbrStartup=%d", BBRModeStartup, bbrStartup)
	}
	if BBRModeDrain != uint8(bbrDrain) {
		t.Fatalf("BBRModeDrain=%d != bbrDrain=%d", BBRModeDrain, bbrDrain)
	}
	if BBRModeProbeBW != uint8(bbrProbeBW) {
		t.Fatalf("BBRModeProbeBW=%d != bbrProbeBW=%d", BBRModeProbeBW, bbrProbeBW)
	}
	if BBRModeProbeRTT != uint8(bbrProbeRTT) {
		t.Fatalf("BBRModeProbeRTT=%d != bbrProbeRTT=%d", BBRModeProbeRTT, bbrProbeRTT)
	}
}

func TestProbeBWPhaseConstants(t *testing.T) {
	if ProbeBWPhaseDown != uint8(probeBWDown) {
		t.Fatalf("ProbeBWPhaseDown=%d != probeBWDown=%d", ProbeBWPhaseDown, probeBWDown)
	}
	if ProbeBWPhaseCruise != uint8(probeBWCruise) {
		t.Fatalf("ProbeBWPhaseCruise=%d != probeBWCruise=%d", ProbeBWPhaseCruise, probeBWCruise)
	}
	if ProbeBWPhaseRefill != uint8(probeBWRefill) {
		t.Fatalf("ProbeBWPhaseRefill=%d != probeBWRefill=%d", ProbeBWPhaseRefill, probeBWRefill)
	}
	if ProbeBWPhaseUp != uint8(probeBWUp) {
		t.Fatalf("ProbeBWPhaseUp=%d != probeBWUp=%d", ProbeBWPhaseUp, probeBWUp)
	}
}

func TestFillSnapshotBBRv3(t *testing.T) {
	b := newSnapshotBBRv3Sender()
	b.congestionWindow = 50000
	b.maxBw = 1000 * BytesPerSecond // 1000 Bps = 8000 bps
	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWUp

	var snap CongestionSnapshot
	b.FillSnapshot(&snap)

	if snap.CongestionWindow != 50000 {
		t.Fatalf("CongestionWindow = %d, want 50000", snap.CongestionWindow)
	}
	if snap.MaxBw != uint64(1000*BytesPerSecond) {
		t.Fatalf("MaxBw = %d, want %d", snap.MaxBw, 1000*BytesPerSecond)
	}
	if snap.BBRMode != BBRModeProbeBW {
		t.Fatalf("BBRMode = %d, want %d", snap.BBRMode, BBRModeProbeBW)
	}
	if snap.ProbeBWPhase != ProbeBWPhaseUp {
		t.Fatalf("ProbeBWPhase = %d, want %d", snap.ProbeBWPhase, ProbeBWPhaseUp)
	}
	if snap.Algorithm != AlgoBBRv3 {
		t.Fatalf("Algorithm = %d, want %d", snap.Algorithm, AlgoBBRv3)
	}
	if snap.SlowStartThreshold != 0 {
		t.Fatalf("SlowStartThreshold = %d, want 0 (BBRv3)", snap.SlowStartThreshold)
	}
}

func TestFillSnapshotCubic(t *testing.T) {
	c := newSnapshotCubicSender()
	c.congestionWindow = 30000
	c.slowStartThreshold = 20000

	var snap CongestionSnapshot
	c.FillSnapshot(&snap)

	if snap.CongestionWindow != 30000 {
		t.Fatalf("CongestionWindow = %d, want 30000", snap.CongestionWindow)
	}
	if snap.SlowStartThreshold != 20000 {
		t.Fatalf("SlowStartThreshold = %d, want 20000", snap.SlowStartThreshold)
	}
	if snap.MaxBw != 0 {
		t.Fatalf("MaxBw = %d, want 0 (CUBIC)", snap.MaxBw)
	}
	if snap.PacingRate != 0 {
		t.Fatalf("PacingRate = %d, want 0 (CUBIC)", snap.PacingRate)
	}
	if snap.BBRMode != BBRModeNA {
		t.Fatalf("BBRMode = %d, want %d (N/A)", snap.BBRMode, BBRModeNA)
	}
	if snap.ProbeBWPhase != ProbeBWPhaseNA {
		t.Fatalf("ProbeBWPhase = %d, want %d (N/A)", snap.ProbeBWPhase, ProbeBWPhaseNA)
	}
	if snap.Algorithm != AlgoCubic {
		t.Fatalf("Algorithm = %d, want %d", snap.Algorithm, AlgoCubic)
	}
}

// ---------- Helper constructors for snapshot tests ----------

func newSnapshotBBRv3Sender() *bbrv3Sender {
	return &bbrv3Sender{
		maxDatagramSize:  1200,
		congestionWindow: 32 * 1200,
		pacingGain:       1.0,
		cwndGain:         2.0,
		bw:               1000 * BytesPerSecond, // avoid nil rttStats path in pacingRateBytesPerSec
	}
}

func newSnapshotCubicSender() *cubicSender {
	return &cubicSender{
		maxDatagramSize:    1200,
		congestionWindow:   32 * 1200,
		slowStartThreshold: protocol.MaxByteCount,
	}
}

// ---------- Benchmarks ----------

func BenchmarkSeqLockWrite(b *testing.B) {
	var sl CongestionSeqLock
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sl.BeginWrite()
		snap := sl.Snap()
		snap.CongestionWindow = uint64(i)
		snap.BytesInFlight = uint64(i)
		snap.MaxBw = uint64(i)
		snap.PacingRate = uint64(i)
		snap.SmoothedRTT = int64(i)
		snap.MinRTT = int64(i)
		snap.BBRMode = BBRModeProbeBW
		sl.EndWrite()
	}
}

func BenchmarkSeqLockRead(b *testing.B) {
	var sl CongestionSeqLock
	// Seed with data.
	sl.BeginWrite()
	snap := sl.Snap()
	snap.CongestionWindow = 42000
	snap.BytesInFlight = 10000
	sl.EndWrite()

	var dst CongestionSnapshot
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sl.ReadSnapshot(&dst)
	}
}

func BenchmarkFillSnapshotBBRv3(b *testing.B) {
	sender := newSnapshotBBRv3Sender()
	sender.maxBw = 1000 * BytesPerSecond
	sender.mode = bbrProbeBW
	sender.probeBWPhase = probeBWCruise
	var snap CongestionSnapshot
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sender.FillSnapshot(&snap)
	}
}

func BenchmarkFillSnapshotCubic(b *testing.B) {
	sender := newSnapshotCubicSender()
	var snap CongestionSnapshot
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sender.FillSnapshot(&snap)
	}
}

func BenchmarkSeqLockConcurrent(b *testing.B) {
	if raceDetectorEnabled {
		b.Skip("SeqLock uses intentional non-synchronized reads; skip under -race")
	}
	var sl CongestionSeqLock
	var stop atomic.Bool

	// Background writer at ~1M writes/sec.
	go func() {
		for i := 0; !stop.Load(); i++ {
			sl.BeginWrite()
			snap := sl.Snap()
			snap.CongestionWindow = uint64(i)
			snap.BytesInFlight = uint64(i)
			sl.EndWrite()
			if i%1000 == 0 {
				time.Sleep(time.Microsecond)
			}
		}
	}()

	var dst CongestionSnapshot
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sl.ReadSnapshot(&dst)
	}
	b.StopTimer()
	stop.Store(true)
}
