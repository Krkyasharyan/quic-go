package congestion

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// ---------- BBR Mode (State Machine) ----------

type bbrMode int

const (
	bbrStartup  bbrMode = iota // Exponentially probe bandwidth.
	bbrDrain                   // Drain the queue created during Startup.
	bbrProbeBW                 // Steady-state: cycle pacing gain to probe bandwidth.
	bbrProbeRTT                // Reduce cwnd to re-measure min RTT.
)

func (m bbrMode) String() string {
	switch m {
	case bbrStartup:
		return "Startup"
	case bbrDrain:
		return "Drain"
	case bbrProbeBW:
		return "ProbeBW"
	case bbrProbeRTT:
		return "ProbeRTT"
	default:
		return "Unknown"
	}
}

// ---------- Constants ----------

const (
	// Startup pacing & cwnd gain: ln(2)/ln(4/3) ≈ 2.89.
	bbrStartupPacingGain = 2.89
	bbrStartupCwndGain   = 2.89

	// Drain pacing gain: 1/startup_gain.
	bbrDrainPacingGain = 1.0 / bbrStartupPacingGain

	// ProbeBW cwnd gain — we use 2.0 as the multiplier before the 0.85 headroom
	// factor is applied in targetCwnd().
	bbrProbeBWCwndGain = 2.0

	// The 0.85 BDP headroom multiplier for the steady-state (ProbeBW) cwnd.
	// This prevents router buffer overflow on high-RTT paths (e.g. RU↔EU).
	bbrBDPHeadroomMultiplier = 0.85

	// Windowed max-bandwidth filter: 10 round-trips.
	bbrBandwidthWindowSize = 10

	// Windowed min-RTT filter: 10 seconds (in nanoseconds for the filter).
	bbrMinRTTWindowSize = 10 * time.Second

	// ProbeRTT duration: hold for 200 ms with minimal cwnd.
	bbrProbeRTTDuration = 200 * time.Millisecond

	// Minimum cwnd in packets during normal operation.
	bbrMinCongestionWindowPackets = 4

	// The initial congestion window in packets.
	bbrInitialCongestionWindowPackets = 32

	// Number of rounds in Startup without ≥25% bandwidth growth before exiting.
	bbrStartupFullBandwidthRounds = 3

	// Threshold for bandwidth growth in Startup: 25%.
	bbrStartupFullBandwidthThreshold = 1.25

	// Pacing "death zone": QUIC critical jitter zone is 26–35 pps.
	bbrDeathZoneLowPPS  = 26
	bbrDeathZoneHighPPS = 35
	bbrSafeZonePPS      = 25

	// Default MTU for QUIC.
	bbrDefaultMTU = 1200
)

// ProbeBW pacing gain cycle: [1.25, 0.75, 1, 1, 1, 1, 1, 1].
var bbrProbeBWPacingGainCycle = [8]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

// ---------- bbrv3Sender ----------

type bbrv3Sender struct {
	// External dependencies.
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	clock     Clock
	pacer     *pacer
	qlogger   qlogwriter.Recorder

	// Datagram size.
	maxDatagramSize protocol.ByteCount

	// --- BBR State Machine ---
	mode bbrMode

	// --- Bandwidth Estimation ---
	maxBwFilter *windowedFilter // windowed max over bbrBandwidthWindowSize rounds
	btlBw       Bandwidth       // current best bandwidth estimate (bits/s)

	// --- RTT Estimation ---
	minRttFilter    *windowedFilter // windowed min over bbrMinRTTWindowSize
	minRtt          time.Duration   // current best min RTT
	minRttTimestamp monotime.Time   // time at which minRtt was last set
	minRttExpired   bool            // whether the min RTT window has expired

	// --- Round Tracking ---
	currentRoundTripEnd protocol.PacketNumber
	roundCount          int64
	roundStart          bool

	// --- Startup ---
	fullBandwidth        Bandwidth // bandwidth at which we last declared "full"
	fullBandwidthCount   int       // consecutive rounds without ≥25% BW growth
	startupFullBWReached bool

	// --- ProbeBW ---
	cycleIndex int
	cycleStart monotime.Time

	// --- ProbeRTT ---
	probeRttDoneAt    monotime.Time
	probeRttRoundDone bool
	priorCwnd         protocol.ByteCount
	disableProbeRTT   bool // togglable flag for transparent-tunnel tuning

	// --- Gains ---
	pacingGain float64
	cwndGain   float64

	// --- Congestion Window ---
	congestionWindow protocol.ByteCount

	// --- Packet Tracking (for recovery) ---
	largestSentPacketNumber  protocol.PacketNumber
	largestAckedPacketNumber protocol.PacketNumber
	largestSentAtLastCutback protocol.PacketNumber

	// --- qlog ---
	lastState qlog.CongestionState
}

var (
	_ SendAlgorithm               = &bbrv3Sender{}
	_ SendAlgorithmWithDebugInfos = &bbrv3Sender{}
	_ BandwidthSampleConsumer     = &bbrv3Sender{}
)

// NewBBRv3Sender creates a new BBRv3 congestion controller.
func NewBBRv3Sender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *bbrv3Sender {
	b := &bbrv3Sender{
		rttStats:  rttStats,
		connStats: connStats,
		clock:     clock,
		qlogger:   qlogger,

		maxDatagramSize: initialMaxDatagramSize,

		mode: bbrStartup,

		maxBwFilter:  newWindowedFilter(bbrBandwidthWindowSize, true),      // max filter
		minRttFilter: newWindowedFilter(int64(bbrMinRTTWindowSize), false), // min filter (keyed by nanosecond timestamp)

		minRtt: rttStats.SmoothedRTT(),

		currentRoundTripEnd: protocol.InvalidPacketNumber,

		pacingGain: bbrStartupPacingGain,
		cwndGain:   bbrStartupCwndGain,

		congestionWindow: protocol.ByteCount(bbrInitialCongestionWindowPackets) * initialMaxDatagramSize,

		largestSentPacketNumber:  protocol.InvalidPacketNumber,
		largestAckedPacketNumber: protocol.InvalidPacketNumber,
		largestSentAtLastCutback: protocol.InvalidPacketNumber,
	}

	// Create the pacer with the BBR pacing rate callback (no 1.25× overhead).
	b.pacer = newPacerDirect(b.pacingRateBytesPerSec)

	if b.qlogger != nil {
		b.lastState = qlog.CongestionStateSlowStart
		b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
	}

	return b
}

// ---------- SendAlgorithm Implementation ----------

// TimeUntilSend returns when the next packet should be sent.
func (b *bbrv3Sender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

// HasPacingBudget reports whether the pacer allows sending at this moment.
func (b *bbrv3Sender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

// OnPacketSent is called when a packet is sent.
func (b *bbrv3Sender) OnPacketSent(
	sentTime monotime.Time,
	_ protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	b.largestSentPacketNumber = packetNumber
}

// CanSend reports whether bytes can be sent given the current cwnd.
func (b *bbrv3Sender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

// MaybeExitSlowStart is a no-op for BBR (BBR detects its own Startup exit).
func (b *bbrv3Sender) MaybeExitSlowStart() {}

// OnPacketAcked is called when a packet is acknowledged.
func (b *bbrv3Sender) OnPacketAcked(
	ackedPacketNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	b.largestAckedPacketNumber = max(ackedPacketNumber, b.largestAckedPacketNumber)

	// 1. Advance round-trip counter.
	b.updateRound(ackedPacketNumber)

	// 2. Bandwidth estimation is now handled by OnBandwidthSample,
	//    called from the sent_packet_handler after computing a proper
	//    delivery-rate sample across the entire ACK frame.

	// 3. Update min RTT estimate.
	b.updateMinRtt(eventTime)

	// 4. Run the state machine.
	switch b.mode {
	case bbrStartup:
		b.checkStartupDone()
	case bbrDrain:
		b.checkDrain(priorInFlight)
	case bbrProbeBW:
		b.updateProbeBWCyclePhase(eventTime, priorInFlight)
		b.maybeEnterProbeRTT(eventTime)
	case bbrProbeRTT:
		b.handleProbeRTT(eventTime, priorInFlight)
	}

	// 5. Update congestion window.
	b.updateCwnd()
}

// OnCongestionEvent is called when a packet is detected as lost.
func (b *bbrv3Sender) OnCongestionEvent(
	packetNumber protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	b.connStats.PacketsLost.Add(1)
	b.connStats.BytesLost.Add(uint64(lostBytes))

	// Treat losses within the same cutback window as a single event.
	if packetNumber <= b.largestSentAtLastCutback {
		return
	}

	// In Startup, if we see losses, consider transitioning.
	// BBRv3 uses loss as an additional signal in Startup.
	if b.mode == bbrStartup {
		// Mark bandwidth as fully probed if we see significant loss.
		b.startupFullBWReached = true
		b.enterDrain()
	}

	b.largestSentAtLastCutback = b.largestSentPacketNumber

	// In ProbeBW/Drain, cut cwnd by beta=0.7 on loss (conservative).
	if b.mode == bbrProbeBW || b.mode == bbrDrain {
		b.congestionWindow = protocol.ByteCount(float64(b.congestionWindow) * 0.7)
		if b.congestionWindow < b.minCongestionWindow() {
			b.congestionWindow = b.minCongestionWindow()
		}
	}

	b.maybeQlogStateChange(qlog.CongestionStateRecovery)
}

// OnRetransmissionTimeout is called on a retransmission timeout.
func (b *bbrv3Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	b.priorCwnd = b.congestionWindow
	b.congestionWindow = b.minCongestionWindow()
	b.largestSentAtLastCutback = protocol.InvalidPacketNumber
}

// SetMaxDatagramSize updates the MTU.
func (b *bbrv3Sender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, s))
	}
	cwndIsMin := b.congestionWindow == b.minCongestionWindow()
	b.maxDatagramSize = s
	if cwndIsMin {
		b.congestionWindow = b.minCongestionWindow()
	}
	b.pacer.SetMaxDatagramSize(s)
}

// ---------- SendAlgorithmWithDebugInfos ----------

// InSlowStart reports whether BBR is in Startup (analogous to slow start).
func (b *bbrv3Sender) InSlowStart() bool {
	return b.mode == bbrStartup
}

// InRecovery reports whether we are in loss recovery.
func (b *bbrv3Sender) InRecovery() bool {
	return b.largestAckedPacketNumber != protocol.InvalidPacketNumber &&
		b.largestAckedPacketNumber <= b.largestSentAtLastCutback
}

// GetCongestionWindow returns the current congestion window in bytes.
func (b *bbrv3Sender) GetCongestionWindow() protocol.ByteCount {
	return b.congestionWindow
}

// ---------- Pacing Rate ----------

// pacingRateBytesPerSec returns the pacing rate in bytes per second.
// This is the callback passed to the pacer. It applies the death-zone clamp.
func (b *bbrv3Sender) pacingRateBytesPerSec() uint64 {
	bw := b.btlBw
	if bw == 0 {
		// Fallback: derive from initial cwnd / smoothed RTT.
		srtt := b.rttStats.SmoothedRTT()
		if srtt == 0 {
			srtt = protocol.TimerGranularity
		}
		bw = BandwidthFromDelta(b.congestionWindow, srtt)
	}

	// Apply pacing gain. The result is in bits/s.
	pacingBw := Bandwidth(float64(bw) * b.pacingGain)

	// Convert to bytes/s.
	bytesPerSec := uint64(pacingBw / BytesPerSecond)

	// Death-zone clamp: avoid the QUIC critical jitter zone of 26–35 pps.
	mtu := uint64(b.maxDatagramSize)
	if mtu == 0 {
		mtu = bbrDefaultMTU
	}
	pps := bytesPerSec / mtu
	if pps >= bbrDeathZoneLowPPS && pps <= bbrDeathZoneHighPPS {
		// Clamp down to safe zone: 25 pps.
		bytesPerSec = bbrSafeZonePPS * mtu
	}

	return bytesPerSec
}

// PacingRate returns the current pacing rate as a Bandwidth (bits/s).
// Exported for testing / diagnostics.
func (b *bbrv3Sender) PacingRate() Bandwidth {
	return Bandwidth(b.pacingRateBytesPerSec()) * BytesPerSecond
}

// ---------- Bandwidth Estimation ----------

// OnBandwidthSample is called by the sent_packet_handler with the best
// delivery-rate sample from an ACK frame. It replaces the old per-packet
// ackedBytes/RTT heuristic with a proper delivery-rate estimate.
func (b *bbrv3Sender) OnBandwidthSample(sample RateSample) {
	// If the sample was taken during an app-limited period and the measured
	// rate doesn't exceed our current best, discard it — we don't want
	// idle periods to pollute the max-bandwidth filter.
	if sample.IsAppLimited && sample.DeliveryRate <= b.btlBw {
		return
	}

	// Update the windowed max filter (keyed by round count).
	b.maxBwFilter.Update(int64(sample.DeliveryRate), b.roundCount)
	b.btlBw = Bandwidth(b.maxBwFilter.GetBest())
}

// ---------- RTT Estimation ----------

func (b *bbrv3Sender) updateMinRtt(eventTime monotime.Time) {
	latestRtt := b.rttStats.LatestRTT()
	if latestRtt <= 0 {
		return
	}

	// Convert event time to nanoseconds for the filter key.
	eventNs := int64(eventTime)

	b.minRttFilter.Update(int64(latestRtt), eventNs)

	bestMinRtt := time.Duration(b.minRttFilter.GetBest())
	if bestMinRtt > 0 {
		b.minRtt = bestMinRtt
	}

	// Check if the min RTT window has expired.
	if !b.minRttTimestamp.IsZero() {
		elapsed := eventTime.Sub(b.minRttTimestamp)
		b.minRttExpired = elapsed > bbrMinRTTWindowSize
	}

	// Update the timestamp whenever we have a new best.
	if latestRtt <= b.minRtt {
		b.minRtt = latestRtt
		b.minRttTimestamp = eventTime
		b.minRttExpired = false
	}
}

// ---------- Round Tracking ----------

func (b *bbrv3Sender) updateRound(lastAckedPacket protocol.PacketNumber) {
	if lastAckedPacket > b.currentRoundTripEnd {
		b.roundCount++
		b.roundStart = true
		b.currentRoundTripEnd = b.largestSentPacketNumber
	} else {
		b.roundStart = false
	}
}

// ---------- State Machine ----------

// --- Startup ---

func (b *bbrv3Sender) checkStartupDone() {
	if b.startupFullBWReached {
		b.enterDrain()
		return
	}
	b.checkStartupFullBandwidth()
}

func (b *bbrv3Sender) checkStartupFullBandwidth() {
	if !b.roundStart {
		return
	}

	target := Bandwidth(float64(b.fullBandwidth) * bbrStartupFullBandwidthThreshold)
	if b.btlBw >= target {
		// Still growing — reset the counter.
		b.fullBandwidth = b.btlBw
		b.fullBandwidthCount = 0
		return
	}

	b.fullBandwidthCount++
	if b.fullBandwidthCount >= bbrStartupFullBandwidthRounds {
		b.startupFullBWReached = true
		b.enterDrain()
	}
}

func (b *bbrv3Sender) enterDrain() {
	b.mode = bbrDrain
	b.pacingGain = bbrDrainPacingGain
	b.cwndGain = bbrStartupCwndGain // keep cwnd high during drain
	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

// --- Drain ---

func (b *bbrv3Sender) checkDrain(bytesInFlight protocol.ByteCount) {
	if bytesInFlight <= b.targetCwnd() {
		b.enterProbeBW(b.clock.Now())
	}
}

// --- ProbeBW ---

func (b *bbrv3Sender) enterProbeBW(now monotime.Time) {
	b.mode = bbrProbeBW
	b.cwndGain = bbrProbeBWCwndGain

	// Start at a random-ish index (use round count mod 8, skip index 1 which is the drain phase).
	b.cycleIndex = int(b.roundCount) % len(bbrProbeBWPacingGainCycle)
	if b.cycleIndex == 1 {
		b.cycleIndex = 0
	}
	b.pacingGain = bbrProbeBWPacingGainCycle[b.cycleIndex]
	b.cycleStart = now
	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

func (b *bbrv3Sender) updateProbeBWCyclePhase(eventTime monotime.Time, bytesInFlight protocol.ByteCount) {
	// Advance to next phase when one min_rtt has elapsed.
	cycleElapsed := eventTime.Sub(b.cycleStart)

	if cycleElapsed > b.minRtt {
		b.advanceProbeBWCycle(eventTime)
	}
}

func (b *bbrv3Sender) advanceProbeBWCycle(now monotime.Time) {
	b.cycleIndex = (b.cycleIndex + 1) % len(bbrProbeBWPacingGainCycle)
	b.cycleStart = now
	b.pacingGain = bbrProbeBWPacingGainCycle[b.cycleIndex]
}

// --- ProbeRTT ---

func (b *bbrv3Sender) maybeEnterProbeRTT(eventTime monotime.Time) {
	if b.disableProbeRTT {
		return
	}
	if !b.minRttExpired {
		return
	}
	b.enterProbeRTT(eventTime)
}

func (b *bbrv3Sender) enterProbeRTT(eventTime monotime.Time) {
	b.mode = bbrProbeRTT
	b.pacingGain = 1.0
	b.priorCwnd = b.congestionWindow
	b.congestionWindow = b.minCongestionWindow()
	b.probeRttDoneAt = monotime.Time(0) // will be set once cwnd is drained
	b.probeRttRoundDone = false
	b.maybeQlogStateChange(qlog.CongestionStateApplicationLimited)
}

func (b *bbrv3Sender) handleProbeRTT(eventTime monotime.Time, bytesInFlight protocol.ByteCount) {
	// Maintain minimal cwnd.
	b.congestionWindow = b.minCongestionWindow()

	if b.probeRttDoneAt.IsZero() {
		// Wait until the in-flight bytes drain to the minimal cwnd.
		if bytesInFlight <= b.minCongestionWindow() {
			b.probeRttDoneAt = eventTime.Add(bbrProbeRTTDuration)
			b.probeRttRoundDone = false
			b.currentRoundTripEnd = b.largestSentPacketNumber
		}
		return
	}

	if !b.probeRttRoundDone {
		// Wait for a full round to pass.
		if b.roundStart {
			b.probeRttRoundDone = true
		}
		return
	}

	// Check if the probe duration has elapsed.
	if eventTime.After(b.probeRttDoneAt) || eventTime.Equal(b.probeRttDoneAt) {
		b.exitProbeRTT(eventTime)
	}
}

func (b *bbrv3Sender) exitProbeRTT(eventTime monotime.Time) {
	// Reset min RTT tracking.
	b.minRttTimestamp = eventTime
	b.minRttExpired = false

	// Restore cwnd.
	b.congestionWindow = max(b.priorCwnd, b.minCongestionWindow())

	// Transition to ProbeBW.
	b.enterProbeBW(eventTime)
}

// ---------- Cwnd Calculation ----------

func (b *bbrv3Sender) targetCwnd() protocol.ByteCount {
	if b.btlBw == 0 || b.minRtt == 0 {
		return b.congestionWindow
	}

	// BDP = btlBw (bytes/s) * minRtt (s)
	bdpBytesPerSec := uint64(b.btlBw / BytesPerSecond)
	bdp := protocol.ByteCount(bdpBytesPerSec * uint64(b.minRtt) / uint64(time.Second))

	var target protocol.ByteCount
	switch b.mode {
	case bbrProbeBW:
		// Habr Bufferbloat Mitigation: 0.85 × BDP.
		target = protocol.ByteCount(bbrBDPHeadroomMultiplier * float64(bdp))
	default:
		// Startup/Drain use cwndGain × BDP.
		target = protocol.ByteCount(b.cwndGain * float64(bdp))
	}

	// Floor: never below minimum cwnd.
	if target < b.minCongestionWindow() {
		target = b.minCongestionWindow()
	}
	return target
}

func (b *bbrv3Sender) updateCwnd() {
	if b.mode == bbrProbeRTT {
		// ProbeRTT manages cwnd directly.
		return
	}

	target := b.targetCwnd()
	maxCwnd := b.maxCongestionWindow()

	if target > maxCwnd {
		target = maxCwnd
	}

	// In Startup, only grow cwnd (never shrink).
	if b.mode == bbrStartup {
		if target > b.congestionWindow {
			b.congestionWindow = target
		}
		return
	}

	b.congestionWindow = target
}

func (b *bbrv3Sender) maxCongestionWindow() protocol.ByteCount {
	return b.maxDatagramSize * protocol.MaxCongestionWindowPackets
}

func (b *bbrv3Sender) minCongestionWindow() protocol.ByteCount {
	return b.maxDatagramSize * bbrMinCongestionWindowPackets
}

// ---------- qlog ----------

func (b *bbrv3Sender) maybeQlogStateChange(newState qlog.CongestionState) {
	if b.qlogger == nil || newState == b.lastState {
		return
	}
	b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: newState})
	b.lastState = newState
}

// ---------- Exported Helpers (for testing / diagnostics) ----------

// Mode returns the current BBR mode.
func (b *bbrv3Sender) Mode() bbrMode {
	return b.mode
}

// BtlBw returns the current bottleneck bandwidth estimate (bits/s).
func (b *bbrv3Sender) BtlBw() Bandwidth {
	return b.btlBw
}

// MinRtt returns the current windowed minimum RTT.
func (b *bbrv3Sender) MinRtt() time.Duration {
	return b.minRtt
}

// SetDisableProbeRTT sets whether ProbeRTT is disabled.
func (b *bbrv3Sender) SetDisableProbeRTT(disable bool) {
	b.disableProbeRTT = disable
}
