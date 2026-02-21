package congestion

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// ---------- BBR Mode (Top-Level State Machine) ----------

type bbrMode int

const (
	bbrStartup  bbrMode = iota // Exponentially probe bandwidth.
	bbrDrain                   // Drain the queue created during Startup.
	bbrProbeBW                 // Steady-state: cycle through sub-phases to probe bandwidth.
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

// ---------- ProbeBW Sub-States (BBRv3) ----------

type probeBWPhase int

const (
	probeBWDown   probeBWPhase = iota // Drain queue after a bandwidth probe.
	probeBWCruise                     // Maintain stable throughput at BDP.
	probeBWRefill                     // Refill the pipe before probing up.
	probeBWUp                         // Actively probe for more bandwidth.
)

func (p probeBWPhase) String() string {
	switch p {
	case probeBWDown:
		return "DOWN"
	case probeBWCruise:
		return "CRUISE"
	case probeBWRefill:
		return "REFILL"
	case probeBWUp:
		return "UP"
	default:
		return "UNKNOWN"
	}
}

// ---------- Constants ----------

const (
	// Startup pacing & cwnd gain: ln(2)/ln(4/3) ≈ 2.89.
	bbrStartupPacingGain = 2.89
	bbrStartupCwndGain   = 2.89

	// Drain pacing gain: 1/startup_gain ≈ 0.346.
	bbrDrainPacingGain = 1.0 / bbrStartupPacingGain

	// ProbeBW cwnd gain: 2.0 (headroom for probing phases).
	bbrProbeBWCwndGain = 2.0

	// ProbeBW sub-state pacing gains.
	bbrProbeBWDownPacingGain   = 0.9
	bbrProbeBWCruisePacingGain = 1.0
	bbrProbeBWRefillPacingGain = 1.0
	bbrProbeBWUpPacingGain     = 1.25

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

	// BBRv3 loss threshold: if loss rate exceeds 2% of inflight, react.
	bbrLossThreshold = 0.02

	// Pacing "death zone": QUIC critical jitter zone is 26–35 pps.
	bbrDeathZoneLowPPS  = 26
	bbrDeathZoneHighPPS = 35
	bbrSafeZonePPS      = 25

	// Default MTU for QUIC.
	bbrDefaultMTU = 1200
)

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

	// --- ProbeBW Sub-State Machine (BBRv3) ---
	probeBWPhase          probeBWPhase
	probeBWPhaseStart     monotime.Time // timestamp when we entered the current sub-phase
	probeBWCruiseDeadline monotime.Time // randomized CRUISE→REFILL transition time
	probeBWRefillRound    int64         // round count at which REFILL was entered
	probeBWUpRound        int64         // round count at which UP started

	// --- BBRv3 Inflight / Bandwidth Bounds ---
	inflightLo protocol.ByteCount // lower inflight bound (set during loss in CRUISE/DOWN)
	inflightHi protocol.ByteCount // upper inflight bound (set during ProbeBW_UP / Startup loss)
	bwLo       Bandwidth          // lower bandwidth bound

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

	// --- Loss tracking for current round ---
	lossInRound    protocol.ByteCount // bytes lost in current round
	inflightAtLoss protocol.ByteCount // bytes in flight when loss was detected

	// --- Per-round delivered tracking (BBRv3 loss rate denominator) ---
	lastDelivered         protocol.ByteCount // cumulative delivered from most recent bandwidth sample
	deliveredAtRoundStart protocol.ByteCount // cumulative delivered at start of current round

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

	// --- Diagnostic logging ---
	lastLogTime    time.Time // wall-clock of last diagnostic log line
	lastSampleRate Bandwidth // delivery rate from most recent bandwidth sample (bits/s)
}

var (
	_ SendAlgorithm               = &bbrv3Sender{}
	_ SendAlgorithmWithDebugInfos = &bbrv3Sender{}
	_ BandwidthSampleConsumer     = &bbrv3Sender{}
	_ ECNCongestionConsumer       = &bbrv3Sender{}
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
		b.updateProbeBWPhase(eventTime, priorInFlight)
		b.maybeEnterProbeRTT()
	case bbrProbeRTT:
		b.handleProbeRTT(eventTime, priorInFlight)
	}

	// 5. Update congestion window.
	b.updateCwnd()

	// 6. Diagnostic telemetry (throttled to ≤2 Hz).
	b.logState(priorInFlight)
}

// OnCongestionEvent is called when a packet is detected as lost.
func (b *bbrv3Sender) OnCongestionEvent(
	packetNumber protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	b.connStats.PacketsLost.Add(1)
	b.connStats.BytesLost.Add(uint64(lostBytes))

	// Track loss in this round for BBRv3 excessive-loss detection.
	b.lossInRound += lostBytes
	if b.inflightAtLoss == 0 || priorInFlight > b.inflightAtLoss {
		b.inflightAtLoss = priorInFlight
	}

	// Treat losses within the same cutback window as a single event.
	if packetNumber <= b.largestSentAtLastCutback {
		return
	}
	b.largestSentAtLastCutback = b.largestSentPacketNumber

	switch b.mode {
	case bbrStartup:
		// BBRv3: loss in Startup sets inflight_hi as a cap, but does NOT
		// trigger immediate exit. Startup exit remains bandwidth-plateau-only.
		b.inflightHi = priorInFlight
	case bbrProbeBW:
		b.handleProbeBWLoss(priorInFlight)
	case bbrDrain:
		// No cwnd cut in Drain — we are already draining.
	case bbrProbeRTT:
		// Loss in ProbeRTT: cap inflight_hi as in Startup.
		b.inflightHi = priorInFlight
	}

	b.maybeQlogStateChange(qlog.CongestionStateRecovery)
}

// handleProbeBWLoss implements BBRv3 loss response during ProbeBW.
func (b *bbrv3Sender) handleProbeBWLoss(priorInFlight protocol.ByteCount) {
	switch b.probeBWPhase {
	case probeBWUp:
		// Excessive loss during UP: cap inflight_hi, set bwLo, transition to DOWN.
		if b.isExcessiveLoss() {
			b.inflightHi = priorInFlight
			b.bwLo = b.btlBw
			b.enterProbeBWDown(b.clock.Now())
		}
	case probeBWCruise, probeBWDown:
		// During CRUISE/DOWN, tighten the lower inflight bound on loss.
		if b.inflightLo == 0 || priorInFlight < b.inflightLo {
			b.inflightLo = priorInFlight
		}
		// If excessive loss and bwLo is already set, tighten it proportionally.
		if b.isExcessiveLoss() && b.bwLo > 0 {
			lossRate := b.currentLossRate()
			b.bwLo = Bandwidth(float64(b.bwLo) * (1.0 - lossRate))
		}
	case probeBWRefill:
		// Loss in REFILL: tighten the lower inflight bound.
		if b.inflightLo == 0 || priorInFlight < b.inflightLo {
			b.inflightLo = priorInFlight
		}
	}
}

// isExcessiveLoss returns true if the loss rate in the current round exceeds
// the BBRv3 loss threshold: lost / (lost + delivered) > 2%.
func (b *bbrv3Sender) isExcessiveLoss() bool {
	var deliveredInRound protocol.ByteCount
	if b.lastDelivered > b.deliveredAtRoundStart {
		deliveredInRound = b.lastDelivered - b.deliveredAtRoundStart
	}
	total := b.lossInRound + deliveredInRound
	if total == 0 {
		return false
	}
	return float64(b.lossInRound) > bbrLossThreshold*float64(total)
}

// currentLossRate returns the loss rate in the current round:
// lost / (lost + delivered). Returns 0 if no events in the round.
func (b *bbrv3Sender) currentLossRate() float64 {
	var deliveredInRound protocol.ByteCount
	if b.lastDelivered > b.deliveredAtRoundStart {
		deliveredInRound = b.lastDelivered - b.deliveredAtRoundStart
	}
	total := b.lossInRound + deliveredInRound
	if total == 0 {
		return 0
	}
	return float64(b.lossInRound) / float64(total)
}

// OnRetransmissionTimeout is called on a retransmission timeout.
// BBRv3: RTO does not collapse cwnd. Instead, it sets inflight_hi as a cap
// at the current cwnd and transitions to ProbeBW_DOWN to re-probe gracefully.
// This preserves btlBw and minRtt estimates.
func (b *bbrv3Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	if b.congestionWindow > 0 {
		b.inflightHi = b.congestionWindow
	}
	b.enterProbeBWDown(b.clock.Now())
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

	// Apply bwLo cap (set during loss events, cleared in REFILL).
	if b.bwLo > 0 && pacingBw > b.bwLo {
		pacingBw = b.bwLo
	}

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

	// Track cumulative delivered for per-round loss rate calculation.
	if sample.Delivered > b.lastDelivered {
		b.lastDelivered = sample.Delivered
	}

	// Stash the latest sample rate for diagnostic logging.
	b.lastSampleRate = sample.DeliveryRate
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
		// Reset per-round loss tracking at the start of each round.
		b.lossInRound = 0
		b.inflightAtLoss = 0
		// Snapshot cumulative delivered at round start for loss rate calculation.
		b.deliveredAtRoundStart = b.lastDelivered
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
	// BBRv3: Drain exits when bytes in flight ≤ BDP.
	bdp := b.bdp()
	if bdp == 0 {
		bdp = b.targetCwnd() // fallback when BDP can't be computed
	}
	if bytesInFlight <= bdp {
		b.enterProbeBWCruise(b.clock.Now())
	}
}

// --- ProbeBW (BBRv3 sub-states: DOWN → CRUISE → REFILL → UP → DOWN ...) ---

func (b *bbrv3Sender) enterProbeBWDown(now monotime.Time) {
	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWDown
	b.probeBWPhaseStart = now
	b.pacingGain = bbrProbeBWDownPacingGain // 0.9
	b.cwndGain = bbrProbeBWCwndGain         // 2.0
	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

func (b *bbrv3Sender) enterProbeBWCruise(now monotime.Time) {
	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWCruise
	b.probeBWPhaseStart = now
	b.pacingGain = bbrProbeBWCruisePacingGain // 1.0
	b.cwndGain = bbrProbeBWCwndGain           // 2.0
	// Set a randomized deadline for CRUISE: [minRTT, 2×minRTT] from now.
	b.probeBWCruiseDeadline = now.Add(b.randomizedCruiseDuration())
	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

func (b *bbrv3Sender) enterProbeBWRefill(now monotime.Time) {
	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWRefill
	b.probeBWPhaseStart = now
	b.pacingGain = bbrProbeBWRefillPacingGain // 1.0
	b.cwndGain = bbrProbeBWCwndGain           // 2.0
	// Clear lower bounds: REFILL starts fresh before probing up.
	b.inflightLo = 0
	b.bwLo = 0
	// Record the round count; REFILL lasts exactly one round.
	b.probeBWRefillRound = b.roundCount
	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

func (b *bbrv3Sender) enterProbeBWUp(now monotime.Time) {
	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWUp
	b.probeBWPhaseStart = now
	b.pacingGain = bbrProbeBWUpPacingGain // 1.25
	b.cwndGain = bbrProbeBWCwndGain       // 2.0
	b.probeBWUpRound = b.roundCount
	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

// updateProbeBWPhase is called on each ACK while in ProbeBW mode.
// It checks whether the current sub-phase should transition.
func (b *bbrv3Sender) updateProbeBWPhase(eventTime monotime.Time, bytesInFlight protocol.ByteCount) {
	switch b.probeBWPhase {
	case probeBWDown:
		// Exit DOWN when inflight ≤ BDP.
		bdp := b.bdp()
		if bdp > 0 && bytesInFlight <= bdp {
			b.enterProbeBWCruise(eventTime)
		}
	case probeBWCruise:
		// Exit CRUISE when the randomized timer fires.
		if !b.probeBWCruiseDeadline.IsZero() && !eventTime.Before(b.probeBWCruiseDeadline) {
			b.enterProbeBWRefill(eventTime)
		}
	case probeBWRefill:
		// Exit REFILL after exactly one round has elapsed.
		if b.roundCount > b.probeBWRefillRound {
			b.enterProbeBWUp(eventTime)
		}
	case probeBWUp:
		// Exit UP if: (a) bytesInFlight exceeds 1.25 × BDP, OR
		// (b) a full round has elapsed.
		bdp := b.bdp()
		overshoot := bdp > 0 && bytesInFlight > protocol.ByteCount(float64(bdp)*bbrProbeBWUpPacingGain)
		roundElapsed := b.roundCount > b.probeBWUpRound
		if overshoot || (roundElapsed && bdp > 0) {
			// If no excessive loss, raise inflight_hi to the current level.
			if !b.isExcessiveLoss() && bytesInFlight > b.inflightHi {
				b.inflightHi = bytesInFlight
			}
			b.enterProbeBWDown(eventTime)
		}
	}
}

// randomizedCruiseDuration returns a duration in [minRTT, 2×minRTT].
func (b *bbrv3Sender) randomizedCruiseDuration() time.Duration {
	minDur := b.minRtt
	if minDur <= 0 {
		minDur = 100 * time.Millisecond // fallback
	}
	// rand in [0, minDur]
	jitter := time.Duration(rand.Int63n(int64(minDur) + 1))
	return minDur + jitter
}

// --- ProbeRTT ---

func (b *bbrv3Sender) maybeEnterProbeRTT() {
	if b.disableProbeRTT {
		return
	}
	if !b.minRttExpired {
		return
	}
	b.enterProbeRTT()
}

func (b *bbrv3Sender) enterProbeRTT() {
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

	// Transition to ProbeBW CRUISE (clean slate after RTT probe).
	b.enterProbeBWCruise(eventTime)
}

// ---------- Cwnd Calculation ----------

// bdp returns the current bandwidth-delay product in bytes.
func (b *bbrv3Sender) bdp() protocol.ByteCount {
	if b.btlBw == 0 || b.minRtt == 0 {
		return 0
	}
	bdpBytesPerSec := uint64(b.btlBw / BytesPerSecond)
	return protocol.ByteCount(bdpBytesPerSec * uint64(b.minRtt) / uint64(time.Second))
}

func (b *bbrv3Sender) targetCwnd() protocol.ByteCount {
	bdp := b.bdp()
	if bdp == 0 {
		return b.congestionWindow
	}

	var target protocol.ByteCount
	switch b.mode {
	case bbrProbeBW:
		// BBRv3 ProbeBW: cwnd = cwndGain × BDP, bounded by inflight caps.
		target = protocol.ByteCount(b.cwndGain * float64(bdp))
		// Apply inflight_hi cap (limits overshoot from probing).
		if b.inflightHi > 0 && target > b.inflightHi {
			target = b.inflightHi
		}
		// Apply inflight_lo cap during CRUISE and DOWN (limits steady-state queue).
		if b.probeBWPhase == probeBWCruise || b.probeBWPhase == probeBWDown {
			if b.inflightLo > 0 && target > b.inflightLo {
				target = b.inflightLo
			}
		}
	default:
		// Startup/Drain use cwndGain × BDP.
		target = protocol.ByteCount(b.cwndGain * float64(bdp))
	}

	// Global inflight_hi cap (set by Startup loss or ProbeBW_UP).
	if b.inflightHi > 0 && target > b.inflightHi {
		target = b.inflightHi
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

// ---------- Diagnostic Telemetry ----------

const bbrLogInterval = 500 * time.Millisecond

// logState prints a single-line diagnostic snapshot of the BBR state machine.
// It is throttled to fire at most once every 500 ms (wall-clock) so that it
// does not measurably affect throughput or flood the console.
func (b *bbrv3Sender) logState(bytesInFlight protocol.ByteCount) {
	now := time.Now()
	if now.Sub(b.lastLogTime) < bbrLogInterval {
		return
	}
	b.lastLogTime = now

	// Compute human-readable state label.
	state := b.mode.String()
	if b.mode == bbrProbeBW {
		state = "ProbeBW_" + b.probeBWPhase.String()
	}

	// Delivery rate from last sample in KB/s.
	sampleKBps := float64(b.lastSampleRate/BytesPerSecond) / 1024.0

	// Windowed max bandwidth in KB/s.
	btlKBps := float64(b.btlBw/BytesPerSecond) / 1024.0

	// MinRTT in ms.
	minRttMs := float64(b.minRtt) / float64(time.Millisecond)

	// BDP in bytes.
	bdp := b.bdp()

	// Pacing rate in KB/s.
	pacingKBps := float64(b.pacingRateBytesPerSec()) / 1024.0

	// bwLo in KB/s (0 = uncapped).
	bwLoKBps := float64(b.bwLo/BytesPerSecond) / 1024.0

	fmt.Printf("[BBRv3] state=%-16s | sample=%8.1f KB/s  btlBw=%8.1f KB/s  minRTT=%6.1f ms | "+
		"BDP=%8d  cwnd=%8d  inflight=%8d  pacing=%8.1f KB/s | "+
		"inflightHi=%8d  inflightLo=%8d  bwLo=%8.1f KB/s  round=%d  lossRound=%d\n",
		state,
		sampleKBps, btlKBps, minRttMs,
		bdp, b.congestionWindow, bytesInFlight, pacingKBps,
		b.inflightHi, b.inflightLo, bwLoKBps, b.roundCount, b.lossInRound,
	)
}

// ---------- qlog ----------

func (b *bbrv3Sender) maybeQlogStateChange(newState qlog.CongestionState) {
	if b.qlogger == nil || newState == b.lastState {
		return
	}
	b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: newState})
	b.lastState = newState
}

// ---------- ECN Congestion Response ----------

// OnECNCongestion handles ECN Congestion Experienced (CE) signals.
// In BBRv3, ECN-CE is treated as a signal to tighten bounds — similar to
// excessive loss but without actual byte loss.
func (b *bbrv3Sender) OnECNCongestion(priorInFlight protocol.ByteCount) {
	switch b.mode {
	case bbrStartup:
		b.inflightHi = priorInFlight
	case bbrProbeBW:
		b.handleProbeBWECN(priorInFlight)
	case bbrProbeRTT:
		b.inflightHi = priorInFlight
	case bbrDrain:
		// No reaction in Drain — we are already draining.
	}
}

// handleProbeBWECN implements BBRv3 ECN-CE response during ProbeBW.
func (b *bbrv3Sender) handleProbeBWECN(priorInFlight protocol.ByteCount) {
	switch b.probeBWPhase {
	case probeBWUp:
		// ECN-CE during UP: cap bounds and transition to DOWN.
		b.inflightHi = priorInFlight
		b.bwLo = b.btlBw
		b.enterProbeBWDown(b.clock.Now())
	case probeBWCruise, probeBWDown:
		// ECN-CE during CRUISE/DOWN: tighten lower inflight bound.
		if b.inflightLo == 0 || priorInFlight < b.inflightLo {
			b.inflightLo = priorInFlight
		}
	case probeBWRefill:
		// ECN-CE during REFILL: tighten lower inflight bound.
		if b.inflightLo == 0 || priorInFlight < b.inflightLo {
			b.inflightLo = priorInFlight
		}
	}
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

// ProbeBWPhaseValue returns the current ProbeBW sub-phase.
func (b *bbrv3Sender) ProbeBWPhaseValue() probeBWPhase {
	return b.probeBWPhase
}

// InflightHi returns the current upper inflight bound.
func (b *bbrv3Sender) InflightHi() protocol.ByteCount {
	return b.inflightHi
}

// InflightLo returns the current lower inflight bound.
func (b *bbrv3Sender) InflightLo() protocol.ByteCount {
	return b.inflightLo
}

// BwLo returns the current lower bandwidth bound (bits/s). 0 means uncapped.
func (b *bbrv3Sender) BwLo() Bandwidth {
	return b.bwLo
}
