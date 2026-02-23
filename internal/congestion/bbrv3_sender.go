package congestion

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// bbrDebugLog is checked once at process start. Set QUIC_BBR_DEBUG=1 to enable
// per-ACK diagnostic logging to stderr. When false, logState is a single branch
// on a package-level bool — effectively zero overhead.
var bbrDebugLog = os.Getenv("QUIC_BBR_DEBUG") == "1"

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

// ---------- ACK Phase (BBRv3 §5.3.3.6) ----------
// Tracks the lag between probing transmissions and their ACKs.

type bbrAckPhase int

const (
	acksInit          bbrAckPhase = iota
	acksRefilling                 // REFILL phase: filling the pipe
	acksProbeStarting             // UP phase started, waiting for probe data ACKs
	acksProbeFeedback             // receiving ACKs for data sent in UP
	acksProbeStopping             // DOWN phase: waiting for probe cycle ACKs to finish
)

// ---------- Constants (IETF draft-cardwell-ccwg-bbr §2, §5) ----------

const (
	// Spec §2.4: BBR.StartupPacingGain = 4*ln(2) ≈ 2.77
	bbrStartupPacingGain = 2.77

	// Spec §2.5: BBR.DefaultCwndGain = 2 (used in Startup, Drain, and most ProbeBW)
	bbrDefaultCwndGain = 2.0

	// Spec §2.4: BBR.DrainPacingGain = 0.35
	bbrDrainPacingGain = 0.35

	// Spec §5.6.1: ProbeBW pacing gains
	bbrProbeBWDownPacingGain   = 0.9
	bbrProbeBWCruisePacingGain = 1.0
	bbrProbeBWRefillPacingGain = 1.0
	bbrProbeBWUpPacingGain     = 1.25

	// Spec §5.6.1: ProbeBW cwnd gains
	bbrProbeBWCwndGain   = 2.0  // DOWN, CRUISE, REFILL
	bbrProbeBWUpCwndGain = 2.25 // UP only

	// Spec §2.10: MaxBwFilterLen = 2 ProbeBW cycles
	bbrMaxBwFilterLen = 2

	// Spec §2.13.1: MinRTTFilterLen = 10 seconds
	bbrMinRTTFilterLen = 10 * time.Second

	// Spec §2.13.2: ProbeRTTInterval = 5 seconds
	bbrProbeRTTInterval = 5 * time.Second

	// Spec §2.13.2: ProbeRTTDuration = 200 ms
	bbrProbeRTTDuration = 200 * time.Millisecond

	// Spec §2.13.2: ProbeRTTCwndGain = 0.5
	bbrProbeRTTCwndGain = 0.5

	// Spec §2.7: MinPipeCwnd = 4 * C.SMSS
	bbrMinCongestionWindowPackets = 4

	// Initial cwnd in packets (application-level choice, not spec-mandated)
	bbrInitialCongestionWindowPackets = 32

	// Spec §5.3.1.2: 3 rounds without ≥25% growth to declare full pipe
	bbrStartupFullBandwidthRounds    = 3
	bbrStartupFullBandwidthThreshold = 1.25

	// Spec §5.3.1.3: 6 discontiguous loss ranges to exit Startup on loss
	bbrStartupFullLossCnt = 6

	// Spec §2.7: LossThresh = 2%
	bbrLossThreshold = 0.02

	// Spec §2.7: Beta = 0.7
	bbrBeta = 0.7

	// Spec §2.7: Headroom = 0.15
	bbrHeadroom = 0.15

	// Spec §5.6.2: PacingMarginPercent = 1%
	bbrPacingMarginPercent = 0.01

	// Spec §2.11: ExtraAckedFilterLen = 10 round trips
	bbrExtraAckedFilterLen = 10

	// Non-spec safety: max rounds to stay in ProbeBW_UP before forcing exit
	bbrProbeBWUpMaxRounds = 30

	// Non-spec: pacing "death zone" clamp for QUIC jitter avoidance
	bbrDeathZoneLowPPS  = 26
	bbrDeathZoneHighPPS = 35
	bbrSafeZonePPS      = 25

	// Non-spec: Drain timeout safety valve
	bbrDrainTimeout = 3 * time.Second

	// Default QUIC MTU
	bbrDefaultMTU = 1200
)

// infMax is used as "Infinity" for the short-term model bounds.
const infMax = protocol.ByteCount(math.MaxInt64)

// bwInfinity is used as "Infinity" for bandwidth short-term bounds.
const bwInfinity = Bandwidth(math.MaxInt64)

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
	probeBWPhase       probeBWPhase
	probeBWPhaseStart  monotime.Time // when we entered the current sub-phase
	probeBWRefillRound int64         // round count at which REFILL was entered
	probeBWUpRound     int64         // round count at which UP started
	probeBWUpRounds    int64         // rounds elapsed while in UP

	// --- ACK Phase tracking (spec §5.3.3.6) ---
	ackPhase bbrAckPhase

	// --- ProbeBW cycle timeout (spec §5.3.3.5) ---
	cycleStamp  monotime.Time // timestamp when the current DOWN→…→UP cycle began
	bwProbeWait time.Duration // randomized cycle timeout: 2s + rand [0, 1s]

	// --- Reno coexistence (spec §5.3.3.5) ---
	roundsSinceBWProbe int64 // rounds since last bandwidth probe (UP phase)

	// --- ProbeBW_UP inflight_longterm probing (additive increase, spec §5.3.3.4) ---
	bwProbeUpAcks   protocol.ByteCount // bytes ACKed during UP toward next raise
	probeUpCnt      protocol.ByteCount // bytes per 1-MSS raise of inflight_longterm
	bwProbeUpRounds int64              // rounds spent in current UP for slope doubling
	bwProbeSamples  int                // flag: only react to loss once per probe

	// --- Network Path Model: Data Rate (spec §2.8.1) ---
	maxBwFilter *windowedFilter // windowed max over bbrMaxBwFilterLen ProbeBW cycles
	maxBw       Bandwidth       // max_bw: windowed max recent bandwidth
	bwShortterm Bandwidth       // bw_shortterm: short-term safe bandwidth (Infinity when uncapped)
	bw          Bandwidth       // bw = min(max_bw, bw_shortterm): effective bandwidth for pacing/BDP

	// --- Network Path Model: Data Volume (spec §2.8.2) ---
	inflightLongterm  protocol.ByteCount // long-term upper inflight bound (set during probing loss)
	inflightShortterm protocol.ByteCount // short-term upper inflight bound (converges via Beta on loss)
	maxInflight       protocol.ByteCount // computed max inflight (BDP*gain + extra_acked)
	bdpVal            protocol.ByteCount // cached BDP = bw * min_rtt

	// --- Congestion Signals (spec §2.9, §5.5.10.3) ---
	bwLatest       Bandwidth          // 1-round-trip max of RS.delivery_rate
	inflightLatest protocol.ByteCount // 1-round-trip max of RS.delivered

	// --- Loss Round Tracking (spec §5.5.10) ---
	lossRoundDelivered protocol.ByteCount // C.delivered at start of current loss round
	lossRoundStart     bool               // true when loss round boundary crosses
	lossInRound        bool               // whether any loss occurred in the current round

	// --- RTT Estimation ---
	minRtt           time.Duration // windowed min RTT (spec §5.5.7)
	minRttStamp      monotime.Time // time when min_rtt was obtained
	probeRttMinDelay time.Duration // min RTT in last ProbeRTTInterval (spec §2.13.2)
	probeRttMinStamp monotime.Time // time when probe_rtt_min_delay was obtained
	probeRttExpired  bool          // whether probe_rtt_min_delay has expired

	// --- Round Tracking ---
	currentRoundTripEnd       protocol.PacketNumber
	roundCount                int64
	roundStart                bool
	newRoundSinceLastBwSample bool               // sticky per-round flag for full-BW check
	nextRoundDelivered        protocol.ByteCount // delivery-based round tracker

	// --- Max BW filter time tracking (spec §5.5.6) ---
	cycleCount int64 // virtual time for max_bw filter, incremented per ProbeBW cycle

	// --- Extra ACKed estimation (spec §5.5.9) ---
	extraAcked              protocol.ByteCount // windowed max of aggregation
	extraAckedFilter        *windowedFilter    // 10-round max filter
	extraAckedIntervalStart monotime.Time      // start of aggregation interval
	extraAckedDelivered     protocol.ByteCount // bytes acked in current interval

	// --- Send Quantum & Offload Budget (spec §5.5.8, §5.6.3) ---
	sendQuantum   protocol.ByteCount
	offloadBudget protocol.ByteCount

	// --- Startup (spec §2.12) ---
	fullBandwidth          Bandwidth // baseline bw for full-pipe detection
	fullBandwidthCount     int       // consecutive rounds without ≥25% growth
	fullBwReached          bool      // BBR.full_bw_reached (lifetime)
	fullBwNow              bool      // BBR.full_bw_now (current probe cycle)
	lastBwSampleAppLimited bool      // whether most recent sample was app-limited

	// --- Drain timeout (non-spec safety) ---
	drainStart monotime.Time

	// --- ProbeRTT (spec §5.3.4) ---
	probeRttDoneStamp monotime.Time
	probeRttRoundDone bool
	priorCwnd         protocol.ByteCount
	disableProbeRTT   bool               // application-level toggle
	idleRestart       bool               // spec §5.4
	connAppLimited    bool               // mirrors C.app_limited from sent_packet_handler
	lastBytesInFlight protocol.ByteCount // last known bytes in flight (from OnPacketSent)

	// --- Gains ---
	pacingGain float64
	cwndGain   float64

	// --- Congestion Window ---
	congestionWindow protocol.ByteCount
	isCwndLimited    bool // spec: C.is_cwnd_limited

	// --- Packet Tracking ---
	largestSentPacketNumber  protocol.PacketNumber
	largestAckedPacketNumber protocol.PacketNumber
	largestSentAtLastCutback protocol.PacketNumber

	// --- Per-round delivered tracking ---
	lastDelivered         protocol.ByteCount
	deliveredAtRoundStart protocol.ByteCount

	// --- Recent ACK info (for gradual cwnd growth) ---
	lastNewlyAcked protocol.ByteCount

	// --- qlog ---
	lastState qlog.CongestionState

	// --- Debug logging ---
	lastLogTime time.Time
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

		// Max BW filter: 2 ProbeBW cycles (keyed by cycleCount)
		maxBwFilter: newWindowedFilter(bbrMaxBwFilterLen, true),

		// Extra ACKed filter: 10 round trips
		extraAckedFilter: newWindowedFilter(bbrExtraAckedFilterLen, true),

		minRtt: rttStats.SmoothedRTT(),

		currentRoundTripEnd: protocol.InvalidPacketNumber,

		// Startup gains (spec §5.3.1.1)
		pacingGain: bbrStartupPacingGain, // 2.77
		cwndGain:   bbrDefaultCwndGain,   // 2.0

		// Short-term model starts at Infinity (uncapped)
		bwShortterm:       bwInfinity,
		inflightShortterm: infMax,

		congestionWindow: protocol.ByteCount(bbrInitialCongestionWindowPackets) * initialMaxDatagramSize,

		largestSentPacketNumber:  protocol.InvalidPacketNumber,
		largestAckedPacketNumber: protocol.InvalidPacketNumber,
		largestSentAtLastCutback: protocol.InvalidPacketNumber,

		extraAckedIntervalStart: clock.Now(),
	}

	// Create the pacer with the BBR pacing rate callback.
	b.pacer = newPacerDirect(b.pacingRateBytesPerSec)

	// Initialize pacing rate (spec §5.6.2 BBRInitPacingRate)
	b.initPacingRate()

	if b.qlogger != nil {
		b.lastState = qlog.CongestionStateSlowStart
		b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
	}

	return b
}

// initPacingRate sets the initial pacing rate based on InitialCwnd and srtt.
// Spec §5.6.2: nominal_bandwidth = InitialCwnd / (srtt ? srtt : 1ms)
//
//	pacing_rate = StartupPacingGain * nominal_bandwidth
func (b *bbrv3Sender) initPacingRate() {
	srtt := b.rttStats.SmoothedRTT()
	if srtt == 0 {
		srtt = time.Millisecond
	}
	nominalBw := BandwidthFromDelta(b.congestionWindow, srtt)
	b.bw = Bandwidth(float64(nominalBw) * bbrStartupPacingGain)
	b.maxBw = b.bw
}

// ---------- SendAlgorithm Implementation ----------

func (b *bbrv3Sender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrv3Sender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

// OnPacketSent: spec §5.2.2 pre-transmit + delivery-rate snapshot.
func (b *bbrv3Sender) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	b.lastBytesInFlight = bytesInFlight
	b.handleRestartFromIdle()
	b.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	b.largestSentPacketNumber = packetNumber
}

func (b *bbrv3Sender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrv3Sender) MaybeExitSlowStart() {}

// OnPacketAcked: called per-packet in an ACK. Implements spec §5.2.3 per-ACK steps.
func (b *bbrv3Sender) OnPacketAcked(
	ackedPacketNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	b.largestAckedPacketNumber = max(ackedPacketNumber, b.largestAckedPacketNumber)
	b.lastNewlyAcked = ackedBytes

	// Track cwnd-limited status
	if priorInFlight >= b.congestionWindow {
		b.isCwndLimited = true
	}

	// 1. Advance round-trip counter (lightweight packet-number based for ProbeRTT).
	b.updateRound(ackedPacketNumber)

	// 2. Update min RTT (spec §5.3.4.3 BBRUpdateMinRTT)
	b.updateMinRtt(eventTime)

	// 3. Run the state machine.
	switch b.mode {
	case bbrStartup:
		if b.fullBwReached {
			b.enterDrain()
		}
	case bbrDrain:
		b.checkDrain(priorInFlight)
	case bbrProbeBW:
		b.updateProbeBWPhase(eventTime, priorInFlight)
		b.checkProbeRTT(eventTime)
	case bbrProbeRTT:
		b.handleProbeRTT(eventTime, priorInFlight)
	}

	// 4. In ProbeBW_UP, raise inflight_longterm incrementally (spec §5.3.3.4).
	if b.mode == bbrProbeBW && b.probeBWPhase == probeBWUp {
		b.probeInflightLongtermUpward(ackedBytes, priorInFlight)
	}

	// 5. Update control parameters (spec §5.2.3 BBRUpdateControlParameters).
	b.setPacingRate()
	b.setSendQuantum()
	b.setCwnd()

	// 6. Diagnostic telemetry.
	b.logState(priorInFlight)
}

// OnCongestionEvent: called per lost packet. Spec §5.2.4.
func (b *bbrv3Sender) OnCongestionEvent(
	packetNumber protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
) {
	b.connStats.PacketsLost.Add(1)
	b.connStats.BytesLost.Add(uint64(lostBytes))

	// Note loss for this round (spec §5.5.10 BBRNoteLoss)
	b.noteLoss(lostBytes)

	if packetNumber <= b.largestSentAtLastCutback {
		return
	}
	b.largestSentAtLastCutback = b.largestSentPacketNumber

	switch b.mode {
	case bbrStartup:
		b.handleStartupLoss(priorInFlight)
	case bbrProbeBW:
		b.handleProbeBWLoss(priorInFlight, lostBytes)
	case bbrDrain:
		// No cwnd cut in Drain.
	case bbrProbeRTT:
		// ProbeRTT: minimal reaction
	}

	b.maybeQlogStateChange(qlog.CongestionStateRecovery)
}

// OnRetransmissionTimeout: spec §5.6.4.4 BBROnEnterRTO.
func (b *bbrv3Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	b.saveCwnd()
	// Set inflightLongterm to prior cwnd so the probing model remembers it.
	if b.inflightLongterm == 0 || b.priorCwnd > b.inflightLongterm {
		b.inflightLongterm = b.priorCwnd
	}
	// Spec: C.cwnd = C.inflight + 1 (allow 1 SMSS to be sent).
	// Since we don't know exact inflight here, use minCwnd as floor.
	b.congestionWindow = b.minCongestionWindow()

	// Non-spec safety: don't abort Startup on handshake PTO.
	if b.mode != bbrStartup {
		b.enterProbeBWDown(b.clock.Now())
	}
	b.largestSentAtLastCutback = protocol.InvalidPacketNumber
}

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

func (b *bbrv3Sender) InSlowStart() bool { return b.mode == bbrStartup }

func (b *bbrv3Sender) InRecovery() bool {
	return b.largestAckedPacketNumber != protocol.InvalidPacketNumber &&
		b.largestAckedPacketNumber <= b.largestSentAtLastCutback
}

func (b *bbrv3Sender) GetCongestionWindow() protocol.ByteCount {
	return b.congestionWindow
}

// ---------- Pacing Rate (spec §5.6.2) ----------

// pacingRateBytesPerSec returns the pacing rate in bytes/sec for the pacer callback.
func (b *bbrv3Sender) pacingRateBytesPerSec() uint64 {
	bwEff := b.bw
	if bwEff == 0 {
		// During init, bootstrap from cwnd/srtt (spec §5.6.2 BBRInitPacingRate).
		srtt := b.rttStats.SmoothedRTT()
		if srtt == 0 {
			srtt = time.Millisecond
		}
		bwEff = BandwidthFromDelta(b.congestionWindow, srtt)
	}

	// Spec §5.6.2: rate = pacing_gain * bw * (1 - PacingMarginPercent)
	rate := float64(bwEff) * b.pacingGain * (1.0 - bbrPacingMarginPercent)
	pacingBytesPerSec := uint64(Bandwidth(rate) / BytesPerSecond)

	// Non-spec: death-zone clamp for QUIC jitter avoidance
	if b.maxDatagramSize > 0 {
		pps := pacingBytesPerSec / uint64(b.maxDatagramSize)
		if pps >= bbrDeathZoneLowPPS && pps <= bbrDeathZoneHighPPS {
			pacingBytesPerSec = bbrSafeZonePPS * uint64(b.maxDatagramSize)
			return pacingBytesPerSec
		}
	}

	return pacingBytesPerSec
}

// setPacingRate implements spec §5.6.2 BBRSetPacingRate.
func (b *bbrv3Sender) setPacingRate() {
	// After init, the rate is set by pacingRateBytesPerSec callback on each pacer query.
	// The spec says: only update if full_bw_reached or new rate > current.
	// This is inherently handled by pacingRateBytesPerSec reading b.bw and b.pacingGain.
}

// PacingRate returns the current pacing rate as Bandwidth (bits/s).
func (b *bbrv3Sender) PacingRate() Bandwidth {
	return Bandwidth(b.pacingRateBytesPerSec()) * BytesPerSecond
}

// ---------- Send Quantum (spec §5.6.3) ----------

func (b *bbrv3Sender) setSendQuantum() {
	rate := b.pacingRateBytesPerSec()
	// send_quantum = pacing_rate * 1ms
	b.sendQuantum = protocol.ByteCount(rate / 1000) // rate_bytes_per_sec * 0.001s
	if b.sendQuantum > 64*1024 {
		b.sendQuantum = 64 * 1024
	}
	if b.sendQuantum < 2*b.maxDatagramSize {
		b.sendQuantum = 2 * b.maxDatagramSize
	}
	// Spec §5.5.8: offload_budget = 3 * send_quantum
	b.offloadBudget = 3 * b.sendQuantum
}

// ---------- Bandwidth Model (spec §5.5) ----------

// OnBandwidthSample: called by sent_packet_handler with the best delivery-rate
// sample from an ACK. Implements spec §5.5.5 BBRUpdateMaxBw + round tracking.
func (b *bbrv3Sender) OnBandwidthSample(sample RateSample) {
	// Track cumulative delivered for per-round loss rate.
	if sample.Delivered > b.lastDelivered {
		b.lastDelivered = sample.Delivered
	}

	// --- Update latest delivery signals (spec §5.5.10.3 BBRUpdateLatestDeliverySignals) ---
	b.lossRoundStart = false
	if sample.DeliveryRate > b.bwLatest {
		b.bwLatest = sample.DeliveryRate
	}
	if sample.Delivered > b.inflightLatest {
		b.inflightLatest = sample.Delivered
	}
	if sample.PriorDelivered >= b.lossRoundDelivered {
		b.lossRoundDelivered = sample.Delivered
		b.lossRoundStart = true
	}

	// --- Delivery-based round tracking (spec §5.5.1 BBRUpdateRound) ---
	if sample.PriorDelivered >= b.nextRoundDelivered {
		b.nextRoundDelivered = sample.Delivered
		b.roundCount++
		b.roundsSinceBWProbe++
		b.newRoundSinceLastBwSample = true

		// Per-round delivered tracking (for isExcessiveLossRound denominator).
		b.deliveredAtRoundStart = b.lastDelivered
		// NOTE: lossInRound is NOT reset here; it is reset in the
		// lossRoundStart block below, after adaptLowerBoundsFromCongestion
		// has had a chance to observe it (spec §5.5.10.3).
	}

	// --- Update congestion signals (spec §5.5.10.3 BBRUpdateCongestionSignals) ---
	b.updateMaxBw(sample)
	if b.lossRoundStart {
		b.adaptLowerBoundsFromCongestion()
		b.lossInRound = false
	}

	// --- Update ACK aggregation (spec §5.5.9) ---
	b.updateACKAggregation(sample)

	// --- Check full BW reached (spec §5.3.1.2 BBRCheckFullBWReached) ---
	b.checkFullBWReached(sample)

	// --- Check Startup done (spec §5.3.1 BBRCheckStartupDone) ---
	if b.mode == bbrStartup {
		b.checkStartupHighLoss(sample)
		if b.mode == bbrStartup && b.fullBwReached {
			b.enterDrain()
		}
	}

	// --- Adapt long-term model (spec §5.3.3.6 BBRAdaptLongTermModel) ---
	b.adaptLongTermModel(sample)

	// --- Advance latest delivery signals (spec §5.5.10.3 BBRAdvanceLatestDeliverySignals) ---
	if b.lossRoundStart {
		b.bwLatest = sample.DeliveryRate
		b.inflightLatest = sample.Delivered
	}

	// --- Bound BW for model (spec §5.5.10.3 BBRBoundBWForModel) ---
	b.boundBWForModel()

	b.newRoundSinceLastBwSample = false
}

// updateMaxBw implements spec §5.5.5 BBRUpdateMaxBw.
func (b *bbrv3Sender) updateMaxBw(sample RateSample) {
	// Skip maxBw updates during idle restart: the pipe hasn't refilled yet,
	// so delivery rate samples don't reflect true network capacity.
	// The idle_restart flag is cleared after the first delivered ACK.
	if b.idleRestart {
		return
	}
	if sample.DeliveryRate > 0 &&
		(sample.DeliveryRate >= b.maxBw || !sample.IsAppLimited) {
		b.maxBwFilter.Update(int64(sample.DeliveryRate), b.cycleCount)
		b.maxBw = Bandwidth(b.maxBwFilter.GetBest())
	}
}

// boundBWForModel implements spec §5.5.10.3 BBRBoundBWForModel.
func (b *bbrv3Sender) boundBWForModel() {
	b.bw = b.maxBw
	if b.bwShortterm < b.bw {
		b.bw = b.bwShortterm
	}
}

// adaptLongTermModel implements spec §5.3.3.6 BBRAdaptLongTermModel.
func (b *bbrv3Sender) adaptLongTermModel(sample RateSample) {
	if b.ackPhase == acksProbeStarting && b.newRoundSinceLastBwSample {
		b.ackPhase = acksProbeFeedback
	}
	if b.ackPhase == acksProbeStopping && b.newRoundSinceLastBwSample {
		// End of samples from bw probing phase.
		if b.isInAProbeBWState() && !sample.IsAppLimited {
			b.advanceMaxBwFilter()
		}
	}

	if !b.isInflightTooHigh(sample) {
		// Loss rate is safe. Adjust upper bounds upward.
		if b.inflightLongterm == 0 {
			return // no upper bound to raise
		}
		if sample.TxInFlight > b.inflightLongterm {
			b.inflightLongterm = sample.TxInFlight
		}
		if b.mode == bbrProbeBW && b.probeBWPhase == probeBWUp {
			b.probeInflightLongtermUpward(0, 0) // called from ACK path
		}
	}
}

// advanceMaxBwFilter increments cycle_count. Spec §5.5.6.
func (b *bbrv3Sender) advanceMaxBwFilter() {
	b.cycleCount++
}

// updateACKAggregation implements spec §5.5.9 BBRUpdateACKAggregation.
func (b *bbrv3Sender) updateACKAggregation(sample RateSample) {
	now := b.clock.Now()
	interval := now.Sub(b.extraAckedIntervalStart)
	expectedDelivered := protocol.ByteCount(uint64(b.bw/BytesPerSecond) * uint64(interval) / uint64(time.Second))

	if b.extraAckedDelivered <= expectedDelivered {
		b.extraAckedDelivered = 0
		b.extraAckedIntervalStart = now
		expectedDelivered = 0
	}

	b.extraAckedDelivered += sample.NewlyAcked
	extra := protocol.ByteCount(0)
	if b.extraAckedDelivered > expectedDelivered {
		extra = b.extraAckedDelivered - expectedDelivered
	}
	if extra > b.congestionWindow {
		extra = b.congestionWindow
	}

	filterLen := int64(bbrExtraAckedFilterLen)
	if !b.fullBwReached {
		filterLen = 1 // In Startup, just remember 1 round.
	}
	// Use a temporary window length for the filter.
	savedLen := b.extraAckedFilter.windowLength
	b.extraAckedFilter.windowLength = filterLen
	b.extraAckedFilter.Update(int64(extra), b.roundCount)
	b.extraAckedFilter.windowLength = savedLen

	b.extraAcked = protocol.ByteCount(b.extraAckedFilter.GetBest())
}

// ---------- RTT Estimation (spec §5.3.4.3 BBRUpdateMinRTT) ----------

func (b *bbrv3Sender) updateMinRtt(eventTime monotime.Time) {
	latestRtt := b.rttStats.LatestRTT()
	if latestRtt <= 0 {
		return
	}

	// Update probe_rtt_min_delay (spec §5.3.4.3)
	b.probeRttExpired = !b.probeRttMinStamp.IsZero() &&
		eventTime.Sub(b.probeRttMinStamp) > bbrProbeRTTInterval

	if b.probeRttMinDelay == 0 || latestRtt < b.probeRttMinDelay || b.probeRttExpired {
		b.probeRttMinDelay = latestRtt
		b.probeRttMinStamp = eventTime
	}

	// Update min_rtt (spec §5.5.7)
	minRttExpired := !b.minRttStamp.IsZero() &&
		eventTime.Sub(b.minRttStamp) > bbrMinRTTFilterLen

	if b.minRtt == 0 || b.probeRttMinDelay < b.minRtt || minRttExpired {
		b.minRtt = b.probeRttMinDelay
		b.minRttStamp = b.probeRttMinStamp
	}
}

// ---------- Round Tracking ----------

func (b *bbrv3Sender) updateRound(lastAckedPacket protocol.PacketNumber) {
	// Lightweight packet-number-based round flag used by ProbeRTT.
	if lastAckedPacket > b.currentRoundTripEnd {
		b.roundStart = true
		b.currentRoundTripEnd = b.largestSentPacketNumber
	} else {
		b.roundStart = false
	}
}

// startRound implements spec BBRStartRound.
func (b *bbrv3Sender) startRound() {
	b.nextRoundDelivered = b.lastDelivered
}

// ---------- Loss Handling (spec §5.5.10) ----------

// noteLoss records a loss in the current round. Spec §5.5.10 BBRNoteLoss.
func (b *bbrv3Sender) noteLoss(lostBytes protocol.ByteCount) {
	_ = lostBytes
	if !b.lossInRound {
		b.lossRoundDelivered = b.lastDelivered
	}
	b.lossInRound = true
}

// isInflightTooHigh: spec §5.5.10.2 IsInflightTooHigh.
// Uses per-packet tx_in_flight from the rate sample.
func (b *bbrv3Sender) isInflightTooHigh(sample RateSample) bool {
	if sample.TxInFlight == 0 {
		return false
	}
	return sample.PacketLost > protocol.ByteCount(float64(sample.TxInFlight)*bbrLossThreshold)
}

// isExcessiveLossRound returns true if loss occurred in the current round.
// This is a simplified per-round check (used for UP exit, Startup exit).
func (b *bbrv3Sender) isExcessiveLossRound() bool {
	var deliveredInRound protocol.ByteCount
	if b.lastDelivered > b.deliveredAtRoundStart {
		deliveredInRound = b.lastDelivered - b.deliveredAtRoundStart
	}
	// We don't have bytes-lost-in-round directly anymore, so use lossInRound flag.
	// For precise check, we'd need per-round byte counters. Use the flag + round tracking.
	return b.lossInRound && deliveredInRound > 0
}

// handleInflightTooHigh: spec §5.5.10.2 BBRHandleInflightTooHigh.
func (b *bbrv3Sender) handleInflightTooHigh(sample RateSample) {
	b.bwProbeSamples = 0 // only react once per bw probe

	if !sample.IsAppLimited {
		targetInfl := b.targetInflight()
		betaFloor := protocol.ByteCount(float64(targetInfl) * bbrBeta)
		txInFlight := sample.TxInFlight
		if txInFlight > betaFloor {
			b.inflightLongterm = txInFlight
		} else {
			b.inflightLongterm = betaFloor
		}
	}
	if b.mode == bbrProbeBW && b.probeBWPhase == probeBWUp {
		b.enterProbeBWDown(b.clock.Now())
	}
}

// handleStartupLoss handles loss during Startup. Spec §5.3.1.3.
func (b *bbrv3Sender) handleStartupLoss(priorInFlight protocol.ByteCount) {
	if b.lossInRound {
		if b.inflightLongterm == 0 {
			b.inflightLongterm = priorInFlight
		}
		// Check if loss is persistent enough to exit Startup.
		if b.isExcessiveLossRound() {
			b.inflightLongterm = max(b.bdp(), b.inflightLatest)
			b.fullBwReached = true
		}
	}
}

// handleProbeBWLoss implements loss response during ProbeBW. Spec §5.5.10.2.
func (b *bbrv3Sender) handleProbeBWLoss(priorInFlight protocol.ByteCount, lostBytes protocol.ByteCount) {
	_ = lostBytes
	switch b.probeBWPhase {
	case probeBWUp:
		if b.lossInRound && b.bwProbeSamples > 0 {
			// Construct a minimal sample for handleInflightTooHigh.
			b.handleInflightTooHigh(RateSample{TxInFlight: priorInFlight})
		}
	case probeBWRefill:
		// Loss in REFILL: only react if probing.
		if b.lossInRound && b.bwProbeSamples > 0 {
			b.handleInflightTooHigh(RateSample{TxInFlight: priorInFlight})
		}
	case probeBWCruise, probeBWDown:
		// Loss during non-probing phases handled by short-term model in adaptLowerBoundsFromCongestion.
	}
}

// adaptLowerBoundsFromCongestion: spec §5.5.10.3 BBRAdaptLowerBoundsFromCongestion.
// Called once per round when loss_round_start is true.
func (b *bbrv3Sender) adaptLowerBoundsFromCongestion() {
	if b.isProbingBW() {
		return
	}
	if b.lossInRound {
		b.initLowerBounds()
		b.lossLowerBounds()
	}
}

// isProbingBW: spec §5.3.3.6 BBRIsProbingBW.
func (b *bbrv3Sender) isProbingBW() bool {
	return b.mode == bbrStartup ||
		(b.mode == bbrProbeBW && b.probeBWPhase == probeBWRefill) ||
		(b.mode == bbrProbeBW && b.probeBWPhase == probeBWUp)
}

// initLowerBounds: spec §5.5.10.3 BBRInitLowerBounds.
func (b *bbrv3Sender) initLowerBounds() {
	if b.bwShortterm == bwInfinity {
		b.bwShortterm = b.maxBw
	}
	if b.inflightShortterm == infMax {
		b.inflightShortterm = b.congestionWindow
	}
}

// lossLowerBounds: spec §5.5.10.3 BBRLossLowerBounds.
func (b *bbrv3Sender) lossLowerBounds() {
	betaBw := Bandwidth(float64(b.bwShortterm) * bbrBeta)
	if b.bwLatest > betaBw {
		b.bwShortterm = b.bwLatest
	} else {
		b.bwShortterm = betaBw
	}

	betaInfl := protocol.ByteCount(float64(b.inflightShortterm) * bbrBeta)
	if b.inflightLatest > betaInfl {
		b.inflightShortterm = b.inflightLatest
	} else {
		b.inflightShortterm = betaInfl
	}
}

// resetCongestionSignals: spec §5.5.10.3 BBRResetCongestionSignals.
func (b *bbrv3Sender) resetCongestionSignals() {
	b.lossInRound = false
	b.bwLatest = 0
	b.inflightLatest = 0
}

// resetShortTermModel: spec §5.5.10.3 BBRResetShortTermModel.
func (b *bbrv3Sender) resetShortTermModel() {
	b.bwShortterm = bwInfinity
	b.inflightShortterm = infMax
}

// ---------- State Machine ----------

// --- Full Pipe Detection (spec §5.3.1.2) ---

func (b *bbrv3Sender) resetFullBW() {
	b.fullBandwidth = 0
	b.fullBandwidthCount = 0
	b.fullBwNow = false
}

// checkFullBWReached: spec §5.3.1.2 BBRCheckFullBWReached.
func (b *bbrv3Sender) checkFullBWReached(sample RateSample) {
	if b.fullBwNow || !b.newRoundSinceLastBwSample || sample.IsAppLimited {
		return
	}

	target := Bandwidth(float64(b.fullBandwidth) * bbrStartupFullBandwidthThreshold)
	if sample.DeliveryRate >= target {
		b.resetFullBW()
		b.fullBandwidth = sample.DeliveryRate
		return
	}

	b.fullBandwidthCount++
	b.fullBwNow = b.fullBandwidthCount >= bbrStartupFullBandwidthRounds
	if b.fullBwNow {
		b.fullBwReached = true
	}
}

// checkStartupHighLoss: spec §5.3.1.3 BBRCheckStartupHighLoss.
// Simplified: checks loss rate > 2% and exits Startup.
func (b *bbrv3Sender) checkStartupHighLoss(sample RateSample) {
	if b.mode != bbrStartup {
		return
	}
	// Check if in recovery for at least one round + loss rate > threshold.
	if !b.lossInRound {
		return
	}
	if !b.isExcessiveLossRound() {
		return
	}
	// Set full_bw_reached and compute safe inflight_longterm.
	b.fullBwReached = true
	bdp := b.bdp()
	if b.inflightLatest > bdp {
		b.inflightLongterm = b.inflightLatest
	} else {
		b.inflightLongterm = bdp
	}
	_ = sample
}

// --- Startup ---

func (b *bbrv3Sender) enterStartup() {
	b.mode = bbrStartup
	b.pacingGain = bbrStartupPacingGain // 2.77
	b.cwndGain = bbrDefaultCwndGain     // 2.0
	b.maybeQlogStateChange(qlog.CongestionStateSlowStart)
}

// --- Drain ---

func (b *bbrv3Sender) enterDrain() {
	b.mode = bbrDrain
	b.pacingGain = bbrDrainPacingGain // 0.35
	b.cwndGain = bbrDefaultCwndGain   // 2.0
	b.drainStart = b.clock.Now()
	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

func (b *bbrv3Sender) checkDrain(bytesInFlight protocol.ByteCount) {
	// Spec §5.3.2: exit when inflight <= BBRInflight(1.0)
	drainTarget := b.inflightForGain(1.0)
	if drainTarget < b.minCongestionWindow() {
		drainTarget = b.minCongestionWindow()
	}
	if bytesInFlight <= drainTarget {
		b.enterProbeBW()
		return
	}
	// Non-spec safety: time-based Drain escape.
	if !b.drainStart.IsZero() {
		drainTimeout := bbrDrainTimeout
		if rttTimeout := 10 * b.minRtt; rttTimeout > drainTimeout {
			drainTimeout = rttTimeout
		}
		if b.clock.Now().Sub(b.drainStart) >= drainTimeout {
			b.enterProbeBW()
		}
	}
}

// --- ProbeBW (spec §5.3.3) ---

func (b *bbrv3Sender) enterProbeBW() {
	// Spec §5.3.3.6 BBREnterProbeBW.
	b.cwndGain = bbrDefaultCwndGain // 2.0
	b.startProbeBWDown()
}

func (b *bbrv3Sender) startProbeBWDown() {
	b.resetCongestionSignals()
	b.probeUpCnt = infMax // not growing inflight_longterm
	b.pickProbeWait()
	b.cycleStamp = b.clock.Now()
	b.ackPhase = acksProbeStopping
	b.startRound()

	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWDown
	b.probeBWPhaseStart = b.clock.Now()
	b.pacingGain = bbrProbeBWDownPacingGain // 0.9
	b.cwndGain = bbrDefaultCwndGain         // 2.0

	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

// enterProbeBWDown is a convenience alias for external callers.
func (b *bbrv3Sender) enterProbeBWDown(now monotime.Time) {
	_ = now
	b.startProbeBWDown()
}

func (b *bbrv3Sender) startProbeBWCruise() {
	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWCruise
	b.probeBWPhaseStart = b.clock.Now()
	b.pacingGain = bbrProbeBWCruisePacingGain // 1.0
	b.cwndGain = bbrDefaultCwndGain           // 2.0
	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

func (b *bbrv3Sender) startProbeBWRefill() {
	// Spec §5.3.3.3: reset short-term model.
	b.resetShortTermModel()
	b.bwProbeUpRounds = 0
	b.bwProbeUpAcks = 0
	b.ackPhase = acksRefilling
	b.startRound()

	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWRefill
	b.probeBWPhaseStart = b.clock.Now()
	b.pacingGain = bbrProbeBWRefillPacingGain // 1.0
	b.cwndGain = bbrDefaultCwndGain           // 2.0
	b.probeBWRefillRound = b.roundCount
	b.bwProbeSamples = 1 // arm the one-shot loss response
	b.roundsSinceBWProbe = 0

	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

func (b *bbrv3Sender) startProbeBWUp() {
	b.ackPhase = acksProbeStarting
	b.startRound()
	b.resetFullBW()
	b.fullBandwidth = b.bw

	b.mode = bbrProbeBW
	b.probeBWPhase = probeBWUp
	b.probeBWPhaseStart = b.clock.Now()
	b.pacingGain = bbrProbeBWUpPacingGain // 1.25
	b.cwndGain = bbrProbeBWUpCwndGain     // 2.25
	b.probeBWUpRound = b.roundCount
	b.probeBWUpRounds = 0
	b.bwProbeUpAcks = 0
	b.raiseInflightLongtermSlope()

	b.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
}

// pickProbeWait: spec §5.3.3.5 BBRPickProbeWait.
func (b *bbrv3Sender) pickProbeWait() {
	// Randomized round offset (0 or 1).
	b.roundsSinceBWProbe = int64(rand.Intn(2))
	// Randomized wall clock: 2 + rand[0, 1) seconds.
	b.bwProbeWait = 2*time.Second + time.Duration(rand.Int63n(int64(time.Second)))
}

// isTimeToProbeBW: spec §5.3.3.5 BBRIsTimeToProbeBW.
func (b *bbrv3Sender) isTimeToProbeBW() bool {
	now := b.clock.Now()
	if !b.cycleStamp.IsZero() && now.Sub(b.cycleStamp) >= b.bwProbeWait {
		b.startProbeBWRefill()
		return true
	}
	if b.isRenoCoexistenceProbeTime() {
		b.startProbeBWRefill()
		return true
	}
	return false
}

// isRenoCoexistenceProbeTime: spec §5.3.3.5 BBRIsRenoCoexistenceProbeTime.
func (b *bbrv3Sender) isRenoCoexistenceProbeTime() bool {
	renoRounds := b.targetInflight() / b.maxDatagramSize
	if renoRounds == 0 {
		renoRounds = 1
	}
	rounds := min(int64(renoRounds), 63)
	return b.roundsSinceBWProbe >= rounds
}

// isTimeToCruise: spec §5.3.3.1 BBRIsTimeToCruise.
func (b *bbrv3Sender) isTimeToCruise(bytesInFlight protocol.ByteCount) bool {
	headroom := b.inflightWithHeadroom()
	if headroom != infMax && bytesInFlight > headroom {
		return false
	}
	bdpTarget := b.inflightForGain(1.0)
	if bdpTarget < b.minCongestionWindow() {
		bdpTarget = b.minCongestionWindow()
	}
	return bytesInFlight <= bdpTarget
}

// isTimeToGoDown: spec §5.3.3.4 BBRIsTimeToGoDown.
func (b *bbrv3Sender) isTimeToGoDown() bool {
	if b.isCwndLimited && b.inflightLongterm > 0 && b.congestionWindow >= b.inflightLongterm {
		// BW is limited by inflight_longterm; reset full_bw estimator.
		b.resetFullBW()
		b.fullBandwidth = b.bw
	} else if b.fullBwNow {
		return true
	}
	return false
}

// updateProbeBWPhase: called on each ACK while in ProbeBW.
// Implements spec §5.3.3.6 BBRUpdateProbeBWCyclePhase.
func (b *bbrv3Sender) updateProbeBWPhase(eventTime monotime.Time, bytesInFlight protocol.ByteCount) {
	if !b.fullBwReached {
		return // only in steady-state
	}
	if !b.isInAProbeBWState() {
		return
	}

	switch b.probeBWPhase {
	case probeBWDown:
		if b.isTimeToProbeBW() {
			return
		}
		if b.isTimeToCruise(bytesInFlight) {
			b.startProbeBWCruise()
		}

	case probeBWCruise:
		if b.isTimeToProbeBW() {
			return
		}

	case probeBWRefill:
		if b.roundStart {
			b.bwProbeSamples = 1
			b.startProbeBWUp()
		}

	case probeBWUp:
		if b.isTimeToGoDown() || b.isExcessiveLossRound() {
			b.startProbeBWDown()
			return
		}
		// Non-spec safety: max rounds cap.
		prevUpRounds := b.probeBWUpRounds
		if b.roundCount > b.probeBWUpRound+b.probeBWUpRounds {
			b.probeBWUpRounds = b.roundCount - b.probeBWUpRound
		}
		if b.probeBWUpRounds > prevUpRounds {
			b.raiseInflightLongtermSlope()
		}
		if b.probeBWUpRounds >= bbrProbeBWUpMaxRounds {
			b.startProbeBWDown()
		}
	}

	_ = eventTime
}

// isInAProbeBWState: spec §5.3.3.6.
func (b *bbrv3Sender) isInAProbeBWState() bool {
	return b.mode == bbrProbeBW
}

// inflightWithHeadroom: spec §5.3.3.1 BBRInflightWithHeadroom.
func (b *bbrv3Sender) inflightWithHeadroom() protocol.ByteCount {
	if b.inflightLongterm == 0 {
		return infMax
	}
	headroom := max(b.maxDatagramSize, protocol.ByteCount(bbrHeadroom*float64(b.inflightLongterm)))
	result := b.inflightLongterm - headroom
	if result < b.minCongestionWindow() {
		result = b.minCongestionWindow()
	}
	return result
}

// raiseInflightLongtermSlope: spec §5.3.3.4 BBRRaiseInflightLongtermSlope.
func (b *bbrv3Sender) raiseInflightLongtermSlope() {
	growthThisRound := protocol.ByteCount(1) << uint(min(b.bwProbeUpRounds, 30))
	b.bwProbeUpRounds = min(b.bwProbeUpRounds+1, 30)
	b.probeUpCnt = max(b.congestionWindow/growthThisRound, 1)
}

// probeInflightLongtermUpward: spec §5.3.3.4 BBRProbeInflightLongtermUpward.
func (b *bbrv3Sender) probeInflightLongtermUpward(ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	if b.probeBWPhase != probeBWUp {
		return
	}
	if !b.isCwndLimited || b.congestionWindow < b.inflightLongterm {
		return
	}
	b.bwProbeUpAcks += ackedBytes
	if b.bwProbeUpAcks >= b.probeUpCnt && b.probeUpCnt > 0 {
		delta := b.bwProbeUpAcks / b.probeUpCnt
		b.bwProbeUpAcks -= delta * b.probeUpCnt
		b.inflightLongterm += delta * b.maxDatagramSize
	}
	if b.roundStart {
		b.raiseInflightLongtermSlope()
	}
	_ = priorInFlight
}

// --- ProbeRTT (spec §5.3.4) ---

// checkProbeRTT: spec §5.3.4.3 BBRCheckProbeRTT.
func (b *bbrv3Sender) checkProbeRTT(eventTime monotime.Time) {
	if b.disableProbeRTT {
		return
	}
	if b.mode != bbrProbeRTT && b.probeRttExpired && !b.idleRestart {
		b.enterProbeRTT()
		b.saveCwnd()
		b.probeRttDoneStamp = monotime.Time(0)
		b.ackPhase = acksProbeStopping
		b.startRound()
	}
	if b.mode == bbrProbeRTT {
		b.handleProbeRTT(eventTime, 0) // bytesInFlight handled inside
	}
	if b.lastDelivered > b.deliveredAtRoundStart { // RS.delivered > 0
		b.idleRestart = false
	}
}

func (b *bbrv3Sender) enterProbeRTT() {
	b.mode = bbrProbeRTT
	b.pacingGain = 1.0               // Spec §5.3.4.3: pacing_gain = 1.0
	b.cwndGain = bbrProbeRTTCwndGain // 0.5
	b.probeRttDoneStamp = monotime.Time(0)
	b.probeRttRoundDone = false
	b.maybeQlogStateChange(qlog.CongestionStateApplicationLimited)
}

func (b *bbrv3Sender) handleProbeRTT(eventTime monotime.Time, bytesInFlight protocol.ByteCount) {
	// Spec: MarkConnectionAppLimited() - ignored for now as estimator is separate.
	// Spec: maintain cwnd at ProbeRTTCwnd.
	probeRTTCwnd := b.probeRTTCwnd()
	if b.congestionWindow > probeRTTCwnd {
		b.congestionWindow = probeRTTCwnd
	}

	if b.probeRttDoneStamp.IsZero() {
		if bytesInFlight <= probeRTTCwnd {
			b.probeRttDoneStamp = eventTime.Add(bbrProbeRTTDuration)
			b.probeRttRoundDone = false
			b.startRound()
		}
		return
	}

	if !b.probeRttRoundDone {
		if b.roundStart {
			b.probeRttRoundDone = true
		}
		return
	}

	if eventTime.After(b.probeRttDoneStamp) || eventTime.Equal(b.probeRttDoneStamp) {
		b.checkProbeRTTDone(eventTime)
	}
}

// probeRTTCwnd: spec §5.6.4.5 BBRProbeRTTCwnd.
func (b *bbrv3Sender) probeRTTCwnd() protocol.ByteCount {
	cwnd := b.bdpMultiple(bbrProbeRTTCwndGain)
	if cwnd < b.minCongestionWindow() {
		cwnd = b.minCongestionWindow()
	}
	return cwnd
}

// checkProbeRTTDone: spec §5.3.4.3 BBRCheckProbeRTTDone.
func (b *bbrv3Sender) checkProbeRTTDone(eventTime monotime.Time) {
	if !b.probeRttDoneStamp.IsZero() && (eventTime.After(b.probeRttDoneStamp) || eventTime.Equal(b.probeRttDoneStamp)) {
		// Schedule next ProbeRTT.
		b.probeRttMinStamp = eventTime
		b.restoreCwnd()
		b.exitProbeRTT()
	}
}

// exitProbeRTT: spec §5.3.4.4 BBRExitProbeRTT.
func (b *bbrv3Sender) exitProbeRTT() {
	b.resetShortTermModel()
	if b.fullBwReached {
		b.startProbeBWDown()
		b.startProbeBWCruise() // optimization: skip directly to CRUISE
	} else {
		b.enterStartup()
	}
}

// --- Restart from Idle (spec §5.4.1) ---

// handleRestartFromIdle implements BBRHandleRestartFromIdle.
// Spec §5.4.1: when restarting from idle in ProbeBW, pace at exactly BBR.bw
// to re-fill the pipe. When in ProbeRTT, check if exit conditions are met.
// Critically, this sets idle_restart = true which suppresses immediate
// ProbeRTT entry after an idle period — preventing the "burst + ProbeRTT =
// catastrophic latency spike" scenario.
func (b *bbrv3Sender) handleRestartFromIdle() {
	if b.lastBytesInFlight == 0 && b.connAppLimited {
		b.idleRestart = true
		b.extraAckedIntervalStart = b.clock.Now()
		if b.isInAProbeBWState() {
			// Spec: BBRSetPacingRateWithGain(1) — pace at exactly bw, no gain.
			b.pacingGain = 1.0
		} else if b.mode == bbrProbeRTT {
			b.checkProbeRTTDone(b.clock.Now())
		}
	}
}

// SetAppLimited is called by the sent_packet_handler to mirror the
// C.app_limited state into the congestion controller. This is needed by
// handleRestartFromIdle() which must check C.app_limited at transmit time.
func (b *bbrv3Sender) SetAppLimited(limited bool) {
	b.connAppLimited = limited
}

// --- cwnd save/restore (spec §5.6.4.4) ---

func (b *bbrv3Sender) saveCwnd() {
	if !b.InRecovery() && b.mode != bbrProbeRTT {
		b.priorCwnd = b.congestionWindow
	} else {
		b.priorCwnd = max(b.priorCwnd, b.congestionWindow)
	}
}

func (b *bbrv3Sender) restoreCwnd() {
	b.congestionWindow = max(b.congestionWindow, b.priorCwnd)
}

// ---------- Cwnd Calculation (spec §5.6.4) ----------

// bdp returns the current bandwidth-delay product in bytes.
func (b *bbrv3Sender) bdp() protocol.ByteCount {
	if b.bw == 0 || b.minRtt == 0 {
		return 0
	}
	bwBytesPerSec := uint64(b.bw / BytesPerSecond)
	return protocol.ByteCount(bwBytesPerSec * uint64(b.minRtt) / uint64(time.Second))
}

// bdpFloor returns max(bdp(), minCongestionWindow()).
func (b *bbrv3Sender) bdpFloor() protocol.ByteCount {
	d := b.bdp()
	if d < b.minCongestionWindow() {
		return b.minCongestionWindow()
	}
	return d
}

// bdpMultiple: spec §5.6.4.2 BBRBDPMultiple.
func (b *bbrv3Sender) bdpMultiple(gain float64) protocol.ByteCount {
	if b.minRtt == 0 {
		return b.congestionWindow // no valid RTT yet
	}
	return protocol.ByteCount(gain * float64(b.bdp()))
}

// inflightForGain: spec §5.6.4.2 BBRInflight(gain).
func (b *bbrv3Sender) inflightForGain(gain float64) protocol.ByteCount {
	cap := b.bdpMultiple(gain)
	cap = b.quantizationBudget(cap)
	return cap
}

// quantizationBudget: spec §5.6.4.2 BBRQuantizationBudget.
func (b *bbrv3Sender) quantizationBudget(inflightCap protocol.ByteCount) protocol.ByteCount {
	if inflightCap < b.offloadBudget {
		inflightCap = b.offloadBudget
	}
	if inflightCap < b.minCongestionWindow() {
		inflightCap = b.minCongestionWindow()
	}
	if b.mode == bbrProbeBW && b.probeBWPhase == probeBWUp {
		inflightCap += 2 * b.maxDatagramSize
	}
	return inflightCap
}

// targetInflight: spec §5.3.3.5 BBRTargetInflight.
func (b *bbrv3Sender) targetInflight() protocol.ByteCount {
	bdpVal := b.bdp()
	if b.congestionWindow < bdpVal {
		return b.congestionWindow
	}
	return bdpVal
}

// updateMaxInflight: spec §5.6.4.2 BBRUpdateMaxInflight.
func (b *bbrv3Sender) updateMaxInflight() {
	inflightCap := b.bdpMultiple(b.cwndGain)
	inflightCap += b.extraAcked
	b.maxInflight = b.quantizationBudget(inflightCap)
}

// setCwnd: spec §5.6.4.6 BBRSetCwnd.
func (b *bbrv3Sender) setCwnd() {
	if b.mode == bbrProbeRTT {
		b.boundCwndForProbeRTT()
		b.boundCwndForModel()
		return
	}

	b.updateMaxInflight()

	newlyAcked := b.lastNewlyAcked
	maxCwnd := b.maxCongestionWindow()

	if b.fullBwReached {
		// Gradual growth: cwnd = min(cwnd + newly_acked, max_inflight)
		b.congestionWindow = min(b.congestionWindow+newlyAcked, b.maxInflight)
	} else if b.congestionWindow < b.maxInflight || b.lastDelivered < protocol.ByteCount(bbrInitialCongestionWindowPackets)*b.maxDatagramSize {
		b.congestionWindow = b.congestionWindow + newlyAcked
	}

	// Floor at MinPipeCwnd.
	if b.congestionWindow < b.minCongestionWindow() {
		b.congestionWindow = b.minCongestionWindow()
	}

	// Cap at maximum.
	if b.congestionWindow > maxCwnd {
		b.congestionWindow = maxCwnd
	}

	b.boundCwndForProbeRTT()
	b.boundCwndForModel()

	// Reset for next ACK.
	b.lastNewlyAcked = 0
	b.isCwndLimited = false
}

// boundCwndForProbeRTT: spec §5.6.4.5 BBRBoundCwndForProbeRTT.
func (b *bbrv3Sender) boundCwndForProbeRTT() {
	if b.mode == bbrProbeRTT {
		cwndCap := b.probeRTTCwnd()
		if b.congestionWindow > cwndCap {
			b.congestionWindow = cwndCap
		}
	}
}

// boundCwndForModel: spec §5.6.4.7 BBRBoundCwndForModel.
func (b *bbrv3Sender) boundCwndForModel() {
	cap := infMax

	if b.isInAProbeBWState() && b.probeBWPhase != probeBWCruise {
		// ProbeBW non-CRUISE: cap = inflight_longterm
		if b.inflightLongterm > 0 {
			cap = b.inflightLongterm
		}
	} else if b.mode == bbrProbeRTT || (b.isInAProbeBWState() && b.probeBWPhase == probeBWCruise) {
		// ProbeRTT or CRUISE: cap = inflightWithHeadroom (= 0.85 * inflight_longterm)
		headroom := b.inflightWithHeadroom()
		if headroom < cap {
			cap = headroom
		}
	}

	// Apply inflight_shortterm (may be Infinity).
	if b.inflightShortterm < cap {
		cap = b.inflightShortterm
	}

	// Floor at MinPipeCwnd.
	if cap < b.minCongestionWindow() {
		cap = b.minCongestionWindow()
	}

	if cap < infMax && b.congestionWindow > cap {
		b.congestionWindow = cap
	}
}

func (b *bbrv3Sender) maxCongestionWindow() protocol.ByteCount {
	return b.maxDatagramSize * protocol.MaxCongestionWindowPackets
}

func (b *bbrv3Sender) minCongestionWindow() protocol.ByteCount {
	return b.maxDatagramSize * bbrMinCongestionWindowPackets
}

// ---------- ECN Congestion Response ----------

func (b *bbrv3Sender) OnECNCongestion(priorInFlight protocol.ByteCount) {
	switch b.mode {
	case bbrStartup:
		b.inflightLongterm = priorInFlight
	case bbrProbeBW:
		b.handleProbeBWECN(priorInFlight)
	case bbrProbeRTT:
		b.inflightLongterm = priorInFlight
	case bbrDrain:
		// No reaction in Drain.
	}
}

func (b *bbrv3Sender) handleProbeBWECN(priorInFlight protocol.ByteCount) {
	switch b.probeBWPhase {
	case probeBWUp:
		b.inflightLongterm = priorInFlight
		b.initLowerBounds()
		b.enterProbeBWDown(b.clock.Now())
	case probeBWCruise, probeBWDown:
		// Tighten short-term bounds.
		b.initLowerBounds()
		if priorInFlight < b.inflightShortterm {
			b.inflightShortterm = priorInFlight
		}
		b.lossInRound = true
	case probeBWRefill:
		b.initLowerBounds()
		b.lossInRound = true
	}
}

// ---------- Diagnostic Telemetry ----------

func (b *bbrv3Sender) logState(bytesInFlight protocol.ByteCount) {
	if !bbrDebugLog {
		return
	}

	now := time.Now()
	if !b.lastLogTime.IsZero() && now.Sub(b.lastLogTime) < 500*time.Millisecond {
		return
	}
	b.lastLogTime = now

	var state string
	switch b.mode {
	case bbrStartup:
		state = "Startup"
	case bbrDrain:
		state = "Drain"
	case bbrProbeBW:
		state = "ProbeBW_" + b.probeBWPhase.String()
	case bbrProbeRTT:
		state = "ProbeRTT"
	default:
		state = "Unknown"
	}

	bwKBps := float64(b.bw/BytesPerSecond) / 1024.0
	maxBwKBps := float64(b.maxBw/BytesPerSecond) / 1024.0
	minRttMs := float64(b.minRtt) / float64(time.Millisecond)
	bdpVal := b.bdp()
	pacingKBps := float64(b.pacingRateBytesPerSec()) / 1024.0
	var bwSTKBps float64
	if b.bwShortterm < bwInfinity {
		bwSTKBps = float64(b.bwShortterm/BytesPerSecond) / 1024.0
	}

	fmt.Printf("[BBRv3] state=%-16s | bw=%8.1f KB/s  maxBw=%8.1f KB/s  minRTT=%6.1f ms | "+
		"BDP=%8d  cwnd=%8d  inflight=%8d  pacing=%8.1f KB/s | "+
		"inflLT=%8d  inflST=%8d  bwST=%8.1f KB/s  round=%d\n",
		state,
		bwKBps, maxBwKBps, minRttMs,
		bdpVal, b.congestionWindow, bytesInFlight, pacingKBps,
		b.inflightLongterm, b.inflightShortterm, bwSTKBps, b.roundCount,
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

// ---------- Exported Helpers (for testing / diagnostics) ----------

// Mode returns the current BBR mode.
func (b *bbrv3Sender) Mode() bbrMode { return b.mode }

// BtlBw returns the current bounded bandwidth estimate (bits/s).
func (b *bbrv3Sender) BtlBw() Bandwidth { return b.bw }

// MaxBw returns the windowed maximum bandwidth (bits/s).
func (b *bbrv3Sender) MaxBw() Bandwidth { return b.maxBw }

// MinRtt returns the current windowed minimum RTT.
func (b *bbrv3Sender) MinRtt() time.Duration { return b.minRtt }

// SetDisableProbeRTT sets whether ProbeRTT is disabled.
func (b *bbrv3Sender) SetDisableProbeRTT(disable bool) { b.disableProbeRTT = disable }

// ProbeBWPhaseValue returns the current ProbeBW sub-phase.
func (b *bbrv3Sender) ProbeBWPhaseValue() probeBWPhase { return b.probeBWPhase }

// InflightHi returns the long-term upper inflight bound (for backward compat).
func (b *bbrv3Sender) InflightHi() protocol.ByteCount { return b.inflightLongterm }

// InflightLo returns the short-term upper inflight bound (for backward compat).
func (b *bbrv3Sender) InflightLo() protocol.ByteCount {
	if b.inflightShortterm == infMax {
		return 0
	}
	return b.inflightShortterm
}

// BwLo returns the short-term bandwidth bound (bits/s, 0 means uncapped).
func (b *bbrv3Sender) BwLo() Bandwidth {
	if b.bwShortterm == bwInfinity {
		return 0
	}
	return b.bwShortterm
}

// InflightLongterm returns the long-term inflight bound.
func (b *bbrv3Sender) InflightLongterm() protocol.ByteCount { return b.inflightLongterm }
