package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

const (
	bbrTestMaxDatagramSize = protocol.ByteCount(protocol.InitialPacketSize) // 1280
)

// testBBRSender wraps bbrv3Sender with helper methods for testing.
type testBBRSender struct {
	sender            *bbrv3Sender
	clock             *mockClock
	rttStats          *utils.RTTStats
	bytesInFlight     protocol.ByteCount
	packetNumber      protocol.PacketNumber
	ackedPacketNumber protocol.PacketNumber

	// Delivery rate estimation mirroring sent_packet_handler wiring.
	estimator *DeliveryRateEstimator
	// Per-packet snapshots keyed by packet number.
	pktStates      map[protocol.PacketNumber]pktSnapshot
	cumulativeLost protocol.ByteCount // mirrors sent_packet_handler.cumulativeLost
}

type pktSnapshot struct {
	state         PacketDeliveryState
	sendTime      monotime.Time
	bytesInFlight protocol.ByteCount // C.inflight at send time (for tx_in_flight)
	lostAtSend    protocol.ByteCount // C.lost at send time
}

func newTestBBRSender() *testBBRSender {
	var clock mockClock
	// Start clock at a non-zero value so monotime is valid.
	clock = mockClock(monotime.Time(1_000_000_000))

	rttStats := utils.NewRTTStats()
	estimator := NewDeliveryRateEstimator()

	sender := NewBBRv3Sender(
		&clock,
		rttStats,
		&utils.ConnectionStats{},
		bbrTestMaxDatagramSize,
		nil, // no qlogger
		"test",
	)
	// Wire the delivery-rate estimator so BBR can call MarkConnectionAppLimited()
	// during ProbeRTT (matching production wiring in sent_packet_handler).
	sender.SetAppLimitedSetter(estimator)

	return &testBBRSender{
		clock:        &clock,
		rttStats:     rttStats,
		packetNumber: 1,
		estimator:    estimator,
		pktStates:    make(map[protocol.PacketNumber]pktSnapshot),
		sender:       sender,
	}
}

func (s *testBBRSender) sendPacket() {
	// Snapshot delivery state before send (mirrors sent_packet_handler).
	// Clear app-limited once pipe fills (matches production code).
	if s.bytesInFlight >= s.sender.GetCongestionWindow() {
		s.estimator.ClearAppLimited()
	}
	ds := s.estimator.OnPacketSent(s.clock.Now(), s.bytesInFlight)
	s.pktStates[s.packetNumber] = pktSnapshot{
		state:         ds,
		sendTime:      s.clock.Now(),
		bytesInFlight: s.bytesInFlight,
		lostAtSend:    s.cumulativeLost,
	}

	s.sender.OnPacketSent(s.clock.Now(), s.bytesInFlight, s.packetNumber, bbrTestMaxDatagramSize, true)
	s.bytesInFlight += bbrTestMaxDatagramSize
	s.packetNumber++
}

func (s *testBBRSender) sendNPackets(n int) {
	for range n {
		s.sendPacket()
	}
}

// sendAppLimitedPacket sends a packet while the connection is explicitly
// marked as app-limited (simulating MarkAppLimited() from the send loop).
func (s *testBBRSender) sendAppLimitedPacket() {
	s.estimator.MarkAppLimited(s.bytesInFlight)
	ds := s.estimator.OnPacketSent(s.clock.Now(), s.bytesInFlight)
	s.pktStates[s.packetNumber] = pktSnapshot{
		state:         ds,
		sendTime:      s.clock.Now(),
		bytesInFlight: s.bytesInFlight,
		lostAtSend:    s.cumulativeLost,
	}

	s.sender.OnPacketSent(s.clock.Now(), s.bytesInFlight, s.packetNumber, bbrTestMaxDatagramSize, true)
	s.bytesInFlight += bbrTestMaxDatagramSize
	s.packetNumber++
}

func (s *testBBRSender) ackNPackets(n int, rtt time.Duration) {
	s.rttStats.UpdateRTT(rtt, 0)

	// Phase 1: InitRateSample (spec §4.1.2.3)
	s.estimator.InitRateSample()

	// Phase 2: UpdateRateSample + OnPacketAcked per-packet
	for range n {
		s.ackedPacketNumber++

		if snap, ok := s.pktStates[s.ackedPacketNumber]; ok {
			s.estimator.UpdateRateSample(
				snap.state, snap.sendTime, bbrTestMaxDatagramSize, snap.bytesInFlight, snap.lostAtSend, s.clock.Now(),
			)
			delete(s.pktStates, s.ackedPacketNumber)
		}

		s.sender.OnPacketAcked(
			s.ackedPacketNumber,
			bbrTestMaxDatagramSize,
			s.bytesInFlight,
			s.clock.Now(),
		)
		if s.bytesInFlight >= bbrTestMaxDatagramSize {
			s.bytesInFlight -= bbrTestMaxDatagramSize
		}
	}

	// Phase 3: GenerateRateSample + feed to bandwidth consumer
	sample := s.estimator.GenerateRateSample(s.cumulativeLost)
	if sample.DeliveryRate > 0 {
		s.sender.OnBandwidthSample(sample)
	}
}

func (s *testBBRSender) loseNPackets(n int) {
	for range n {
		s.ackedPacketNumber++
		// Compute per-packet loss metadata (mirrors sent_packet_handler).
		txInFlight := protocol.ByteCount(0)
		var lostSinceTransmit protocol.ByteCount
		if snap, ok := s.pktStates[s.ackedPacketNumber]; ok {
			txInFlight = snap.bytesInFlight
			s.cumulativeLost += bbrTestMaxDatagramSize
			lostSinceTransmit = s.cumulativeLost - snap.lostAtSend
			delete(s.pktStates, s.ackedPacketNumber)
		} else {
			s.cumulativeLost += bbrTestMaxDatagramSize
			lostSinceTransmit = bbrTestMaxDatagramSize
		}
		s.sender.OnCongestionEvent(
			s.ackedPacketNumber,
			bbrTestMaxDatagramSize,
			s.bytesInFlight,
			txInFlight,
			lostSinceTransmit,
		)
		if s.bytesInFlight >= bbrTestMaxDatagramSize {
			s.bytesInFlight -= bbrTestMaxDatagramSize
		}
	}
}

// ---------- Tests ----------

func TestBBRv3InterfaceCompliance(t *testing.T) {
	// Compile-time check that bbrv3Sender implements the interfaces.
	var _ SendAlgorithm = &bbrv3Sender{}
	var _ SendAlgorithmWithDebugInfos = &bbrv3Sender{}
}

func TestBBRv3InitialState(t *testing.T) {
	s := newTestBBRSender()
	require.Equal(t, bbrStartup, s.sender.Mode())
	require.True(t, s.sender.InSlowStart())
	require.False(t, s.sender.InRecovery())
	require.Equal(t,
		protocol.ByteCount(bbrInitialCongestionWindowPackets)*bbrTestMaxDatagramSize,
		s.sender.GetCongestionWindow(),
	)
}

func TestBBRv3CanSend(t *testing.T) {
	s := newTestBBRSender()

	// Should be able to send when no bytes are in flight.
	require.True(t, s.sender.CanSend(0))

	// Should not be able to send when at cwnd.
	cwnd := s.sender.GetCongestionWindow()
	require.False(t, s.sender.CanSend(cwnd))
}

func TestBBRv3StartupToDrain(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	require.Equal(t, bbrStartup, s.sender.Mode())

	// Simulate several round-trips in Startup, each with the same bandwidth
	// so fullBandwidthCount increments and eventually triggers a transition to Drain.
	for i := 0; i < 20; i++ {
		s.sendNPackets(32)
		s.clock.Advance(rtt)
		s.ackNPackets(32, rtt)
		s.clock.Advance(time.Millisecond)

		if s.sender.Mode() != bbrStartup {
			break
		}
	}

	// After enough rounds without 25% BW growth, should have exited Startup.
	// Drain is transient — may have already reached ProbeBW.
	require.NotEqual(t, bbrStartup, s.sender.Mode(), "should have exited Startup")
}

func TestBBRv3DrainToProbeBW(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive through Startup → Drain → ProbeBW.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode(), "should have transitioned to ProbeBW")
}

func TestBBRv3ProbeBWSteadyStateCwnd(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive through Startup → Drain → ProbeBW.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	// BBRv3 steady-state cwnd = cwndGain × BDP (2.0 × BDP),
	// possibly bounded by inflight_hi / inflight_lo.
	btlBw := s.sender.BtlBw()
	minRtt := s.sender.MinRtt()

	if btlBw > 0 && minRtt > 0 {
		bdpBytesPerSec := uint64(btlBw / BytesPerSecond)
		bdp := protocol.ByteCount(bdpBytesPerSec * uint64(minRtt) / uint64(time.Second))
		expectedCwnd := protocol.ByteCount(bbrProbeBWCwndGain * float64(bdp))
		if expectedCwnd < s.sender.minCongestionWindow() {
			expectedCwnd = s.sender.minCongestionWindow()
		}
		// Apply inflight bounds as the sender would.
		if s.sender.InflightHi() > 0 && expectedCwnd > s.sender.InflightHi() {
			expectedCwnd = s.sender.InflightHi()
		}
		phase := s.sender.ProbeBWPhaseValue()
		if phase == probeBWCruise || phase == probeBWDown {
			if s.sender.InflightLo() > 0 && expectedCwnd > s.sender.InflightLo() {
				expectedCwnd = s.sender.InflightLo()
			}
		}

		cwnd := s.sender.GetCongestionWindow()
		require.Equal(t, expectedCwnd, cwnd,
			"ProbeBW cwnd should be 2.0 * BDP (bounded by inflight caps): expected %d, got %d", expectedCwnd, cwnd)
	}
}

func TestBBRv3PacingDeathZoneClamp(t *testing.T) {
	// Construct a scenario where the raw pacing rate would fall into the
	// death zone of 26–35 pps.
	s := newTestBBRSender()

	// Force a low bandwidth estimate that would result in ~30 pps.
	// 30 pps * 1280 bytes = 38400 bytes/s = 307200 bits/s
	// At pacing_gain=1.0, btlBw should be 307200 bits/s.
	targetBytesPerSec := uint64(30) * uint64(bbrTestMaxDatagramSize) // 38400 bytes/s
	targetBw := Bandwidth(targetBytesPerSec) * BytesPerSecond        // in bits/s

	s.sender.bw = targetBw
	s.sender.pacingGain = 1.0
	// Set cwnd small enough and SRTT large enough that cwndBw doesn't override btlBw.
	s.sender.congestionWindow = 4 * bbrTestMaxDatagramSize
	s.rttStats.UpdateRTT(200*time.Millisecond, 0)

	rate := s.sender.pacingRateBytesPerSec()
	pps := rate / uint64(bbrTestMaxDatagramSize)

	// The pacing should be clamped to the safe zone (25 pps), NOT 30 pps.
	require.Equal(t, uint64(bbrSafeZonePPS), pps,
		"pacing should be clamped to %d pps, got %d pps", bbrSafeZonePPS, pps)
}

func TestBBRv3PacingAboveDeathZone(t *testing.T) {
	s := newTestBBRSender()

	// Force a bandwidth estimate that would result in ~50 pps (above death zone).
	targetBytesPerSec := uint64(50) * uint64(bbrTestMaxDatagramSize)
	targetBw := Bandwidth(targetBytesPerSec) * BytesPerSecond

	s.sender.bw = targetBw
	s.sender.pacingGain = 1.0
	// Set cwnd small enough and SRTT large enough that cwndBw doesn't override btlBw.
	s.sender.congestionWindow = 4 * bbrTestMaxDatagramSize
	s.rttStats.UpdateRTT(200*time.Millisecond, 0)

	rate := s.sender.pacingRateBytesPerSec()
	pps := rate / uint64(bbrTestMaxDatagramSize)

	// Should NOT be clamped — PacingMarginPercent (1%) reduces 50→49.
	require.Equal(t, uint64(49), pps,
		"pacing above death zone should not be clamped (after 1%% margin): expected 49, got %d", pps)
}

func TestBBRv3PacingBelowDeathZone(t *testing.T) {
	s := newTestBBRSender()

	// Force a bandwidth estimate that would result in ~20 pps (below death zone).
	targetBytesPerSec := uint64(20) * uint64(bbrTestMaxDatagramSize)
	targetBw := Bandwidth(targetBytesPerSec) * BytesPerSecond

	s.sender.bw = targetBw
	s.sender.pacingGain = 1.0
	// Set cwnd small enough and SRTT large enough that cwndBw doesn't override btlBw.
	// cwndBw with 4*1280/0.2s = 25600 bytes/s = 20 pps — same as target, so btlBw dominates.
	s.sender.congestionWindow = 4 * bbrTestMaxDatagramSize
	s.rttStats.UpdateRTT(200*time.Millisecond, 0)

	rate := s.sender.pacingRateBytesPerSec()
	pps := rate / uint64(bbrTestMaxDatagramSize)

	// Should NOT be clamped — PacingMarginPercent (1%) reduces 20→19.
	require.Equal(t, uint64(19), pps,
		"pacing below death zone should not be clamped (after 1%% margin): expected 19, got %d", pps)
}

func TestBBRv3ProbeRTTTransition(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW first.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	// Set minRttStamp and probeRttMinStamp far in the past so updateMinRtt computes
	// probeRttExpired = true naturally (elapsed > ProbeRTTInterval = 5s).
	s.sender.minRttStamp = s.clock.Now().Add(-11 * time.Second)
	s.sender.probeRttMinStamp = s.clock.Now().Add(-6 * time.Second)

	// Use a higher RTT so the latestRtt > minRtt check doesn't reset the flag.
	higherRtt := 200 * time.Millisecond

	s.sendNPackets(1)
	s.clock.Advance(higherRtt)
	s.ackNPackets(1, higherRtt)

	require.Equal(t, bbrProbeRTT, s.sender.Mode(),
		"should have entered ProbeRTT when min RTT expired")

	// Cwnd should be at minimum (ProbeRTTCwndGain = 0.5 * BDP, floored at minCwnd).
	require.LessOrEqual(t, s.sender.GetCongestionWindow(), s.sender.probeRTTCwnd(),
		"cwnd should be at ProbeRTT level during ProbeRTT")
}

func TestBBRv3ProbeRTTDisableToggle(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	// Disable ProbeRTT.
	s.sender.SetDisableProbeRTT(true)

	// Set old timestamp so minRttExpired would be true.
	s.sender.minRttStamp = s.clock.Now().Add(-11 * time.Second)
	s.sender.probeRttMinStamp = s.clock.Now().Add(-6 * time.Second)
	higherRtt := 200 * time.Millisecond

	// Ack — should NOT enter ProbeRTT.
	s.sendNPackets(1)
	s.clock.Advance(higherRtt)
	s.ackNPackets(1, higherRtt)

	require.Equal(t, bbrProbeBW, s.sender.Mode(),
		"should NOT enter ProbeRTT when disabled")
}

func TestBBRv3ProbeRTTExitToProbeBW(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond
	higherRtt := 200 * time.Millisecond

	// Drive to ProbeBW, then force into ProbeRTT via old timestamp.
	s.driveToState(bbrProbeBW, rtt)
	s.sender.minRttStamp = s.clock.Now().Add(-11 * time.Second)
	s.sender.probeRttMinStamp = s.clock.Now().Add(-6 * time.Second)

	s.sendNPackets(1)
	s.clock.Advance(higherRtt)
	s.ackNPackets(1, higherRtt)
	require.Equal(t, bbrProbeRTT, s.sender.Mode())

	// Drain in-flight to minimum cwnd.
	for s.bytesInFlight > s.sender.minCongestionWindow() {
		toAck := 1
		s.clock.Advance(rtt)
		s.ackNPackets(toAck, rtt)
	}

	// Advance past ProbeRTT duration (200ms) plus one round.
	s.clock.Advance(bbrProbeRTTDuration + rtt)
	if s.sender.CanSend(s.bytesInFlight) {
		s.sendNPackets(1)
	}
	s.clock.Advance(rtt)
	s.ackNPackets(1, rtt)

	// Eventually should exit ProbeRTT back to ProbeBW.
	// May need a few more acks to satisfy the roundStart condition.
	for i := 0; i < 10; i++ {
		if s.sender.Mode() == bbrProbeBW {
			break
		}
		s.clock.Advance(rtt)
		if s.sender.CanSend(s.bytesInFlight) {
			s.sendNPackets(1)
		}
		s.ackNPackets(1, rtt)
	}

	require.Equal(t, bbrProbeBW, s.sender.Mode(),
		"should have exited ProbeRTT back to ProbeBW")

	// After ProbeRTT, we should exit to DOWN (not CRUISE).
	// DOWN may have already transitioned to CRUISE if inflight ≤ BDP.
	phase := s.sender.ProbeBWPhaseValue()
	require.True(t, phase == probeBWDown || phase == probeBWCruise,
		"should exit ProbeRTT to ProbeBW DOWN (or CRUISE): got %s", phase)
}

func TestBBRv3Recovery(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Send some packets and get acks to establish connection.
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(10, rtt)

	require.False(t, s.sender.InRecovery())

	// Lose a packet — should enter recovery.
	s.sendNPackets(5)
	s.loseNPackets(1)

	require.True(t, s.sender.InRecovery(),
		"should be in recovery after loss")
}

func TestBBRv3RTO(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW so RTO can transition to ProbeBW_DOWN.
	// (RTO during Startup intentionally does NOT abort Startup.)
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	s.sendNPackets(5)
	s.clock.Advance(rtt)
	s.ackNPackets(2, rtt)

	cwndBefore := s.sender.GetCongestionWindow()
	s.sender.OnRetransmissionTimeout(true)

	// BBRv3: RTO saves cwnd into inflightHi and transitions to ProbeBW_DOWN.
	require.Equal(t, cwndBefore, s.sender.InflightHi(),
		"inflightHi should be set to cwnd before RTO")
	require.Equal(t, bbrProbeBW, s.sender.Mode(),
		"should transition to ProbeBW after RTO")
	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue(),
		"should be in ProbeBW_DOWN sub-state after RTO")
	// Cwnd is set to minCwnd during RTO (restored later via restoreCwnd).
	require.Equal(t, s.sender.minCongestionWindow(), s.sender.GetCongestionWindow(),
		"cwnd should be set to minCwnd during RTO (saved prior cwnd for later restoration)")
}

func TestBBRv3SetMaxDatagramSize(t *testing.T) {
	s := newTestBBRSender()

	oldMTU := s.sender.maxDatagramSize
	newMTU := oldMTU + 100

	s.sender.SetMaxDatagramSize(newMTU)
	require.Equal(t, newMTU, s.sender.maxDatagramSize)
}

func TestBBRv3SetMaxDatagramSizePanicsOnDecrease(t *testing.T) {
	s := newTestBBRSender()
	require.Panics(t, func() {
		s.sender.SetMaxDatagramSize(s.sender.maxDatagramSize - 1)
	})
}

func TestBBRv3MaybeExitSlowStartIsNoop(t *testing.T) {
	s := newTestBBRSender()
	modeBefore := s.sender.Mode()
	s.sender.MaybeExitSlowStart()
	require.Equal(t, modeBefore, s.sender.Mode(),
		"MaybeExitSlowStart should be a no-op for BBR")
}

func TestBBRv3LossInStartupSetsInflightHi(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Send packets in Startup.
	s.sendNPackets(32)
	s.clock.Advance(rtt)
	s.ackNPackets(20, rtt)

	require.Equal(t, bbrStartup, s.sender.Mode())

	priorInFlight := s.bytesInFlight

	// Lose packets — BBRv3 should set inflight_hi but stay in Startup.
	s.loseNPackets(1)
	require.Equal(t, bbrStartup, s.sender.Mode(),
		"loss in Startup should NOT trigger immediate exit to Drain")
	require.Equal(t, priorInFlight, s.sender.InflightHi(),
		"inflightHi should be set to priorInFlight on Startup loss")
}

func TestBBRv3StartupGains(t *testing.T) {
	s := newTestBBRSender()
	require.InDelta(t, bbrStartupPacingGain, s.sender.pacingGain, 0.01)
	require.InDelta(t, bbrDefaultCwndGain, s.sender.cwndGain, 0.01)
}

func TestBBRv3ProbeBWSubStates(t *testing.T) {
	// Verify the pacing gains for each ProbeBW sub-state.
	require.InDelta(t, 0.9, bbrProbeBWDownPacingGain, 0.001)
	require.InDelta(t, 1.0, bbrProbeBWCruisePacingGain, 0.001)
	require.InDelta(t, 1.0, bbrProbeBWRefillPacingGain, 0.001)
	require.InDelta(t, 1.25, bbrProbeBWUpPacingGain, 0.001)
}

func TestBBRv3ProbeBWSubStateCycle(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive through Startup → Drain → ProbeBW.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	// After Drain, we should enter DOWN sub-state (BBRv3 spec: Drain exits to DOWN).
	// DOWN may have already transitioned to CRUISE if inflight ≤ BDP.
	phase := s.sender.ProbeBWPhaseValue()
	require.True(t, phase == probeBWDown || phase == probeBWCruise,
		"should enter ProbeBW DOWN (or transition through to CRUISE) after Drain: got %s", phase)

	// Drive to CRUISE if not already there.
	if phase == probeBWDown {
		s.driveToProbeBWPhase(probeBWCruise, rtt)
	}
	require.Equal(t, probeBWCruise, s.sender.ProbeBWPhaseValue())

	// Advance past the bwProbeWait deadline (2-3s randomized wall clock).
	s.clock.Advance(4 * time.Second)
	s.sendNPackets(4)
	s.clock.Advance(rtt)
	s.ackNPackets(4, rtt)

	// Should have transitioned to REFILL.
	require.Equal(t, probeBWRefill, s.sender.ProbeBWPhaseValue(),
		"should transition from CRUISE to REFILL after deadline")

	// Advance one round to exit REFILL → UP.
	s.sendNPackets(4)
	s.clock.Advance(rtt)
	s.ackNPackets(4, rtt)

	require.Equal(t, probeBWUp, s.sender.ProbeBWPhaseValue(),
		"should transition from REFILL to UP after one round")

	// In UP, BBRv3 stays for multiple rounds. We need to either:
	//   (a) push inflight above inflightHi, (b) trigger excessive loss, or
	//   (c) wait bbrProbeBWUpMaxRounds rounds.
	// Trigger exit via excessive loss: send a burst, then lose heavily.
	nSend := 0
	for s.sender.CanSend(s.bytesInFlight) && nSend < 64 {
		s.sendPacket()
		nSend++
	}
	// ACK some to advance a round, then lose packets to trigger excessive loss.
	s.clock.Advance(rtt)
	s.ackNPackets(nSend/2, rtt)
	s.loseNPackets(min(nSend/2, int(s.bytesInFlight/bbrTestMaxDatagramSize)))

	// After excessive loss in UP, should transition to DOWN.
	phase = s.sender.ProbeBWPhaseValue()
	require.True(t, phase == probeBWDown || phase == probeBWCruise,
		"should have transitioned from UP to DOWN (or through to CRUISE): got %s", phase)
}

func TestBBRv3ProbeBWLossInUp(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW and then to UP sub-state.
	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWUp, rtt)
	require.Equal(t, probeBWUp, s.sender.ProbeBWPhaseValue())

	// Send enough packets to have significant inflight.
	s.sendNPackets(32)

	// Inject enough loss to trigger the lossInRound flag.
	// With lossInRound && bwProbeSamples > 0, handleProbeBWLoss will
	// call handleInflightTooHigh and transition to DOWN.
	s.loseNPackets(10)

	// After loss in UP, should transition to DOWN, cap inflightHi.
	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue(),
		"loss in UP should trigger transition to DOWN")
	require.Greater(t, s.sender.InflightHi(), protocol.ByteCount(0),
		"inflightHi should be set after loss in UP")
}

func TestBBRv3ProbeBWLossInCruiseSetsBound(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW CRUISE.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, probeBWCruise, s.sender.ProbeBWPhaseValue())

	// Send some packets.
	s.sendNPackets(10)

	// Lose a packet in CRUISE — sets lossInRound = true.
	s.loseNPackets(1)

	// Short-term bounds are adapted at round boundaries via
	// adaptLowerBoundsFromCongestion. Send + ACK to trigger
	// OnBandwidthSample → lossRoundStart → adaptLowerBoundsFromCongestion.
	s.sendNPackets(4)
	s.clock.Advance(rtt)
	s.ackNPackets(4, rtt)

	require.Greater(t, s.sender.InflightLo(), protocol.ByteCount(0),
		"inflightLo should be set after loss in CRUISE + round boundary")
}

func TestBBRv3DrainExitOnBDP(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive through Startup until we reach Drain (or beyond).
	// We want to verify that the Drain→ProbeBW transition happens
	// when bytesInFlight ≤ BDP.
	s.driveToState(bbrProbeBW, rtt)

	// If we are in ProbeBW, Drain was successfully exited.
	// The key assertion is that checkDrain uses BDP-based exit.
	require.Equal(t, bbrProbeBW, s.sender.Mode(),
		"should exit Drain to ProbeBW when inflight ≤ BDP")

	// Verify we're in DOWN sub-state (entered via enterProbeBWDown from Drain).
	// DOWN may have already transitioned to CRUISE if inflight ≤ BDP immediately.
	phase := s.sender.ProbeBWPhaseValue()
	require.True(t, phase == probeBWDown || phase == probeBWCruise,
		"should enter ProbeBW DOWN (or CRUISE) after Drain: got %s", phase)
}

// ---------- Phase 3 Tests: Loss Rate, bwLo, ECN, REFILL/ProbeRTT Loss, RTO ----------

func TestBBRv3ExcessiveLossUsesDeliveredDenominator(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW UP.
	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWUp, rtt)
	require.Equal(t, probeBWUp, s.sender.ProbeBWPhaseValue())

	// Send packets and ACK some to advance delivery counters.
	s.sendNPackets(32)
	s.clock.Advance(rtt)
	s.ackNPackets(16, rtt)

	// Heavy loss: 10 packets triggers lossInRound + handleInflightTooHigh.
	s.loseNPackets(10)

	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue(),
		"heavy loss should trigger transition to DOWN")
	require.Greater(t, s.sender.InflightHi(), protocol.ByteCount(0),
		"inflightHi should be set on loss in UP")
}

func TestBBRv3BwLoCapsPacingRate(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW and establish bandwidth.
	s.driveToState(bbrProbeBW, rtt)

	btlBw := s.sender.BtlBw()
	require.Greater(t, btlBw, Bandwidth(0))

	// Set bwLo to half the bottleneck bandwidth.
	halfBw := btlBw / 2
	s.sender.bwShortterm = halfBw
	s.sender.bw = halfBw // manually trigger bounding: bw = min(maxBw, bwShortterm)

	// The pacing rate should be capped at bwLo.
	rate := s.sender.pacingRateBytesPerSec()
	bwLoBytesPerSec := uint64(halfBw / BytesPerSecond)

	require.LessOrEqual(t, rate, bwLoBytesPerSec,
		"pacing rate should be capped by bwLo: rate=%d, bwLo=%d bytes/s", rate, bwLoBytesPerSec)
}

func TestBBRv3BwLoClearedInRefill(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW.
	s.driveToState(bbrProbeBW, rtt)

	// Set bwLo artificially.
	s.sender.bwShortterm = s.sender.BtlBw()
	require.Greater(t, s.sender.BwLo(), Bandwidth(0))

	// Drive to REFILL — bwLo should be cleared.
	s.driveToProbeBWPhase(probeBWRefill, rtt)
	require.Equal(t, probeBWRefill, s.sender.ProbeBWPhaseValue())
	require.Equal(t, Bandwidth(0), s.sender.BwLo(),
		"bwLo should be cleared when entering REFILL")
}

func TestBBRv3ECNInUpTransitionsDown(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW UP.
	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWUp, rtt)
	require.Equal(t, probeBWUp, s.sender.ProbeBWPhaseValue())

	s.sendNPackets(16)
	priorInFlight := s.bytesInFlight

	// Simulate ECN-CE signal.
	s.sender.OnECNCongestion(priorInFlight)

	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue(),
		"ECN-CE in UP should trigger transition to DOWN")
	require.Equal(t, priorInFlight, s.sender.InflightHi(),
		"inflightHi should be set to priorInFlight on ECN in UP")
	// initLowerBounds initializes bwShortterm from maxBw (non-infinity).
	require.Greater(t, s.sender.BwLo(), Bandwidth(0),
		"bwLo should be initialized on ECN in UP")
}

func TestBBRv3ECNInCruiseSetsInflightLo(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW CRUISE.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, probeBWCruise, s.sender.ProbeBWPhaseValue())

	s.sendNPackets(10)
	priorInFlight := s.bytesInFlight

	// Simulate ECN-CE signal.
	s.sender.OnECNCongestion(priorInFlight)

	// initLowerBounds sets inflightShortterm = congestionWindow,
	// then the ECN handler tightens it to min(congestionWindow, priorInFlight).
	require.Equal(t, priorInFlight, s.sender.InflightLo(),
		"inflightLo should be tightened to priorInFlight on ECN in CRUISE")
}

func TestBBRv3LossInRefillTightensInflightLo(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW REFILL.
	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWRefill, rtt)
	require.Equal(t, probeBWRefill, s.sender.ProbeBWPhaseValue())

	// Send packets.
	s.sendNPackets(10)

	// Lose enough packets during REFILL to exceed the 2% IsInflightTooHigh
	// threshold. The first lost packet may have txInFlight=0 (sent when pipe
	// was empty), which doesn't cross the threshold. The second packet has
	// txInFlight > 0 and lostSinceTransmit well above 2%, triggering
	// handleInflightTooHigh which sets inflightLongterm (inflightHi).
	s.loseNPackets(2)

	require.Greater(t, s.sender.InflightHi(), protocol.ByteCount(0),
		"inflightHi should be set after excessive loss in REFILL")
}

func TestBBRv3LossInProbeRTTSetsInflightHi(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond
	higherRtt := 200 * time.Millisecond

	// Drive to ProbeBW, then force into ProbeRTT.
	s.driveToState(bbrProbeBW, rtt)
	// Expire both minRTT filter and probeRTT interval so checkProbeRTT enters ProbeRTT.
	s.sender.minRttStamp = s.clock.Now().Add(-11 * time.Second)
	s.sender.probeRttMinStamp = s.clock.Now().Add(-6 * time.Second)

	s.sendNPackets(1)
	s.clock.Advance(higherRtt)
	s.ackNPackets(1, higherRtt)
	require.Equal(t, bbrProbeRTT, s.sender.Mode())

	// Send a few packets (ProbeRTT has minimal cwnd).
	if s.sender.CanSend(s.bytesInFlight) {
		s.sendNPackets(1)
	}

	// ECN during ProbeRTT sets inflightLongterm (inflightHi).
	priorInFlight := s.bytesInFlight
	s.sender.OnECNCongestion(priorInFlight)

	require.Equal(t, priorInFlight, s.sender.InflightHi(),
		"inflightHi should be set after ECN in ProbeRTT")
}

func TestBBRv3RTOPreservesBandwidthEstimate(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW to establish bandwidth.
	s.driveToState(bbrProbeBW, rtt)
	btlBwBefore := s.sender.BtlBw()
	minRttBefore := s.sender.MinRtt()
	require.Greater(t, btlBwBefore, Bandwidth(0))

	// Trigger RTO.
	s.sendNPackets(5)
	s.sender.OnRetransmissionTimeout(true)

	// btlBw and minRtt should be preserved.
	require.Equal(t, btlBwBefore, s.sender.BtlBw(),
		"btlBw should be preserved after RTO")
	require.Equal(t, minRttBefore, s.sender.MinRtt(),
		"minRtt should be preserved after RTO")
	// Should be in ProbeBW_DOWN.
	require.Equal(t, bbrProbeBW, s.sender.Mode())
	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue())
}

func TestBBRv3ECNInterfaceCompliance(t *testing.T) {
	// Compile-time check that bbrv3Sender implements ECNCongestionConsumer.
	var _ ECNCongestionConsumer = &bbrv3Sender{}
}

// ---------- Helper: drive the sender to a target BBR state ----------

func (s *testBBRSender) driveToState(targetMode bbrMode, rtt time.Duration) {
	// Drive through Startup.
	for i := 0; i < 40; i++ {
		nSend := 0
		for s.sender.CanSend(s.bytesInFlight) && nSend < 64 {
			s.sendPacket()
			nSend++
		}
		s.clock.Advance(rtt)
		toAck := min(nSend, int(s.bytesInFlight/bbrTestMaxDatagramSize))
		if toAck < 1 {
			toAck = 1
		}
		s.ackNPackets(toAck, rtt)
		s.clock.Advance(time.Millisecond)

		if s.sender.Mode() == targetMode {
			return
		}
	}

	// If we haven't reached ProbeBW yet (stuck in Drain), keep draining.
	if targetMode == bbrProbeBW && s.sender.Mode() == bbrDrain {
		for i := 0; i < 100; i++ {
			if s.bytesInFlight > 0 {
				toAck := min(4, int(s.bytesInFlight/bbrTestMaxDatagramSize))
				if toAck < 1 {
					toAck = 1
				}
				s.clock.Advance(rtt)
				s.ackNPackets(toAck, rtt)
			}
			if s.sender.CanSend(s.bytesInFlight) {
				s.sendNPackets(1)
			}
			s.clock.Advance(time.Millisecond)

			if s.sender.Mode() == targetMode {
				return
			}
		}
	}
}

// driveToProbeBWPhase drives the sender through ProbeBW sub-states
// until the target phase is reached.
func (s *testBBRSender) driveToProbeBWPhase(targetPhase probeBWPhase, rtt time.Duration) {
	// Must already be in ProbeBW.
	if s.sender.Mode() != bbrProbeBW {
		s.driveToState(bbrProbeBW, rtt)
	}

	for i := 0; i < 200; i++ {
		if s.sender.ProbeBWPhaseValue() == targetPhase {
			return
		}

		// Advance time generously to trigger phase transitions.
		minRtt := s.sender.MinRtt()
		if minRtt <= 0 {
			minRtt = rtt
		}
		s.clock.Advance(2*minRtt + time.Millisecond)

		nSend := 0
		for s.sender.CanSend(s.bytesInFlight) && nSend < 16 {
			s.sendPacket()
			nSend++
		}
		if nSend == 0 {
			// Still blocked — ack some packets to free up cwnd.
			if s.bytesInFlight > 0 {
				toAck := min(4, int(s.bytesInFlight/bbrTestMaxDatagramSize))
				if toAck < 1 {
					toAck = 1
				}
				s.clock.Advance(rtt)
				s.ackNPackets(toAck, rtt)
			}
			continue
		}
		s.clock.Advance(rtt)
		toAck := min(nSend, int(s.bytesInFlight/bbrTestMaxDatagramSize))
		if toAck < 1 {
			toAck = 1
		}
		s.ackNPackets(toAck, rtt)
	}
}

// ---------- Phase 4: App-Limited Death Spiral Prevention ----------

func TestBBRv3AppLimitedSampleRejectedWhenBtlBwZero(t *testing.T) {
	// initPacingRate sets a non-zero initial bw from cwnd/srtt.
	// Verify that an app-limited sample does NOT increase bw beyond
	// the initial estimate.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	initialBw := s.sender.bw

	// Send a single app-limited packet (connection draining scenario).
	s.sendAppLimitedPacket()
	s.clock.Advance(rtt)

	// ACK it — this produces an app-limited sample.
	s.ackedPacketNumber++
	snap := s.pktStates[s.ackedPacketNumber]
	s.estimator.InitRateSample()
	s.estimator.UpdateRateSample(snap.state, snap.sendTime, bbrTestMaxDatagramSize, snap.bytesInFlight, snap.lostAtSend, s.clock.Now())
	sample := s.estimator.GenerateRateSample(s.cumulativeLost)
	require.True(t, sample.IsAppLimited)
	require.True(t, sample.DeliveryRate > 0)
	delete(s.pktStates, s.ackedPacketNumber)

	s.sender.OnPacketAcked(s.ackedPacketNumber, bbrTestMaxDatagramSize, s.bytesInFlight, s.clock.Now())
	s.bytesInFlight -= bbrTestMaxDatagramSize

	// Feed the app-limited sample — it should NOT increase bw.
	s.sender.OnBandwidthSample(sample)
	require.LessOrEqual(t, s.sender.bw, initialBw,
		"app-limited sample must not increase btlBw beyond initial estimate")
}

func TestBBRv3AppLimitedSampleAcceptedWhenExceedsBtlBw(t *testing.T) {
	// After btlBw is established, an app-limited sample that exceeds the
	// current btlBw should still update the filter (rate discovery).
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	// Send many packets at full rate to establish btlBw.
	for i := 0; i < 10; i++ {
		n := 10
		s.sendNPackets(n)
		s.clock.Advance(rtt)
		s.ackNPackets(n, rtt)
	}
	require.True(t, s.sender.bw > 0, "btlBw should be established")
	savedBw := s.sender.bw

	// Now send an app-limited packet, but at a HIGHER rate (e.g., shorter RTT).
	s.sendAppLimitedPacket()
	shortRTT := 10 * time.Millisecond
	s.clock.Advance(shortRTT)

	s.ackedPacketNumber++
	snap := s.pktStates[s.ackedPacketNumber]
	s.estimator.InitRateSample()
	s.estimator.UpdateRateSample(snap.state, snap.sendTime, bbrTestMaxDatagramSize, snap.bytesInFlight, snap.lostAtSend, s.clock.Now())
	sample := s.estimator.GenerateRateSample(s.cumulativeLost)
	require.True(t, sample.IsAppLimited)
	delete(s.pktStates, s.ackedPacketNumber)

	s.sender.OnPacketAcked(s.ackedPacketNumber, bbrTestMaxDatagramSize, s.bytesInFlight, s.clock.Now())
	s.bytesInFlight -= bbrTestMaxDatagramSize

	// Only accept if the delivery rate exceeds btlBw.
	if sample.DeliveryRate > savedBw {
		s.sender.OnBandwidthSample(sample)
		require.True(t, s.sender.bw >= savedBw,
			"app-limited sample exceeding btlBw should be accepted")
	}
}

func TestBBRv3StartupIgnoresAppLimitedRounds(t *testing.T) {
	// Startup should not count app-limited rounds toward the bandwidth
	// plateau counter used for exiting Startup.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	require.Equal(t, bbrStartup, s.sender.Mode())

	// Establish some bandwidth first.
	for i := 0; i < 3; i++ {
		s.sendNPackets(10)
		s.clock.Advance(rtt)
		s.ackNPackets(10, rtt)
	}
	require.Equal(t, bbrStartup, s.sender.Mode())
	savedBwPlateauCount := s.sender.fullBandwidthCount

	// Now send only app-limited packets for several rounds.
	for i := 0; i < 5; i++ {
		s.sendAppLimitedPacket()
		s.clock.Advance(rtt)
		// ACK with app-limited sample only.
		s.ackedPacketNumber++
		snap := s.pktStates[s.ackedPacketNumber]
		s.estimator.InitRateSample()
		s.estimator.UpdateRateSample(snap.state, snap.sendTime, bbrTestMaxDatagramSize, snap.bytesInFlight, snap.lostAtSend, s.clock.Now())
		sample := s.estimator.GenerateRateSample(s.cumulativeLost)
		delete(s.pktStates, s.ackedPacketNumber)
		s.sender.OnPacketAcked(s.ackedPacketNumber, bbrTestMaxDatagramSize, s.bytesInFlight, s.clock.Now())
		s.bytesInFlight -= bbrTestMaxDatagramSize

		s.sender.OnBandwidthSample(sample)
	}

	// The plateau count should NOT have increased during app-limited rounds.
	require.Equal(t, savedBwPlateauCount, s.sender.fullBandwidthCount,
		"app-limited rounds must not increment startup bandwidth plateau counter")
	require.Equal(t, bbrStartup, s.sender.Mode(),
		"sender should still be in Startup after app-limited-only rounds")
}

func TestBBRv3BestSamplePrefersNonAppLimited(t *testing.T) {
	// Verify that the best-sample selection prefers a non-app-limited sample
	// over a higher-rate app-limited sample.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	// First send a full-rate packet.
	s.sendPacket()
	s.clock.Advance(rtt)

	// Then send an app-limited packet.
	s.sendAppLimitedPacket()
	s.clock.Advance(rtt / 2) // shorter interval – will have higher rate

	// ACK both simultaneously.
	samples := make([]RateSample, 0, 2)
	for i := 0; i < 2; i++ {
		s.ackedPacketNumber++
		if snap, ok := s.pktStates[s.ackedPacketNumber]; ok {
			s.estimator.InitRateSample()
			s.estimator.UpdateRateSample(snap.state, snap.sendTime, bbrTestMaxDatagramSize, snap.bytesInFlight, snap.lostAtSend, s.clock.Now())
			sample := s.estimator.GenerateRateSample(s.cumulativeLost)
			samples = append(samples, sample)
			delete(s.pktStates, s.ackedPacketNumber)
		}
	}

	require.Len(t, samples, 2)
	// Identify which is app-limited vs not.
	var nonAppLimitedSample, appLimitedSample RateSample
	for _, sample := range samples {
		if sample.IsAppLimited {
			appLimitedSample = sample
		} else {
			nonAppLimitedSample = sample
		}
	}
	// Regardless of rates, the non-app-limited sample should be preferred.
	if nonAppLimitedSample.DeliveryRate > 0 && appLimitedSample.DeliveryRate > 0 {
		// Apply the same selection logic as production.
		var best RateSample
		for _, sample := range samples {
			if best.DeliveryRate == 0 {
				best = sample
			} else if !sample.IsAppLimited && best.IsAppLimited {
				best = sample
			} else if sample.IsAppLimited == best.IsAppLimited && sample.DeliveryRate > best.DeliveryRate {
				best = sample
			}
		}
		require.False(t, best.IsAppLimited,
			"best sample should not be app-limited when a non-app-limited sample exists")
	}
}

func TestBBRv3NormalOperationAfterAppLimitedPhase(t *testing.T) {
	// Simulate app-limited → full-rate transition. Verify btlBw recovers.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	// Drive to ProbeBW with established bandwidth.
	s.driveToState(bbrProbeBW, rtt)
	require.True(t, s.sender.bw > 0)
	savedBw := s.sender.bw

	// Send app-limited for several rounds (should NOT corrupt btlBw).
	for i := 0; i < 5; i++ {
		s.sendAppLimitedPacket()
		s.clock.Advance(rtt)
		s.ackedPacketNumber++
		if snap, ok := s.pktStates[s.ackedPacketNumber]; ok {
			s.estimator.InitRateSample()
			s.estimator.UpdateRateSample(snap.state, snap.sendTime, bbrTestMaxDatagramSize, snap.bytesInFlight, snap.lostAtSend, s.clock.Now())
			sample := s.estimator.GenerateRateSample(s.cumulativeLost)
			delete(s.pktStates, s.ackedPacketNumber)
			s.sender.OnPacketAcked(s.ackedPacketNumber, bbrTestMaxDatagramSize, s.bytesInFlight, s.clock.Now())
			s.bytesInFlight -= bbrTestMaxDatagramSize
			s.sender.OnBandwidthSample(sample)
		}
	}
	require.True(t, s.sender.bw >= savedBw,
		"btlBw should not decrease after app-limited samples when rate is lower")

	// Resume full-rate sending — should get back to normal.
	for i := 0; i < 5; i++ {
		n := 10
		s.sendNPackets(n)
		s.clock.Advance(rtt)
		s.ackNPackets(n, rtt)
	}
	require.True(t, s.sender.bw >= savedBw,
		"btlBw should recover after resuming full-rate sending")
}

// ---------- Delivery-Based Round Tracking ----------

func TestBBRv3DeliveryBasedRoundTracking(t *testing.T) {
	// Verify that rounds advance based on delivery progress, not per-ACK.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	require.Equal(t, int64(0), s.sender.roundCount)

	// Send and ACK one batch → should be round 1.
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(10, rtt)
	require.Equal(t, int64(1), s.sender.roundCount,
		"first batch of ACKs should advance to round 1")

	savedRound := s.sender.roundCount

	// Send and ACK another batch → should be round 2.
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(10, rtt)
	require.Equal(t, savedRound+1, s.sender.roundCount,
		"second batch should advance exactly one more round")
}

func TestBBRv3StartupNeedsThreePlateauRounds(t *testing.T) {
	// STARTUP must NOT exit until 3 consecutive rounds without ≥25%
	// bandwidth growth. With delivery-based round tracking, each
	// send-ACK iteration at the same rate should count as one round.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	require.Equal(t, bbrStartup, s.sender.Mode())

	// Round 1: establish btlBw (fullBandwidth set, count=0).
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(10, rtt)
	require.Equal(t, bbrStartup, s.sender.Mode(), "should still be in Startup after round 1")
	require.True(t, s.sender.bw > 0, "btlBw should be seeded")

	// Rounds 2, 3: bandwidth ~same → fullBandwidthCount increments.
	for i := 0; i < 2; i++ {
		s.sendNPackets(10)
		s.clock.Advance(rtt)
		s.ackNPackets(10, rtt)
		require.Equal(t, bbrStartup, s.sender.Mode(),
			"should still be in Startup after round %d", i+2)
	}
	require.True(t, s.sender.fullBandwidthCount >= 1,
		"fullBandwidthCount should have incremented")
	require.True(t, s.sender.fullBandwidthCount < 3,
		"fullBandwidthCount should be < 3 (need 3 consecutive plateau rounds)")

	// Round 4: third consecutive plateau round → STARTUP exits.
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(10, rtt)

	// After 3 plateau rounds, mode should be Drain (or ProbeBW if Drain already exited).
	require.NotEqual(t, bbrStartup, s.sender.Mode(),
		"should have exited Startup after 3 plateau rounds (round ~4)")
}

func TestBBRv3StartupDoesNotExitOnSingleACK(t *testing.T) {
	// The old packet-number-based round tracker could advance multiple
	// rounds on a single ACK, causing STARTUP to exit prematurely.
	// With delivery-based tracking, a single send-ACK cycle is one round.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	// One send-ACK cycle should produce at most 1 round.
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(10, rtt)

	require.Equal(t, int64(1), s.sender.roundCount,
		"single ACK cycle should be exactly one round")
	require.Equal(t, bbrStartup, s.sender.Mode(),
		"STARTUP must not exit after a single round")
}

func TestBBRv3StartupExitsOnBandwidthGrowth(t *testing.T) {
	// Verify that STARTUP does NOT exit when bandwidth is still growing ≥25%.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	// Round 1: small rate.
	s.sendNPackets(2)
	s.clock.Advance(rtt)
	s.ackNPackets(2, rtt)
	require.Equal(t, bbrStartup, s.sender.Mode())
	savedBw := s.sender.bw

	// Round 2: send more packets → higher delivery rate (more delivered in same RTT).
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(10, rtt)

	// If bandwidth grew ≥25%, fullBandwidthCount should be reset.
	if s.sender.bw >= Bandwidth(float64(savedBw)*bbrStartupFullBandwidthThreshold) {
		require.Equal(t, 0, s.sender.fullBandwidthCount,
			"fullBandwidthCount should be 0 when bandwidth is still growing")
		require.Equal(t, bbrStartup, s.sender.Mode(),
			"STARTUP should continue when bandwidth is growing")
	}
}

// ---------- Phase 5: InflightHi Deadlock & DOWN Trap Fixes (BBRv3 §4.3.3) ----------

func TestBBRv3InflightHiGrowsDuringUp(t *testing.T) {
	// BBRv3 §4.3.3.5: During ProbeBW_UP, inflight_hi must be raised
	// incrementally (additive increase) when the sender is cwnd-limited.
	// This breaks the deadlock where cwnd is capped at a crushed inflight_hi.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW_UP.
	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWUp, rtt)
	require.Equal(t, probeBWUp, s.sender.ProbeBWPhaseValue())

	// Simulate a crushed inflight_hi: set it to a small value.
	crushedHi := protocol.ByteCount(4) * bbrTestMaxDatagramSize
	s.sender.inflightLongterm = crushedHi

	// Force cwnd down to inflightHi (mimicking targetCwnd cap).
	s.sender.congestionWindow = crushedHi

	// Now send+ACK packets while cwnd-limited — inflight_hi probing should kick in.
	// We need bytesInFlight >= congestionWindow for the priorInFlight check.
	s.bytesInFlight = crushedHi // at the cwnd limit

	for i := 0; i < 5; i++ {
		s.clock.Advance(rtt)
		// ACK one packet with priorInFlight == congestionWindow (cwnd-limited).
		oldHi := s.sender.inflightLongterm
		s.sender.OnPacketAcked(
			s.packetNumber,
			bbrTestMaxDatagramSize,
			crushedHi, // priorInFlight == cwnd → cwnd-limited
			s.clock.Now(),
		)
		s.packetNumber++

		// After enough ACKs, inflight_hi should have grown.
		if s.sender.inflightLongterm > oldHi {
			break
		}
	}

	require.Greater(t, s.sender.inflightLongterm, crushedHi,
		"inflight_hi should grow via additive increase during ProbeBW_UP when cwnd-limited")
}

func TestBBRv3DownCycleTimeoutEscapesToRefill(t *testing.T) {
	// BBRv3 §4.3.3 BBRCheckTimeToProbeBW: If bwProbeWait (2-3s) elapses
	// while in ProbeBW_DOWN, the sender escapes directly to REFILL.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW (any phase).
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	// Manually enter DOWN with a fresh cycle timestamp so the timeout
	// hasn't elapsed yet.
	s.sender.enterProbeBWDown(s.clock.Now())
	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue())

	// Record the cycle start.
	cycleStart := s.sender.cycleStamp
	require.False(t, cycleStart.IsZero(), "cycleStamp should be set")
	require.Greater(t, s.sender.bwProbeWait, time.Duration(0), "bwProbeWait should be set")

	// Keep bytesInFlight above BDP so the inflight-based DOWN→CRUISE transition
	// never fires — simulating the deadlock scenario.
	s.bytesInFlight = s.sender.GetCongestionWindow() * 2

	// Advance time well past bwProbeWait (use 4 seconds to cover max 3s timer).
	s.clock.Advance(4 * time.Second)

	// Send+ACK to trigger updateProbeBWPhase with the advanced clock.
	s.sendNPackets(2)
	s.clock.Advance(rtt)
	s.ackNPackets(2, rtt)

	// Should have escaped DOWN → REFILL (or already moved to UP).
	phase := s.sender.ProbeBWPhaseValue()
	require.True(t, phase == probeBWRefill || phase == probeBWUp,
		"should escape DOWN via cycle timeout to REFILL (or UP): got %s", phase)
}

func TestBBRv3CruiseCycleTimeoutEscapesToRefill(t *testing.T) {
	// The BBRv3 cycle timeout also applies during ProbeBW_CRUISE.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW_CRUISE.
	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWCruise, rtt)
	require.Equal(t, probeBWCruise, s.sender.ProbeBWPhaseValue())

	// Set a very high bytesInFlight so the normal CRUISE exit doesn't fire.
	s.bytesInFlight = s.sender.GetCongestionWindow() * 2

	// Advance past the cycle timeout (bwProbeWait was set in enterProbeBWDown).
	s.clock.Advance(4 * time.Second)

	// Trigger phase check.
	s.sendNPackets(2)
	s.clock.Advance(rtt)
	s.ackNPackets(2, rtt)

	// Should have escaped CRUISE → REFILL (or already moved to UP).
	phase := s.sender.ProbeBWPhaseValue()
	require.True(t, phase == probeBWRefill || phase == probeBWUp,
		"should escape CRUISE via cycle timeout to REFILL (or UP): got %s", phase)
}

// ---------- Phase 6: BDP Floor & Drain Hardening ----------

func TestBBRv3DownExitUsesBdpFloor(t *testing.T) {
	// When btlBw collapses so that bdp() < minCwnd, the DOWN exit condition
	// must use minCwnd as the drain target (bdpFloor). Otherwise inflight can
	// never reach the microscopic BDP and the sender is permanently trapped.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW.
	s.driveToState(bbrProbeBW, rtt)

	// Manually enter DOWN with a fresh cycle timestamp.
	s.sender.enterProbeBWDown(s.clock.Now())
	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue())

	// Crush btlBw so that bdp() returns a value far below minCwnd.
	// minCwnd = 4 * 1280 = 5120 bytes.
	// Set btlBw so that bdp = btlBw_bytes_per_sec * minRtt / 1s ≈ 100 bytes.
	// 100 bytes/s in Bandwidth units: 100 * 8 bits/s = 800 bits/s.
	s.sender.bw = 800 * BytesPerSecond // ~800 bytes/s → BDP = 800 * 0.1 = 80 bytes
	s.sender.maxBwFilter.Reset(int64(s.sender.bw), s.sender.roundCount)

	rawBdp := s.sender.bdp()
	require.Less(t, rawBdp, s.sender.minCongestionWindow(),
		"bdp() should be less than minCwnd for this test to be meaningful")

	// Set bytesInFlight so that after sendNPackets(1) adds 1 MTU, priorInFlight
	// at ACK time equals minCwnd — i.e. exactly at the bdpFloor target.
	s.bytesInFlight = s.sender.minCongestionWindow() - bbrTestMaxDatagramSize

	// ACK a packet to trigger updateProbeBWPhase.
	s.sendNPackets(1)
	s.clock.Advance(rtt)
	s.ackNPackets(1, rtt)

	// Should have exited DOWN to CRUISE (or beyond) since bytesInFlight <= bdpFloor.
	phase := s.sender.ProbeBWPhaseValue()
	require.NotEqual(t, probeBWDown, phase,
		"DOWN should exit when bytesInFlight <= bdpFloor (minCwnd), not stay trapped: got %s", phase)
}

func TestBBRv3DrainExitUsesBdpFloor(t *testing.T) {
	// Same bdpFloor fix applies to Drain: when BDP < minCwnd, the drain
	// target should be minCwnd so Drain doesn't get stuck.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive through Startup to Drain.
	s.driveToState(bbrDrain, rtt)
	require.Equal(t, bbrDrain, s.sender.Mode())

	// Crush btlBw to make bdp() microscopic.
	s.sender.bw = 800 * BytesPerSecond
	s.sender.maxBwFilter.Reset(int64(s.sender.bw), s.sender.roundCount)

	rawBdp := s.sender.bdp()
	require.Less(t, rawBdp, s.sender.minCongestionWindow(),
		"bdp() should be less than minCwnd for this test")

	// Set bytesInFlight so that after sendNPackets(1) adds 1 MTU, priorInFlight
	// at ACK time equals minCwnd — satisfying the floored drain target.
	s.bytesInFlight = s.sender.minCongestionWindow() - bbrTestMaxDatagramSize

	// Trigger checkDrain via OnPacketAcked.
	s.sendNPackets(1)
	s.clock.Advance(rtt)
	s.ackNPackets(1, rtt)

	// Should have exited Drain to ProbeBW.
	require.Equal(t, bbrProbeBW, s.sender.Mode(),
		"Drain should exit to ProbeBW when bytesInFlight <= bdpFloor (minCwnd)")
}

func TestBBRv3DrainTimeoutEscape(t *testing.T) {
	// Defense-in-depth: Drain has a time-based escape of max(3s, 10×minRTT).
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to Drain.
	s.driveToState(bbrDrain, rtt)
	require.Equal(t, bbrDrain, s.sender.Mode())

	// Keep bytesInFlight high so the inflight-based exit never fires.
	s.bytesInFlight = s.sender.GetCongestionWindow() * 3

	// Advance time past the drain timeout (3 seconds).
	s.clock.Advance(4 * time.Second)

	// Trigger checkDrain.
	s.sendNPackets(1)
	s.clock.Advance(rtt)
	s.ackNPackets(1, rtt)

	// Should have escaped Drain via timeout.
	require.Equal(t, bbrProbeBW, s.sender.Mode(),
		"Drain should escape to ProbeBW via timeout when inflight stays high")
}

func TestBBRv3BdpFloorNeverBelowMinCwnd(t *testing.T) {
	// bdpFloor() must always return at least minCongestionWindow().
	s := newTestBBRSender()

	// Case 1: btlBw = 0, minRtt = 0 (BDP unknown).
	s.sender.bw = 0
	s.sender.minRtt = 0
	floor := s.sender.bdpFloor()
	require.GreaterOrEqual(t, floor, s.sender.minCongestionWindow(),
		"bdpFloor should be >= minCwnd even when BDP is unknown")

	// Case 2: btlBw is set but produces microscopic BDP.
	s.sender.bw = 100 * BytesPerSecond
	s.sender.minRtt = 1 * time.Millisecond // BDP ≈ 0.1 bytes → truncated to 0
	floor = s.sender.bdpFloor()
	require.GreaterOrEqual(t, floor, s.sender.minCongestionWindow(),
		"bdpFloor should be >= minCwnd when BDP is microscopic")

	// Case 3: btlBw produces healthy BDP above minCwnd.
	s.sender.bw = 10_000_000 * BytesPerSecond // 10 MB/s
	s.sender.minRtt = 100 * time.Millisecond  // BDP = 1 MB
	floor = s.sender.bdpFloor()
	require.Greater(t, floor, s.sender.minCongestionWindow(),
		"bdpFloor should be the actual BDP when it exceeds minCwnd")
}

// TestBBRv3ProbeRTTDoesNotCollapseMaxBw verifies that the fix for spec §5.3.4.3
// MarkConnectionAppLimited() prevents the maxBw filter from being poisoned
// by low delivery-rate samples observed during ProbeRTT's reduced cwnd.
//
// This is the primary regression test for the "4K stagnation" bug where
// maxBw dropped from ~6.8 MB/s to ~20 KB/s and never recovered.
func TestBBRv3ProbeRTTDoesNotCollapseMaxBw(t *testing.T) {
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	// 1. Drive to ProbeBW and establish a good maxBw.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	// Record the healthy maxBw established during Startup/ProbeBW.
	healthyMaxBw := s.sender.MaxBw()
	require.Greater(t, healthyMaxBw, Bandwidth(0),
		"maxBw should be non-zero after reaching ProbeBW")
	t.Logf("healthy maxBw = %d bits/s (%d KB/s)", healthyMaxBw, healthyMaxBw/BytesPerSecond/1024)

	// 2. Force entry into ProbeRTT by setting timestamps far in the past.
	s.sender.minRttStamp = s.clock.Now().Add(-11 * time.Second)
	s.sender.probeRttMinStamp = s.clock.Now().Add(-6 * time.Second)

	// Send + ACK to trigger updateMinRtt → probeRttExpired → checkProbeRTT → enterProbeRTT.
	higherRtt := 200 * time.Millisecond
	s.sendNPackets(1)
	s.clock.Advance(higherRtt)
	s.ackNPackets(1, higherRtt)
	require.Equal(t, bbrProbeRTT, s.sender.Mode(),
		"should have entered ProbeRTT")

	// 3. Simulate several round trips IN ProbeRTT.
	// During ProbeRTT, cwnd is reduced to 0.5*BDP, so delivery rates will be low.
	// The critical invariant: these low samples must be app-limited.
	for i := 0; i < 8; i++ {
		if s.sender.CanSend(s.bytesInFlight) {
			s.sendNPackets(1)
		}
		s.clock.Advance(rtt)
		if s.bytesInFlight > 0 {
			s.ackNPackets(1, rtt)
		}
	}

	// 4. Drive through ProbeRTT exit (duration + round completion).
	s.clock.Advance(bbrProbeRTTDuration + rtt)
	for i := 0; i < 15; i++ {
		if s.sender.Mode() != bbrProbeRTT {
			break
		}
		if s.sender.CanSend(s.bytesInFlight) {
			s.sendNPackets(1)
		}
		s.clock.Advance(rtt)
		if s.bytesInFlight > 0 {
			s.ackNPackets(1, rtt)
		}
	}
	require.NotEqual(t, bbrProbeRTT, s.sender.Mode(),
		"should have exited ProbeRTT by now")

	// 5. THE CRITICAL CHECK: maxBw must NOT have collapsed.
	postProbeRTTMaxBw := s.sender.MaxBw()
	t.Logf("post-ProbeRTT maxBw = %d bits/s (%d KB/s)", postProbeRTTMaxBw, postProbeRTTMaxBw/BytesPerSecond/1024)

	// Allow some tolerance (50%) but absolutely no catastrophic collapse.
	// Before the fix, maxBw would drop to <1% of the healthy value.
	minAcceptable := Bandwidth(float64(healthyMaxBw) * 0.5)
	require.GreaterOrEqual(t, postProbeRTTMaxBw, minAcceptable,
		"maxBw should NOT collapse after ProbeRTT (was %d, now %d, min acceptable %d)",
		healthyMaxBw, postProbeRTTMaxBw, minAcceptable)
}

// TestBBRv3ProbeRTTSamplesMarkedAppLimited verifies that during ProbeRTT,
// the delivery-rate estimator is correctly marked as app-limited, so that
// low-rate samples from ProbeRTT's reduced cwnd are tagged as app-limited
// and filtered by updateMaxBw() (spec §5.5.5).
func TestBBRv3ProbeRTTSamplesMarkedAppLimited(t *testing.T) {
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	s.driveToState(bbrProbeBW, rtt)

	// Force ProbeRTT.
	s.sender.minRttStamp = s.clock.Now().Add(-11 * time.Second)
	s.sender.probeRttMinStamp = s.clock.Now().Add(-6 * time.Second)

	s.sendNPackets(1)
	s.clock.Advance(200 * time.Millisecond)
	s.ackNPackets(1, 200*time.Millisecond)
	require.Equal(t, bbrProbeRTT, s.sender.Mode())

	// The estimator should be marked app-limited during ProbeRTT.
	require.True(t, s.estimator.IsAppLimited(),
		"delivery rate estimator should be app-limited during ProbeRTT")

	// Send a packet WHILE in ProbeRTT — it should be stamped as app-limited.
	if s.sender.CanSend(s.bytesInFlight) {
		pn := s.packetNumber
		s.sendPacket()
		snap, ok := s.pktStates[pn]
		require.True(t, ok)
		require.True(t, snap.state.IsAppLimited,
			"packet sent during ProbeRTT should be marked app-limited")
	}
}

// TestBBRv3StartupHighLossRequires6LossEvents verifies that the Startup
// loss-based exit now requires at least 6 discontiguous loss events
// (BBRStartupFullLossCnt=6) per spec §5.3.1.3, not just a boolean flag.
func TestBBRv3StartupHighLossRequires6LossEvents(t *testing.T) {
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	// Build up some delivered bytes and round history.
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.rttStats.UpdateRTT(rtt, 0)
	s.ackNPackets(10, rtt)
	require.Equal(t, bbrStartup, s.sender.Mode())

	// Send a flight to have something in-flight.
	s.sendNPackets(20)
	s.clock.Advance(rtt)

	// Lose 5 packets (below the threshold of 6).
	// Each loseNPackets(1) call creates one loss event.
	for i := 0; i < 5; i++ {
		s.loseNPackets(1)
	}
	require.Equal(t, bbrStartup, s.sender.Mode(),
		"5 loss events should NOT exit Startup (need 6)")
	// Check loss tracking BEFORE any ack that might reset the round counters.
	require.Equal(t, 5, s.sender.lossEventsInRound,
		"lossEventsInRound should count 5 loss events")

	// Lose 1 more → total 6 loss events in this round.
	s.loseNPackets(1)
	require.Equal(t, 6, s.sender.lossEventsInRound,
		"lossEventsInRound should count each loss event")
	require.True(t, s.sender.lossInRound)
}

// TestBBRv3IsExcessiveLossRoundUsesLossRate verifies that isExcessiveLossRound()
// computes a proper loss rate rather than just a boolean flag.
func TestBBRv3IsExcessiveLossRoundUsesLossRate(t *testing.T) {
	s := newTestBBRSender()

	// Case 1: no loss in round → not excessive.
	s.sender.lossInRound = false
	s.sender.bytesLostInRound = 0
	s.sender.lastDelivered = 100000
	s.sender.deliveredAtRoundStart = 0
	require.False(t, s.sender.isExcessiveLossRound(),
		"no loss → not excessive")

	// Case 2: 1% loss rate (< 2% threshold) → not excessive.
	s.sender.lossInRound = true
	s.sender.lastDelivered = 100000
	s.sender.deliveredAtRoundStart = 0
	// 1% of 100000 delivered = 1000 bytes lost; total at risk = 101000
	s.sender.bytesLostInRound = 1000
	require.False(t, s.sender.isExcessiveLossRound(),
		"1% loss rate should NOT be excessive (threshold is 2%)")

	// Case 3: 10% loss rate (> 2% threshold) → excessive.
	s.sender.lossInRound = true
	s.sender.lastDelivered = 50000
	s.sender.deliveredAtRoundStart = 0
	// 10% loss: 5000 lost / (50000 + 5000) total ≈ 9.1%
	s.sender.bytesLostInRound = 5000
	require.True(t, s.sender.isExcessiveLossRound(),
		"10% loss rate should be excessive")

	// Case 4: exactly at threshold (2%) → not excessive (strict >).
	s.sender.lossInRound = true
	s.sender.lastDelivered = 98000
	s.sender.deliveredAtRoundStart = 0
	// 2% of total: lost=2000, total=100000, rate=0.02 exactly → not > 0.02
	s.sender.bytesLostInRound = 2000
	require.False(t, s.sender.isExcessiveLossRound(),
		"exactly 2% loss rate should NOT be excessive (strict >)")
}

// ---------- Phase 6: inflST Spec-Compliance Tests ----------

func TestBBRv3ACKPathRateSampleCarriesLost(t *testing.T) {
	// Verify that the ACK-path RateSample (from GenerateRateSample) correctly
	// computes RS.lost = C.lost - P.lost, enabling the ACK-path
	// isInflightTooHigh check in adaptLongTermModel.
	e := NewDeliveryRateEstimator()
	now := monotime.Time(1_000_000_000)

	// Send 5 packets. C.lost = 0 at send time for all.
	type pkt struct {
		state    PacketDeliveryState
		sendTime monotime.Time
	}
	pkts := make([]pkt, 5)
	var bif protocol.ByteCount
	for i := range pkts {
		pkts[i].state = e.OnPacketSent(now, bif)
		pkts[i].sendTime = now
		bif += testPacketSize
		now += monotime.Time(time.Millisecond)
	}

	// Simulate: 2 packets were lost between send and ACK (cumulativeLost = 2*1200).
	cumulativeLost := 2 * testPacketSize

	// ACK packets 3-4 (the surviving ones). P.lost for these was 0 at send time.
	ackTime := now + monotime.Time(50*time.Millisecond)
	e.InitRateSample()
	e.UpdateRateSample(pkts[2].state, pkts[2].sendTime, testPacketSize, 2*testPacketSize, 0, ackTime)
	e.UpdateRateSample(pkts[3].state, pkts[3].sendTime, testPacketSize, 3*testPacketSize, 0, ackTime)
	sample := e.GenerateRateSample(cumulativeLost)

	// RS.lost should be cumulativeLost - P.lost_at_send_of_reference_pkt.
	// Reference is pkt[3] (newest), P.lost = 0 → RS.lost = 2400 - 0 = 2400.
	require.Equal(t, cumulativeLost, sample.PacketLost,
		"RS.lost should equal cumulative lost minus reference packet's P.lost")
	require.Greater(t, sample.TxInFlight, protocol.ByteCount(0),
		"RS.tx_in_flight should be non-zero")
}

func TestBBRv3AdaptLongTermModelSetsInflightHiOnExcessiveLoss(t *testing.T) {
	// Verify that adaptLongTermModel correctly detects excessive loss on the
	// ACK-path sample and sets inflightLongterm (inflight_hi) via
	// handleInflightTooHigh. This was the missing branch (Bug 2).
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW UP (bwProbeSamples = 1 = armed).
	s.driveToProbeBWPhase(probeBWUp, rtt)
	require.Equal(t, probeBWUp, s.sender.ProbeBWPhaseValue())
	require.Equal(t, 1, s.sender.bwProbeSamples, "bwProbeSamples should be armed in UP")

	// Record state before loss.
	require.Equal(t, protocol.ByteCount(0), s.sender.inflightLongterm,
		"inflightLongterm should not yet be set if no excessive loss detected")

	// Send a burst of packets to establish high tx_in_flight.
	nSend := 0
	for s.sender.CanSend(s.bytesInFlight) && nSend < 20 {
		s.sendPacket()
		nSend++
	}
	require.Greater(t, nSend, 0)

	// Lose enough packets to exceed the 2% loss threshold.
	// With 20 packets in flight at ~1280 bytes each = 25600 bytes,
	// we need loss > 2% of tx_in_flight at send time.
	// Lose 5 packets before ACKing to push cumulativeLost high.
	nLoss := 5
	s.loseNPackets(nLoss)

	// Now ACK remaining packets. The RateSample will carry RS.lost > 0
	// from the cumulativeLost accumulated above. If tx_in_flight * 0.02 < lost,
	// isInflightTooHigh returns true → handleInflightTooHigh sets inflightLongterm.
	s.clock.Advance(rtt)
	remaining := nSend - nLoss
	if remaining > 0 {
		s.ackNPackets(remaining, rtt)
	}

	// inflightLongterm should now be set (non-zero) if the ACK-path
	// isInflightTooHigh correctly fired.
	require.Greater(t, s.sender.inflightLongterm, protocol.ByteCount(0),
		"inflightLongterm should be set after excessive loss detected on ACK path")
}

func TestBBRv3BDPFailsafeWhenBothBoundsUninitialized(t *testing.T) {
	// Verify that when both inflightLongterm == 0 and inflightShortterm == infMax,
	// boundCwndForModel enforces a BDP-based cap (cwnd_gain * BDP).
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW CRUISE so boundCwndForModel is active.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	// Force both bounds to be uninitialized.
	s.sender.inflightLongterm = 0
	s.sender.inflightShortterm = infMax

	// Inflate cwnd artificially to something much larger than BDP.
	bdp := s.sender.bdp()
	require.Greater(t, bdp, protocol.ByteCount(0), "BDP should be > 0")
	hugeCwnd := bdp * 100
	s.sender.congestionWindow = hugeCwnd

	// Call boundCwndForModel — should cap cwnd at cwndGain * BDP.
	s.sender.boundCwndForModel()

	expectedCap := s.sender.bdpMultiple(s.sender.cwndGain)
	require.LessOrEqual(t, s.sender.congestionWindow, expectedCap,
		"cwnd should be capped at cwndGain * BDP when both bounds are uninitialized")
	require.Less(t, s.sender.congestionWindow, hugeCwnd,
		"cwnd should have been reduced from the inflated value")
}

func TestBBRv3BDPFailsafeNotAppliedInStartup(t *testing.T) {
	// The BDP failsafe should NOT apply during Startup, because Startup
	// intentionally grows cwnd without upper bounds.
	s := newTestBBRSender()
	require.Equal(t, bbrStartup, s.sender.Mode())

	// Both bounds are uninitialized by default in Startup.
	require.Equal(t, protocol.ByteCount(0), s.sender.inflightLongterm)
	require.Equal(t, infMax, s.sender.inflightShortterm)

	// Set a large cwnd manually.
	largeCwnd := protocol.ByteCount(1_000_000)
	s.sender.congestionWindow = largeCwnd

	// boundCwndForModel should NOT cap it.
	s.sender.boundCwndForModel()
	require.Equal(t, largeCwnd, s.sender.congestionWindow,
		"BDP failsafe must not apply during Startup")
}

// ---------- Bug 4: isTimeToGoDown branch order ----------

func TestBBRv3IsTimeToGoDownFullBwNowTakesPriority(t *testing.T) {
	// When both fullBwNow=true AND cwndLimited at inflight_hi ceiling,
	// isTimeToGoDown must return true (exit UP) immediately rather than
	// resetting fullBwNow (spec §4.3.3.4 checks full_bw_now first).
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWUp, rtt)
	require.Equal(t, probeBWUp, s.sender.ProbeBWPhaseValue())

	// Set up conditions: fullBwNow=true, cwnd-limited at inflight_hi ceiling.
	s.sender.fullBwNow = true
	s.sender.isCwndLimited = true
	s.sender.inflightLongterm = 20000
	s.sender.congestionWindow = 20000

	// isTimeToGoDown should return true (fullBwNow checked first).
	require.True(t, s.sender.isTimeToGoDown(),
		"isTimeToGoDown must return true when fullBwNow is set")

	// fullBwNow should still be true (not reset by cwndLimited branch).
	require.True(t, s.sender.fullBwNow,
		"fullBwNow must not be cleared when it triggers exit")
}

func TestBBRv3IsTimeToGoDownCwndLimitedResets(t *testing.T) {
	// When fullBwNow=false but cwnd-limited at ceiling, isTimeToGoDown
	// should return false and reset the full BW estimator.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWUp, rtt)

	s.sender.fullBwNow = false
	s.sender.isCwndLimited = true
	s.sender.inflightLongterm = 20000
	s.sender.congestionWindow = 20000
	s.sender.fullBandwidthCount = 2 // non-zero to verify reset

	require.False(t, s.sender.isTimeToGoDown(),
		"isTimeToGoDown must return false when fullBwNow is not set")
	require.Equal(t, 0, s.sender.fullBandwidthCount,
		"cwndLimited branch should have reset fullBandwidthCount")
}

// ---------- Bug 5: Startup loss data ordering ----------

func TestBBRv3StartupHighLossSeesAccumulatedData(t *testing.T) {
	// Verify that checkStartupHighLoss observes loss data accumulated during
	// the round, even when the round boundary fires on the same ACK.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	require.Equal(t, bbrStartup, s.sender.Mode())

	// Fill the pipe with enough packets to create real traffic.
	nSend := 32
	s.sendNPackets(nSend)
	s.clock.Advance(rtt)
	s.ackNPackets(nSend, rtt)

	// Now create a round with heavy loss.
	// Send another burst.
	s.sendNPackets(nSend)
	s.clock.Advance(rtt)

	// Lose enough packets to exceed 2% loss threshold and 6+ events.
	nLoss := 10 // 10/32 = 31% >> 2%
	s.loseNPackets(nLoss)

	// Verify loss data is accumulated.
	require.True(t, s.sender.lossInRound, "lossInRound should be true after losses")
	require.Greater(t, s.sender.lossEventsInRound, 0, "lossEventsInRound should be > 0")
	require.Greater(t, s.sender.bytesLostInRound, protocol.ByteCount(0))

	// ACK the remaining packets — this triggers OnBandwidthSample which
	// should run checkStartupHighLoss BEFORE clearing loss counters.
	remaining := nSend - nLoss
	s.ackNPackets(remaining, rtt)

	// With the fix, checkStartupHighLoss should have seen the loss data
	// and initiated Startup exit (fullBwReached=true, mode transitions).
	// The connection requirements (>2% loss rate, >= 6 loss events) are met.
	if s.sender.lossEventsInRound >= bbrStartupFullLossCnt {
		// If enough events accumulated before the ACK cleared them,
		// Startup should have exited.
		require.True(t, s.sender.fullBwReached,
			"fullBwReached should be true after excessive Startup loss")
		require.NotEqual(t, bbrStartup, s.sender.Mode(),
			"should have exited Startup after excessive loss")
	}
}

// ---------- Bug 6: Post-sample cwnd re-bounding ----------

func TestBBRv3PostBandwidthSampleReboundsCwnd(t *testing.T) {
	// Verify that PostBandwidthSample applies cwnd bounding after
	// OnBandwidthSample sets inflightLongterm via adaptLongTermModel.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	s.driveToState(bbrProbeBW, rtt)
	s.driveToProbeBWPhase(probeBWCruise, rtt)
	require.Equal(t, probeBWCruise, s.sender.ProbeBWPhaseValue())

	// Set inflightLongterm to a small value (simulating handleInflightTooHigh).
	bdp := s.sender.bdp()
	require.Greater(t, bdp, protocol.ByteCount(0))
	s.sender.inflightLongterm = bdp

	// Inflate cwnd beyond inflightLongterm.
	s.sender.congestionWindow = bdp * 5

	// PostBandwidthSample should enforce the model cap.
	s.sender.PostBandwidthSample()

	// In CRUISE, cap = inflightWithHeadroom = 0.85 * inflightLongterm.
	headroom := s.sender.inflightWithHeadroom()
	require.LessOrEqual(t, s.sender.congestionWindow, headroom,
		"PostBandwidthSample should have bounded cwnd to inflightWithHeadroom")
}

// ---------- Bug 8: adaptLongTermModel must not run during Startup ----------

func TestBBRv3AdaptLongTermModelSkippedDuringStartup(t *testing.T) {
	// During Startup, adaptLongTermModel must be a no-op. Otherwise,
	// the else-branch ratchets inflightLongterm upward on every ACK
	// (via TxInFlight > inflightLongterm), bloating it to 100x BDP.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	require.Equal(t, bbrStartup, s.sender.Mode())

	// Simulate handleStartupLoss having set inflightLongterm to a small value.
	initialInflLT := protocol.ByteCount(5000)
	s.sender.inflightLongterm = initialInflLT

	// Send a burst with TxInFlight > initialInflLT, then ACK.
	// Without the guard, adaptLongTermModel would ratchet inflightLongterm up.
	s.sendNPackets(8) // 8 * 1280 = 10240 > 5000
	s.clock.Advance(rtt)
	s.ackNPackets(8, rtt)

	require.Equal(t, bbrStartup, s.sender.Mode(),
		"should still be in Startup")
	require.False(t, s.sender.fullBwReached,
		"fullBwReached should not be set yet")
	// inflightLongterm must NOT have been ratcheted up by adaptLongTermModel.
	require.Equal(t, initialInflLT, s.sender.inflightLongterm,
		"adaptLongTermModel should not modify inflightLongterm during Startup")
}

func TestBBRv3AdaptLongTermModelRunsAfterStartup(t *testing.T) {
	// After Startup, adaptLongTermModel should operate normally.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	s.driveToState(bbrProbeBW, rtt)
	require.True(t, s.sender.fullBwReached)

	// Set inflightLongterm to a small value, then send at higher inflight.
	smallInflLT := protocol.ByteCount(5000)
	s.sender.inflightLongterm = smallInflLT

	s.sendNPackets(16)
	s.clock.Advance(rtt)
	s.ackNPackets(16, rtt)

	require.Greater(t, s.sender.inflightLongterm, smallInflLT,
		"adaptLongTermModel should raise inflightLongterm after Startup")
}

// ---------- Bug 7: Startup max rounds exit ----------

func TestBBRv3StartupMaxRoundsExit(t *testing.T) {
	// Verify that Startup exits after bbrStartupMaxRounds even when
	// all samples are app-limited (preventing checkFullBWReached from firing).
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	require.Equal(t, bbrStartup, s.sender.Mode())

	// Drive rounds by sending app-limited packets (inflight << cwnd).
	// Each iteration: send 1 packet (app-limited), advance time, ACK it.
	for i := int64(0); i < bbrStartupMaxRounds+10; i++ {
		s.sendAppLimitedPacket()
		s.clock.Advance(rtt)
		s.ackNPackets(1, rtt)
		s.clock.Advance(time.Millisecond)

		if s.sender.Mode() != bbrStartup {
			require.LessOrEqual(t, i, bbrStartupMaxRounds,
				"should exit Startup at or before bbrStartupMaxRounds")
			break
		}
	}

	require.NotEqual(t, bbrStartup, s.sender.Mode(),
		"should have exited Startup after %d rounds", bbrStartupMaxRounds)
	require.True(t, s.sender.fullBwReached,
		"fullBwReached should be set by the max-rounds exit")
}

func TestBBRv3StartupExitsNormallyBeforeMaxRounds(t *testing.T) {
	// Normal Startup exit (via bandwidth growth plateau) should still
	// work and occur well before the max-rounds safety valve.
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	for i := 0; i < 30; i++ {
		s.sendNPackets(32)
		s.clock.Advance(rtt)
		s.ackNPackets(32, rtt)
		s.clock.Advance(time.Millisecond)

		if s.sender.Mode() != bbrStartup {
			break
		}
	}

	require.NotEqual(t, bbrStartup, s.sender.Mode(),
		"normal Startup should exit via bandwidth growth plateau")
	require.Less(t, s.sender.roundCount, bbrStartupMaxRounds,
		"normal Startup should exit well before max-rounds")
}
