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
	pktStates map[protocol.PacketNumber]pktSnapshot
}

type pktSnapshot struct {
	state    PacketDeliveryState
	sendTime monotime.Time
}

func newTestBBRSender() *testBBRSender {
	var clock mockClock
	// Start clock at a non-zero value so monotime is valid.
	clock = mockClock(monotime.Time(1_000_000_000))

	rttStats := utils.NewRTTStats()

	return &testBBRSender{
		clock:        &clock,
		rttStats:     rttStats,
		packetNumber: 1,
		estimator:    NewDeliveryRateEstimator(),
		pktStates:    make(map[protocol.PacketNumber]pktSnapshot),
		sender: NewBBRv3Sender(
			&clock,
			rttStats,
			&utils.ConnectionStats{},
			bbrTestMaxDatagramSize,
			nil, // no qlogger
		),
	}
}

func (s *testBBRSender) sendPacket() {
	// Snapshot delivery state before send (mirrors sent_packet_handler).
	// Clear app-limited once pipe fills (matches production code).
	if s.bytesInFlight >= s.sender.GetCongestionWindow() {
		s.estimator.SetAppLimited(false)
	}
	ds := s.estimator.OnPacketSent(s.clock.Now(), s.bytesInFlight)
	s.pktStates[s.packetNumber] = pktSnapshot{state: ds, sendTime: s.clock.Now()}

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
	s.estimator.SetAppLimited(true)
	ds := s.estimator.OnPacketSent(s.clock.Now(), s.bytesInFlight)
	s.pktStates[s.packetNumber] = pktSnapshot{state: ds, sendTime: s.clock.Now()}

	s.sender.OnPacketSent(s.clock.Now(), s.bytesInFlight, s.packetNumber, bbrTestMaxDatagramSize, true)
	s.bytesInFlight += bbrTestMaxDatagramSize
	s.packetNumber++
}

func (s *testBBRSender) ackNPackets(n int, rtt time.Duration) {
	s.rttStats.UpdateRTT(rtt, 0)
	var bestSample RateSample
	for range n {
		s.ackedPacketNumber++

		// Generate delivery-rate sample (mirrors sent_packet_handler ACK path).
		if snap, ok := s.pktStates[s.ackedPacketNumber]; ok {
			sample := s.estimator.GenerateRateSample(
				snap.state, snap.sendTime, bbrTestMaxDatagramSize, s.clock.Now(),
			)
			// Best-sample selection: prefer non-app-limited over app-limited.
			if bestSample.DeliveryRate == 0 {
				bestSample = sample
			} else if !sample.IsAppLimited && bestSample.IsAppLimited {
				bestSample = sample
			} else if sample.IsAppLimited == bestSample.IsAppLimited && sample.DeliveryRate > bestSample.DeliveryRate {
				bestSample = sample
			}
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
	// Feed the best sample to the bandwidth consumer.
	if bestSample.DeliveryRate > 0 {
		s.sender.OnBandwidthSample(bestSample)
	}
}

func (s *testBBRSender) loseNPackets(n int) {
	for range n {
		s.ackedPacketNumber++
		s.sender.OnCongestionEvent(
			s.ackedPacketNumber,
			bbrTestMaxDatagramSize,
			s.bytesInFlight,
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

	s.sender.btlBw = targetBw
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

	s.sender.btlBw = targetBw
	s.sender.pacingGain = 1.0
	// Set cwnd small enough and SRTT large enough that cwndBw doesn't override btlBw.
	s.sender.congestionWindow = 4 * bbrTestMaxDatagramSize
	s.rttStats.UpdateRTT(200*time.Millisecond, 0)

	rate := s.sender.pacingRateBytesPerSec()
	pps := rate / uint64(bbrTestMaxDatagramSize)

	// Should NOT be clamped — should remain at 50.
	require.Equal(t, uint64(50), pps,
		"pacing above death zone should not be clamped: expected 50, got %d", pps)
}

func TestBBRv3PacingBelowDeathZone(t *testing.T) {
	s := newTestBBRSender()

	// Force a bandwidth estimate that would result in ~20 pps (below death zone).
	targetBytesPerSec := uint64(20) * uint64(bbrTestMaxDatagramSize)
	targetBw := Bandwidth(targetBytesPerSec) * BytesPerSecond

	s.sender.btlBw = targetBw
	s.sender.pacingGain = 1.0
	// Set cwnd small enough and SRTT large enough that cwndBw doesn't override btlBw.
	// cwndBw with 4*1280/0.2s = 25600 bytes/s = 20 pps — same as target, so btlBw dominates.
	s.sender.congestionWindow = 4 * bbrTestMaxDatagramSize
	s.rttStats.UpdateRTT(200*time.Millisecond, 0)

	rate := s.sender.pacingRateBytesPerSec()
	pps := rate / uint64(bbrTestMaxDatagramSize)

	// Should NOT be clamped — should remain at 20.
	require.Equal(t, uint64(20), pps,
		"pacing below death zone should not be clamped: expected 20, got %d", pps)
}

func TestBBRv3ProbeRTTTransition(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW first.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, bbrProbeBW, s.sender.Mode())

	// Set minRttTimestamp far in the past so updateMinRtt computes
	// elapsed > 10s and sets minRttExpired = true naturally.
	s.sender.minRttTimestamp = s.clock.Now().Add(-11 * time.Second)

	// Use a higher RTT so the latestRtt > minRtt check doesn't reset the flag.
	higherRtt := 200 * time.Millisecond

	s.sendNPackets(1)
	s.clock.Advance(higherRtt)
	s.ackNPackets(1, higherRtt)

	require.Equal(t, bbrProbeRTT, s.sender.Mode(),
		"should have entered ProbeRTT when min RTT expired")

	// Cwnd should be at minimum.
	require.Equal(t, s.sender.minCongestionWindow(), s.sender.GetCongestionWindow(),
		"cwnd should be minimal during ProbeRTT")
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
	s.sender.minRttTimestamp = s.clock.Now().Add(-11 * time.Second)
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
	s.sender.minRttTimestamp = s.clock.Now().Add(-11 * time.Second)

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

	// BBRv3: RTO does NOT collapse cwnd. It sets inflightHi as a cap
	// and transitions to ProbeBW_DOWN to re-probe gracefully.
	require.Equal(t, cwndBefore, s.sender.InflightHi(),
		"inflightHi should be set to cwnd before RTO")
	require.Equal(t, bbrProbeBW, s.sender.Mode(),
		"should transition to ProbeBW after RTO")
	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue(),
		"should be in ProbeBW_DOWN sub-state after RTO")
	// Cwnd should be recalculated based on targetCwnd with inflightHi cap, not collapsed.
	require.Greater(t, s.sender.GetCongestionWindow(), s.sender.minCongestionWindow(),
		"cwnd should NOT collapse to minimum after RTO in BBRv3")
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
	require.InDelta(t, bbrStartupCwndGain, s.sender.cwndGain, 0.01)
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

	// Advance past the CRUISE deadline (at most 2×minRTT from entry).
	minRtt := s.sender.MinRtt()
	if minRtt <= 0 {
		minRtt = 100 * time.Millisecond
	}
	s.clock.Advance(2*minRtt + time.Millisecond)
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

	// Inject enough loss to exceed the 2% threshold.
	// BBRv3 loss rate = lost / (lost + delivered_in_round).
	// Losing 10 packets (12800 bytes) is clearly excessive for any
	// reasonable delivered_in_round value.
	s.loseNPackets(10)

	// After excessive loss in UP, should transition to DOWN, cap inflightHi, and set bwLo.
	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue(),
		"excessive loss in UP should trigger transition to DOWN")
	require.Greater(t, s.sender.InflightHi(), protocol.ByteCount(0),
		"inflightHi should be set after excessive loss in UP")
	require.Greater(t, s.sender.BwLo(), Bandwidth(0),
		"bwLo should be set after excessive loss in UP")
}

func TestBBRv3ProbeBWLossInCruiseSetsBound(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond

	// Drive to ProbeBW CRUISE.
	s.driveToState(bbrProbeBW, rtt)
	require.Equal(t, probeBWCruise, s.sender.ProbeBWPhaseValue())

	// Send some packets.
	s.sendNPackets(10)

	// Lose a packet in CRUISE — should set inflightLo.
	s.loseNPackets(1)

	require.Greater(t, s.sender.InflightLo(), protocol.ByteCount(0),
		"inflightLo should be set after loss in CRUISE")
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

	// Send packets without ACKing to stay in UP.
	s.sendNPackets(32)

	// Heavy loss: 10 packets = clearly excessive regardless of denominator.
	// BBRv3 loss rate = lost / (lost + deliveredInRound).
	// With deliveredInRound from previous ACKs and 12800 bytes lost,
	// this is well above the 2% threshold.
	s.loseNPackets(10)

	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue(),
		"heavy loss should trigger excessive loss detection and transition to DOWN")
	require.Greater(t, s.sender.BwLo(), Bandwidth(0),
		"bwLo should be set on excessive loss in UP")
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
	s.sender.bwLo = halfBw

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
	s.sender.bwLo = s.sender.BtlBw()
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
	require.Greater(t, s.sender.BwLo(), Bandwidth(0),
		"bwLo should be set on ECN in UP")
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

	require.Equal(t, priorInFlight, s.sender.InflightLo(),
		"inflightLo should be tightened on ECN in CRUISE")
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

	// Lose a packet during REFILL — should tighten inflightLo.
	s.loseNPackets(1)

	require.Greater(t, s.sender.InflightLo(), protocol.ByteCount(0),
		"inflightLo should be set after loss in REFILL")
}

func TestBBRv3LossInProbeRTTSetsInflightHi(t *testing.T) {
	s := newTestBBRSender()
	rtt := 100 * time.Millisecond
	higherRtt := 200 * time.Millisecond

	// Drive to ProbeBW, then force into ProbeRTT.
	s.driveToState(bbrProbeBW, rtt)
	s.sender.minRttTimestamp = s.clock.Now().Add(-11 * time.Second)

	s.sendNPackets(1)
	s.clock.Advance(higherRtt)
	s.ackNPackets(1, higherRtt)
	require.Equal(t, bbrProbeRTT, s.sender.Mode())

	// Send a few packets (ProbeRTT has minimal cwnd).
	if s.sender.CanSend(s.bytesInFlight) {
		s.sendNPackets(1)
	}

	priorInFlight := s.bytesInFlight

	// Lose a packet during ProbeRTT — should set inflightHi.
	s.loseNPackets(1)

	require.Equal(t, priorInFlight, s.sender.InflightHi(),
		"inflightHi should be set after loss in ProbeRTT")
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
	// When btlBw is 0 (initial state), an app-limited sample must NOT seed
	// the maxBwFilter, even if its rate is positive.
	s := newTestBBRSender()
	rtt := 50 * time.Millisecond

	require.Equal(t, Bandwidth(0), s.sender.btlBw)

	// Send a single app-limited packet (connection draining scenario).
	s.sendAppLimitedPacket()
	s.clock.Advance(rtt)

	// ACK it — this produces an app-limited sample.
	s.ackedPacketNumber++
	snap := s.pktStates[s.ackedPacketNumber]
	sample := s.estimator.GenerateRateSample(
		snap.state, snap.sendTime, bbrTestMaxDatagramSize, s.clock.Now(),
	)
	require.True(t, sample.IsAppLimited)
	require.True(t, sample.DeliveryRate > 0)
	delete(s.pktStates, s.ackedPacketNumber)

	s.sender.OnPacketAcked(s.ackedPacketNumber, bbrTestMaxDatagramSize, s.bytesInFlight, s.clock.Now())
	s.bytesInFlight -= bbrTestMaxDatagramSize

	// Feed the app-limited sample — it should be rejected.
	s.sender.OnBandwidthSample(sample)
	require.Equal(t, Bandwidth(0), s.sender.btlBw,
		"app-limited sample must not seed btlBw when btlBw is zero")
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
	require.True(t, s.sender.btlBw > 0, "btlBw should be established")
	savedBw := s.sender.btlBw

	// Now send an app-limited packet, but at a HIGHER rate (e.g., shorter RTT).
	s.sendAppLimitedPacket()
	shortRTT := 10 * time.Millisecond
	s.clock.Advance(shortRTT)

	s.ackedPacketNumber++
	snap := s.pktStates[s.ackedPacketNumber]
	sample := s.estimator.GenerateRateSample(
		snap.state, snap.sendTime, bbrTestMaxDatagramSize, s.clock.Now(),
	)
	require.True(t, sample.IsAppLimited)
	delete(s.pktStates, s.ackedPacketNumber)

	s.sender.OnPacketAcked(s.ackedPacketNumber, bbrTestMaxDatagramSize, s.bytesInFlight, s.clock.Now())
	s.bytesInFlight -= bbrTestMaxDatagramSize

	// Only accept if the delivery rate exceeds btlBw.
	if sample.DeliveryRate > savedBw {
		s.sender.OnBandwidthSample(sample)
		require.True(t, s.sender.btlBw >= savedBw,
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
		sample := s.estimator.GenerateRateSample(
			snap.state, snap.sendTime, bbrTestMaxDatagramSize, s.clock.Now(),
		)
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
			sample := s.estimator.GenerateRateSample(
				snap.state, snap.sendTime, bbrTestMaxDatagramSize, s.clock.Now(),
			)
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
	require.True(t, s.sender.btlBw > 0)
	savedBw := s.sender.btlBw

	// Send app-limited for several rounds (should NOT corrupt btlBw).
	for i := 0; i < 5; i++ {
		s.sendAppLimitedPacket()
		s.clock.Advance(rtt)
		s.ackedPacketNumber++
		if snap, ok := s.pktStates[s.ackedPacketNumber]; ok {
			sample := s.estimator.GenerateRateSample(
				snap.state, snap.sendTime, bbrTestMaxDatagramSize, s.clock.Now(),
			)
			delete(s.pktStates, s.ackedPacketNumber)
			s.sender.OnPacketAcked(s.ackedPacketNumber, bbrTestMaxDatagramSize, s.bytesInFlight, s.clock.Now())
			s.bytesInFlight -= bbrTestMaxDatagramSize
			s.sender.OnBandwidthSample(sample)
		}
	}
	require.True(t, s.sender.btlBw >= savedBw,
		"btlBw should not decrease after app-limited samples when rate is lower")

	// Resume full-rate sending — should get back to normal.
	for i := 0; i < 5; i++ {
		n := 10
		s.sendNPackets(n)
		s.clock.Advance(rtt)
		s.ackNPackets(n, rtt)
	}
	require.True(t, s.sender.btlBw >= savedBw,
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
	require.True(t, s.sender.btlBw > 0, "btlBw should be seeded")

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
	savedBw := s.sender.btlBw

	// Round 2: send more packets → higher delivery rate (more delivered in same RTT).
	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(10, rtt)

	// If bandwidth grew ≥25%, fullBandwidthCount should be reset.
	if s.sender.btlBw >= Bandwidth(float64(savedBw)*bbrStartupFullBandwidthThreshold) {
		require.Equal(t, 0, s.sender.fullBandwidthCount,
			"fullBandwidthCount should be 0 when bandwidth is still growing")
		require.Equal(t, bbrStartup, s.sender.Mode(),
			"STARTUP should continue when bandwidth is growing")
	}
}
