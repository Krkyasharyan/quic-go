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
	appLimited := s.bytesInFlight < s.sender.GetCongestionWindow()
	ds := s.estimator.OnPacketSent(s.clock.Now(), s.bytesInFlight, appLimited)
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
			if sample.DeliveryRate > bestSample.DeliveryRate {
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

	s.sendNPackets(10)
	s.clock.Advance(rtt)
	s.ackNPackets(5, rtt)

	cwndBefore := s.sender.GetCongestionWindow()
	s.sender.OnRetransmissionTimeout(true)

	require.Equal(t, s.sender.minCongestionWindow(), s.sender.GetCongestionWindow(),
		"cwnd should be minimum after RTO")
	_ = cwndBefore
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

	// After Drain, we should enter CRUISE sub-state.
	require.Equal(t, probeBWCruise, s.sender.ProbeBWPhaseValue(),
		"should enter ProbeBW CRUISE after Drain")

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

	// In UP, we need to advance a whole round to trigger UP→DOWN.
	// The UP→DOWN condition is: (roundCount > probeBWUpRound && bdp > 0)
	//   OR (bytesInFlight > 1.25×BDP).
	// Send a burst, then ACK all of it to cross the round boundary.
	nSend := 0
	for s.sender.CanSend(s.bytesInFlight) && nSend < 64 {
		s.sendPacket()
		nSend++
	}
	// ACK all outstanding bytes, which crosses the currentRoundTripEnd boundary.
	s.clock.Advance(rtt)
	allInFlight := int(s.bytesInFlight / bbrTestMaxDatagramSize)
	if allInFlight < 1 {
		allInFlight = 1
	}
	s.ackNPackets(allInFlight, rtt)

	// The UP→DOWN transition may have fired. But DOWN→CRUISE fires immediately
	// when bytesInFlight ≤ BDP. So check if we transited through DOWN.
	// The cycle is: UP→DOWN→CRUISE (transient DOWN is correct BBRv3 behavior).
	phase := s.sender.ProbeBWPhaseValue()
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

	priorInFlight := s.bytesInFlight

	// Inject enough loss to exceed the 2% threshold.
	// We need lossInRound > 0.02 * inflightAtLoss.
	// inflightAtLoss will be priorInFlight (set by first loss call).
	// We need lost bytes > 0.02 * priorInFlight.
	lossNeeded := int(float64(priorInFlight)*bbrLossThreshold/float64(bbrTestMaxDatagramSize)) + 1
	if lossNeeded < 2 {
		lossNeeded = 2
	}
	s.loseNPackets(lossNeeded)

	// After excessive loss in UP, should transition to DOWN and cap inflightHi.
	require.Equal(t, probeBWDown, s.sender.ProbeBWPhaseValue(),
		"excessive loss in UP should trigger transition to DOWN")
	require.Greater(t, s.sender.InflightHi(), protocol.ByteCount(0),
		"inflightHi should be set after excessive loss in UP")
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

	// Verify we're in CRUISE sub-state (entered via enterProbeBWCruise from Drain).
	require.Equal(t, probeBWCruise, s.sender.ProbeBWPhaseValue(),
		"should enter ProbeBW CRUISE after Drain")
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
