package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

const testPacketSize protocol.ByteCount = 1200

func TestDeliveryRateEstimatorBatchedACK(t *testing.T) {
	// Simulate sending 10 packets at 1ms intervals, then ACKing all at once
	// after 100ms. The delivery rate should reflect the aggregate throughput,
	// not single-packet / RTT.
	e := NewDeliveryRateEstimator()

	var now monotime.Time = 1_000_000_000 // 1s offset for clarity
	const interval = time.Millisecond

	type pktInfo struct {
		state    PacketDeliveryState
		sendTime monotime.Time
	}
	packets := make([]pktInfo, 10)

	// --- Send path ---
	var bytesInFlight protocol.ByteCount
	for i := 0; i < 10; i++ {
		state := e.OnPacketSent(now, bytesInFlight)
		packets[i] = pktInfo{state: state, sendTime: now}
		bytesInFlight += testPacketSize
		now += monotime.Time(interval)
	}

	// Advance time to 100ms after the first send.
	ackTime := packets[0].sendTime + monotime.Time(100*time.Millisecond)

	// --- ACK path: acknowledge all 10 packets at once ---
	var bestSample RateSample
	for i := 0; i < 10; i++ {
		sample := e.GenerateRateSample(
			packets[i].state,
			packets[i].sendTime,
			testPacketSize,
			ackTime,
		)
		if sample.DeliveryRate > bestSample.DeliveryRate {
			bestSample = sample
		}
	}

	// Expected: 10 * 1200 = 12000 bytes delivered over ~100ms interval.
	// sendElapsed for last packet = 9ms, ackElapsed for first packet ≈ 100ms.
	// The best sample should come from the last packet (most delivered delta).
	// delivery_rate = (12000 bytes) / 100ms ≈ 120,000 bytes/s = 960,000 bits/s
	expectedBytesPerSec := float64(10*testPacketSize) / 0.1
	actualBytesPerSec := float64(bestSample.DeliveryRate / BytesPerSecond)

	// Allow 10% tolerance for integer arithmetic.
	require.InDelta(t, expectedBytesPerSec, actualBytesPerSec, expectedBytesPerSec*0.10,
		"delivery rate should reflect aggregate throughput, got %v bytes/s, want ~%v", actualBytesPerSec, expectedBytesPerSec)
	require.Greater(t, bestSample.DeliveryRate, Bandwidth(0), "delivery rate must be > 0")
}

func TestDeliveryRateEstimatorSendElapsedVsAckElapsed(t *testing.T) {
	// When ACKs arrive faster than packets were sent, sendElapsed should
	// dominate. When ACKs are delayed, ackElapsed should dominate.
	e := NewDeliveryRateEstimator()

	var now monotime.Time = 1_000_000_000

	// Send 2 packets 50ms apart.
	s1 := e.OnPacketSent(now, 0)
	t1 := now
	now += monotime.Time(50 * time.Millisecond)

	s2 := e.OnPacketSent(now, testPacketSize)
	t2 := now

	// Case 1: ACK both at send_time + 60ms (ackElapsed for pkt1 = 60ms > sendElapsed for pkt2 = 50ms).
	ackTime := t1 + monotime.Time(60*time.Millisecond)
	_ = e.GenerateRateSample(s1, t1, testPacketSize, ackTime) // update delivered counter
	sample := e.GenerateRateSample(s2, t2, testPacketSize, ackTime)

	require.Equal(t, 60*time.Millisecond, sample.AckElapsed, "ackElapsed should be 60ms")
	require.Equal(t, 50*time.Millisecond, sample.SendElapsed, "sendElapsed should be 50ms")
	require.Equal(t, 60*time.Millisecond, sample.Interval, "interval should be max(50ms, 60ms) = 60ms")

	// Verify the delivery rate uses the correct 60ms interval.
	e2 := NewDeliveryRateEstimator()
	now2 := monotime.Time(2_000_000_000)

	// Case 2: Send 2 packets 100ms apart, ACK both 30ms after first send.
	s1b := e2.OnPacketSent(now2, 0)
	t1b := now2
	now2 += monotime.Time(100 * time.Millisecond)
	s2b := e2.OnPacketSent(now2, testPacketSize)
	t2b := now2

	ackTime2 := t1b + monotime.Time(30*time.Millisecond)
	_ = e2.GenerateRateSample(s1b, t1b, testPacketSize, ackTime2)
	sample2 := e2.GenerateRateSample(s2b, t2b, testPacketSize, ackTime2)

	require.Equal(t, 100*time.Millisecond, sample2.SendElapsed, "sendElapsed should be 100ms")
	require.Equal(t, 100*time.Millisecond, sample2.Interval, "interval should be max(100ms, 30ms) = 100ms")
}

func TestDeliveryRateEstimatorAppLimited(t *testing.T) {
	e := NewDeliveryRateEstimator()

	var now monotime.Time = 1_000_000_000

	// Mark as app-limited using watermark, then send a packet.
	e.MarkAppLimited(0) // no inflight → watermark = max(delivered + 0, 1) = 1
	state := e.OnPacketSent(now, 0)
	require.True(t, state.IsAppLimited, "snapshot should record app-limited state")

	// ACK it.
	ackTime := now + monotime.Time(100*time.Millisecond)
	sample := e.GenerateRateSample(state, now, testPacketSize, ackTime)
	require.True(t, sample.IsAppLimited, "sample should be marked as app-limited")

	// Clear app-limited, send a packet when NOT app-limited.
	e.ClearAppLimited()
	now = ackTime
	state2 := e.OnPacketSent(now, testPacketSize)
	require.False(t, state2.IsAppLimited, "should not be app-limited")
}

func TestDeliveryRateEstimatorZeroInterval(t *testing.T) {
	e := NewDeliveryRateEstimator()

	now := monotime.Time(1_000_000_000)
	state := e.OnPacketSent(now, 0)

	// ACK immediately (same timestamp → interval = 0).
	sample := e.GenerateRateSample(state, now, testPacketSize, now)
	require.Equal(t, Bandwidth(0), sample.DeliveryRate, "should return 0 for zero interval")
}

func TestDeliveryRateEstimatorCumulativeDelivered(t *testing.T) {
	e := NewDeliveryRateEstimator()

	var now monotime.Time = 1_000_000_000

	// Send and ACK 3 packets sequentially.
	for i := 0; i < 3; i++ {
		state := e.OnPacketSent(now, protocol.ByteCount(i)*testPacketSize)
		now += monotime.Time(10 * time.Millisecond)
		_ = e.GenerateRateSample(state, now-monotime.Time(10*time.Millisecond), testPacketSize, now)
	}

	require.Equal(t, 3*testPacketSize, e.Delivered(), "delivered counter should be 3 packets")
}

func TestDeliveryRateEstimatorNewFlightResets(t *testing.T) {
	e := NewDeliveryRateEstimator()

	now := monotime.Time(1_000_000_000)

	// First flight.
	s1 := e.OnPacketSent(now, 0) // bytesInFlight=0 → new flight
	require.Equal(t, now, s1.FirstSentTime, "first packet should set firstSentTime")

	// Second packet in same flight.
	now += monotime.Time(time.Millisecond)
	s2 := e.OnPacketSent(now, testPacketSize)
	require.Equal(t, s1.FirstSentTime, s2.FirstSentTime, "same flight should keep firstSentTime")

	// ACK both, then start a new flight.
	ackTime := now + monotime.Time(50*time.Millisecond)
	_ = e.GenerateRateSample(s1, s1.FirstSentTime, testPacketSize, ackTime)
	_ = e.GenerateRateSample(s2, now, testPacketSize, ackTime)

	// New flight (bytesInFlight=0 again).
	now = ackTime + monotime.Time(time.Millisecond)
	s3 := e.OnPacketSent(now, 0)
	require.Equal(t, now, s3.FirstSentTime, "new flight should reset firstSentTime")
}

func TestDeliveryRateEstimatorImmunityToACKAggregation(t *testing.T) {
	// Core invariant: delivery rate should be approximately the same whether
	// we ACK packets individually or in a batch.

	// --- Scenario A: ACK each packet individually ---
	eA := NewDeliveryRateEstimator()
	nowA := monotime.Time(1_000_000_000)
	const numPackets = 10
	const rtt = 50 * time.Millisecond
	const sendInterval = time.Millisecond

	var bestRateA Bandwidth
	var bytesInFlightA protocol.ByteCount
	type sentPkt struct {
		state    PacketDeliveryState
		sendTime monotime.Time
	}
	pktsA := make([]sentPkt, numPackets)
	for i := 0; i < numPackets; i++ {
		s := eA.OnPacketSent(nowA, bytesInFlightA)
		pktsA[i] = sentPkt{state: s, sendTime: nowA}
		bytesInFlightA += testPacketSize
		nowA += monotime.Time(sendInterval)
	}
	// ACK each one individually, each arriving 1ms apart starting at rtt after first send.
	ackTimeA := pktsA[0].sendTime + monotime.Time(rtt)
	for i := 0; i < numPackets; i++ {
		sample := eA.GenerateRateSample(pktsA[i].state, pktsA[i].sendTime, testPacketSize, ackTimeA)
		if sample.DeliveryRate > bestRateA {
			bestRateA = sample.DeliveryRate
		}
		ackTimeA += monotime.Time(sendInterval)
	}

	// --- Scenario B: ACK all packets at once ---
	eB := NewDeliveryRateEstimator()
	nowB := monotime.Time(1_000_000_000)
	var bytesInFlightB protocol.ByteCount
	pktsB := make([]sentPkt, numPackets)
	for i := 0; i < numPackets; i++ {
		s := eB.OnPacketSent(nowB, bytesInFlightB)
		pktsB[i] = sentPkt{state: s, sendTime: nowB}
		bytesInFlightB += testPacketSize
		nowB += monotime.Time(sendInterval)
	}
	ackTimeB := pktsB[0].sendTime + monotime.Time(rtt)
	var bestRateB Bandwidth
	for i := 0; i < numPackets; i++ {
		sample := eB.GenerateRateSample(pktsB[i].state, pktsB[i].sendTime, testPacketSize, ackTimeB)
		if sample.DeliveryRate > bestRateB {
			bestRateB = sample.DeliveryRate
		}
	}

	// Both should produce rates within 20% of each other.
	ratioAB := float64(bestRateA) / float64(bestRateB)
	require.InDelta(t, 1.0, ratioAB, 0.20,
		"individual ACK rate (%v) vs batched ACK rate (%v) should be similar", bestRateA, bestRateB)
}
