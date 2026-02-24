package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// PacketDeliveryState is the connection-level delivery state snapshot taken
// when a packet is sent. These values are stored per-packet and used on ACK
// to compute a delivery rate sample.
type PacketDeliveryState struct {
	Delivered     protocol.ByteCount // cumulative bytes delivered at send time
	DeliveredTime monotime.Time      // time of last delivery update at send time
	FirstSentTime monotime.Time      // send time of first packet in the current flight
	IsAppLimited  bool               // whether the connection was app-limited at send time
}

// RateSample holds the result of a delivery rate computation for one ACK event.
type RateSample struct {
	DeliveryRate   Bandwidth          // computed delivery rate (bits/s)
	IsAppLimited   bool               // whether the triggering packet was sent during app-limited period
	Interval       time.Duration      // max(sendElapsed, ackElapsed)
	Delivered      protocol.ByteCount // total bytes delivered at sample time
	PriorDelivered protocol.ByteCount // bytes delivered when the sampled packet was sent
	PriorTime      monotime.Time      // deliveredTime when the sampled packet was sent
	SendElapsed    time.Duration      // sentTime - firstSentTimeAtSend
	AckElapsed     time.Duration      // now - deliveredTimeAtSend

	// Fields required by BBRv3 per-ACK and per-loss processing (spec §2.2).
	NewlyAcked protocol.ByteCount // RS.newly_acked: bytes acked in this ACK event
	NewlyLost  protocol.ByteCount // RS.newly_lost: bytes lost detected in this ACK event
	TxInFlight protocol.ByteCount // RS.tx_in_flight: C.inflight when acked packet was sent
	PacketLost protocol.ByteCount // RS.lost: bytes lost between transmit and ack of this packet
	PacketSize protocol.ByteCount // size of the individual packet (for per-loss processing)
}

// BandwidthSampleConsumer is implemented by congestion controllers that
// consume delivery-rate samples (e.g. BBRv3). This is separate from
// SendAlgorithm so that controllers like Cubic are unaffected.
type BandwidthSampleConsumer interface {
	OnBandwidthSample(sample RateSample)
}

// AppLimitedSetter allows a congestion controller to mark the connection as
// application-limited. This is used by BBRv3 during ProbeRTT (spec §5.3.4.3)
// to ensure that low-rate samples produced while cwnd is artificially reduced
// are correctly tagged, preventing them from polluting the maxBw filter.
type AppLimitedSetter interface {
	SetAppLimited(limited bool)
}

// AppLimitedAware is optionally implemented by congestion controllers (e.g.
// BBRv3) that need a reference to the AppLimitedSetter so they can call
// MarkConnectionAppLimited() during ProbeRTT as required by the spec.
type AppLimitedAware interface {
	SetAppLimitedSetter(setter AppLimitedSetter)
}

// DeliveryRateEstimator tracks the connection-level state needed to produce
// per-ACK delivery rate samples according to the BBR delivery-rate estimation
// algorithm (draft-cheng-iccrg-delivery-rate-estimation).
type DeliveryRateEstimator struct {
	// delivered is the cumulative count of bytes acknowledged so far.
	delivered protocol.ByteCount
	// deliveredTime is the wall-clock (monotime) at which delivered was last
	// updated.
	deliveredTime monotime.Time
	// firstSentTime is the send time of the first packet in the current
	// flight (reset when bytesInFlight transitions from 0 to >0).
	firstSentTime monotime.Time

	// --- Watermark-based app-limited detection ---
	// Per draft-cheng-iccrg-delivery-rate-estimation §4.1.1.2 and Linux BBR's
	// tp->app_limited: when the send loop runs out of data, we record a
	// watermark = delivered + bytes_in_flight. Once delivered exceeds the
	// watermark (~1 RTT after sending resumes), the flag auto-clears. This
	// prevents relay/proxy scenarios from being permanently app-limited
	// (which happens with a sticky boolean when the cwnd is never filled).
	appLimitedUntil protocol.ByteCount

	// forceAppLimited is set by the congestion controller (e.g. BBRv3 during
	// ProbeRTT) to unconditionally mark packets as app-limited. Unlike the
	// watermark, it does not auto-clear — the controller must explicitly
	// call SetAppLimited(false).
	forceAppLimited bool

	// lastSentAppLimited tracks whether the previous OnPacketSent call saw
	// the connection as app-limited. Used to detect the transition from
	// app-limited → non-app-limited so we can reset firstSentTime, giving
	// fresh delivery rate samples uncontaminated by the app-limited gap.
	lastSentAppLimited bool
}

// NewDeliveryRateEstimator creates a new estimator with zero state.
func NewDeliveryRateEstimator() *DeliveryRateEstimator {
	return &DeliveryRateEstimator{}
}

// OnPacketSent snapshots the current connection-level delivery state. The
// returned PacketDeliveryState must be stored on the sent packet so that
// the rate can be computed when the packet is acknowledged.
//
// sentTime is the packet's send timestamp (monotime).
// bytesInFlight is the number of bytes in flight *before* this packet is added.
func (e *DeliveryRateEstimator) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight protocol.ByteCount,
) PacketDeliveryState {
	// If this is the first packet of a new flight (nothing in flight before),
	// mark the start of the flight.
	if bytesInFlight == 0 {
		e.firstSentTime = sentTime
		e.deliveredTime = sentTime
	}

	isAppLimited := e.forceAppLimited || e.appLimitedUntil > 0

	// When transitioning from app-limited to non-app-limited while there
	// are still packets in flight, reset the send baseline. This ensures
	// delivery rate samples after the transition aren't contaminated by
	// the inflated sendElapsed that includes the app-limited gap. This is
	// critical for proxy/relay scenarios where bytesInFlight rarely
	// reaches 0 and firstSentTime would otherwise never refresh.
	if !isAppLimited && e.lastSentAppLimited && bytesInFlight > 0 {
		e.firstSentTime = sentTime
	}
	e.lastSentAppLimited = isAppLimited

	return PacketDeliveryState{
		Delivered:     e.delivered,
		DeliveredTime: e.deliveredTime,
		FirstSentTime: e.firstSentTime,
		IsAppLimited:  isAppLimited,
	}
}

// GenerateRateSample computes a delivery rate sample when a packet is
// acknowledged. It updates the connection-level delivered counter.
//
// pktState is the delivery snapshot stored on the packet at send time.
// pktSendTime is the packet's original send timestamp.
// ackedBytes is the wire size of the acknowledged packet.
// now is the current time (ACK receipt time).
func (e *DeliveryRateEstimator) GenerateRateSample(
	pktState PacketDeliveryState,
	pktSendTime monotime.Time,
	ackedBytes protocol.ByteCount,
	now monotime.Time,
) RateSample {
	// Update connection-level counters.
	e.delivered += ackedBytes
	e.deliveredTime = now

	// Auto-clear the app-limited watermark once enough bytes have been
	// delivered past the mark, per draft-cheng-iccrg-delivery-rate-estimation
	// §4.1.2.5. This indicates the pipe has "refilled" with non-app-limited data.
	if e.appLimitedUntil > 0 && e.delivered > e.appLimitedUntil {
		e.appLimitedUntil = 0
	}

	// Compute elapsed intervals.
	sendElapsed := pktSendTime.Sub(pktState.FirstSentTime)
	ackElapsed := now.Sub(pktState.DeliveredTime)

	// The interval is the larger of the two: this makes the estimate immune
	// to ACK compression/aggregation.
	interval := max(sendElapsed, ackElapsed)

	// Guard against zero or negative intervals.
	if interval <= 0 {
		return RateSample{
			IsAppLimited:   pktState.IsAppLimited,
			Delivered:      e.delivered,
			PriorDelivered: pktState.Delivered,
			PriorTime:      pktState.DeliveredTime,
			SendElapsed:    sendElapsed,
			AckElapsed:     ackElapsed,
		}
	}

	// delivered_delta = total delivered now - delivered when this pkt was sent.
	deliveredDelta := e.delivered - pktState.Delivered

	// delivery_rate = delivered_delta / interval (in bits/s).
	deliveryRate := BandwidthFromDelta(deliveredDelta, interval)

	return RateSample{
		DeliveryRate:   deliveryRate,
		IsAppLimited:   pktState.IsAppLimited,
		Interval:       interval,
		Delivered:      e.delivered,
		PriorDelivered: pktState.Delivered,
		PriorTime:      pktState.DeliveredTime,
		SendElapsed:    sendElapsed,
		AckElapsed:     ackElapsed,
	}
}

// SetAppLimited is used by congestion controllers to force the app-limited
// state (e.g., BBRv3 during ProbeRTT per spec §5.3.4.3). Unlike the
// watermark set by MarkAppLimited, this flag does not auto-clear — the
// controller must explicitly call SetAppLimited(false).
func (e *DeliveryRateEstimator) SetAppLimited(limited bool) {
	e.forceAppLimited = limited
}

// MarkAppLimited sets the app-limited watermark per
// draft-cheng-iccrg-delivery-rate-estimation §4.1.1.2:
//
//	C.app_limited = (C.delivered + bytes_in_flight) ?: 1
//
// Called by the send loop when the sender runs out of data to send while
// the congestion window is not full. The watermark auto-clears in
// GenerateRateSample when delivered exceeds it (~1 RTT after sending
// resumes), unlike the sticky boolean this replaces.
func (e *DeliveryRateEstimator) MarkAppLimited(bytesInFlight protocol.ByteCount) {
	e.appLimitedUntil = e.delivered + bytesInFlight
	if e.appLimitedUntil == 0 {
		e.appLimitedUntil = 1 // ensure non-zero to indicate app-limited
	}
}

// ClearAppLimitedWatermark immediately clears the send-loop watermark.
// Called when the pipe fills (bytesInFlight >= cwnd), providing faster
// clearing than waiting for the ACK-path auto-clear.
func (e *DeliveryRateEstimator) ClearAppLimitedWatermark() {
	e.appLimitedUntil = 0
}

// IsAppLimited reports whether the connection is currently app-limited,
// either via the send-loop watermark or the CC-forced flag.
func (e *DeliveryRateEstimator) IsAppLimited() bool {
	return e.forceAppLimited || e.appLimitedUntil > 0
}

// Delivered returns the current cumulative delivered byte count.
func (e *DeliveryRateEstimator) Delivered() protocol.ByteCount {
	return e.delivered
}
