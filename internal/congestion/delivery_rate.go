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
// application-limited using the watermark approach from spec §4.1.2.4.
//
// MarkAppLimited sets C.app_limited = (C.delivered + bytesInFlight) so that
// the flag auto-clears once the "bubble" of app-limited data flushes through.
// ClearAppLimited forces C.app_limited = 0 (non-app-limited).
type AppLimitedSetter interface {
	MarkAppLimited(bytesInFlight protocol.ByteCount)
	ClearAppLimited()
}

// AppLimitedAware is optionally implemented by congestion controllers (e.g.
// BBRv3) that need a reference to the AppLimitedSetter so they can call
// MarkConnectionAppLimited() during ProbeRTT as required by the spec.
type AppLimitedAware interface {
	SetAppLimitedSetter(setter AppLimitedSetter)
}

// DeliveryRateEstimator tracks the connection-level state needed to produce
// per-ACK delivery rate samples according to the BBR delivery-rate estimation
// algorithm (draft-cheng-iccrg-delivery-rate-estimation §4.1.2).
//
// The estimator follows the spec's 3-phase approach:
//  1. InitRateSample() — initialize per-ACK state
//  2. UpdateRateSample() — called per-ACKed-packet, updates C.delivered and
//     tracks the reference (most recently sent) packet
//  3. GenerateRateSample() — called once after all packets are processed,
//     computes the final delivery rate from the reference packet
type DeliveryRateEstimator struct {
	// delivered is the cumulative count of bytes acknowledged so far (C.delivered).
	delivered protocol.ByteCount
	// deliveredTime is the wall-clock (monotime) at which delivered was last
	// updated (C.delivered_time).
	deliveredTime monotime.Time
	// firstSentTime tracks the send time of the reference packet from the
	// most recently completed ACK processing (C.first_send_time). This is
	// updated to P.send_time of the newest ACKed packet during
	// UpdateRateSample, per spec §4.1.2.3. It serves as the anchor for
	// sendElapsed in the next rate sample, ensuring the send-side interval
	// stays bounded (typically ~1 RTT) rather than growing unbounded from
	// connection start.
	firstSentTime monotime.Time
	// appLimited is the delivery-count watermark per spec §4.1.2.4:
	//   C.app_limited = (C.delivered + C.inflight) when marked, or 0.
	// A non-zero value means the connection is app-limited. The flag
	// auto-clears in GenerateRateSample once C.delivered > C.app_limited,
	// i.e. the "bubble" of app-limited data has been ACKed and flushed.
	appLimited protocol.ByteCount

	// --- Per-ACK accumulation state (spec §4.1.2.3 UpdateRateSample) ---
	// These fields are set during the per-packet UpdateRateSample calls and
	// consumed by the final GenerateRateSample call.

	// rsHasData is true if at least one packet has been processed this ACK.
	rsHasData bool
	// rsPriorDelivered is P.delivered from the reference packet.
	rsPriorDelivered protocol.ByteCount
	// rsPriorTime is P.delivered_time from the reference packet.
	rsPriorTime monotime.Time
	// rsIsAppLimited is P.is_app_limited from the reference packet.
	rsIsAppLimited bool
	// rsSendElapsed is P.send_time - P.first_send_time from the reference packet.
	rsSendElapsed time.Duration
	// rsAckElapsed is C.delivered_time - P.delivered_time from the reference packet.
	rsAckElapsed time.Duration
	// rsRefSendTime is the send time of the reference (newest) packet,
	// used to update C.first_send_time after GenerateRateSample.
	rsRefSendTime monotime.Time
	// rsTxInFlight is P.tx_in_flight (bytes in flight at send time) of the
	// reference packet, forwarded to the rate sample for adaptLongTermModel.
	rsTxInFlight protocol.ByteCount
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
//
// Spec §4.1.2.2 OnPacketSent.
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

	return PacketDeliveryState{
		Delivered:     e.delivered,
		DeliveredTime: e.deliveredTime,
		FirstSentTime: e.firstSentTime,
		IsAppLimited:  e.appLimited != 0,
	}
}

// InitRateSample initializes per-ACK state before processing individual
// packet acknowledgements. Must be called once at the start of each ACK event.
//
// Spec §4.1.2.3 InitRateSample.
func (e *DeliveryRateEstimator) InitRateSample() {
	e.rsHasData = false
	e.rsPriorDelivered = 0
	e.rsPriorTime = 0
	e.rsIsAppLimited = false
	e.rsSendElapsed = 0
	e.rsAckElapsed = 0
	e.rsRefSendTime = 0
	e.rsTxInFlight = 0
}

// UpdateRateSample is called for each newly acknowledged packet. It updates
// the connection-level delivered counter and tracks the reference packet
// (the most recently sent packet in this ACK) for rate computation.
//
// pktState is the delivery snapshot stored on the packet at send time.
// pktSendTime is the packet's original send timestamp.
// ackedBytes is the wire size of the acknowledged packet.
// pktTxInFlight is the bytes in flight when this packet was sent (P.tx_in_flight).
// now is the current time (ACK receipt time).
//
// Spec §4.1.2.3 UpdateRateSample.
func (e *DeliveryRateEstimator) UpdateRateSample(
	pktState PacketDeliveryState,
	pktSendTime monotime.Time,
	ackedBytes protocol.ByteCount,
	pktTxInFlight protocol.ByteCount,
	now monotime.Time,
) {
	// Update connection-level counters (C.delivered, C.delivered_time).
	e.delivered += ackedBytes
	e.deliveredTime = now

	// "Update info using the newest packet" (spec §4.1.2.3).
	// IsNewestPacket: P.send_time >= C.first_send_time (in our case we use
	// the reference packet's send time tracked in rsRefSendTime).
	// In QUIC, packets are sent in order, so the last packet in the ACK
	// range is always the newest. We use >= to handle equal timestamps.
	if !e.rsHasData || pktSendTime >= e.rsRefSendTime {
		e.rsHasData = true
		e.rsPriorDelivered = pktState.Delivered
		e.rsPriorTime = pktState.DeliveredTime
		e.rsIsAppLimited = pktState.IsAppLimited
		e.rsSendElapsed = pktSendTime.Sub(pktState.FirstSentTime)
		e.rsAckElapsed = now.Sub(pktState.DeliveredTime)
		e.rsRefSendTime = pktSendTime
		e.rsTxInFlight = pktTxInFlight

		// Spec §4.1.2.3: C.first_send_time = P.send_time
		// This is the CRITICAL update that anchors the next flight's
		// sendElapsed to a recent reference point, preventing sendElapsed
		// from growing unbounded over the connection lifetime.
		e.firstSentTime = pktSendTime
	}
}

// GenerateRateSample computes the final delivery rate sample after all
// packets in an ACK event have been processed via UpdateRateSample.
// Must be called once after all UpdateRateSample calls for the ACK.
//
// Returns a zero-rate RateSample if no valid sample could be computed.
//
// Spec §4.1.2.3 GenerateRateSample.
func (e *DeliveryRateEstimator) GenerateRateSample() RateSample {
	// Spec §4.1.2.3: Clear app-limited field if bubble is ACKed and gone.
	if e.appLimited != 0 && e.delivered > e.appLimited {
		e.appLimited = 0
	}

	if !e.rsHasData || e.rsPriorTime == 0 {
		return RateSample{} // nothing delivered on this ACK
	}

	// Use the longer of send_elapsed and ack_elapsed (spec §4.1.2.3).
	interval := max(e.rsSendElapsed, e.rsAckElapsed)

	if interval <= 0 {
		return RateSample{
			IsAppLimited:   e.rsIsAppLimited,
			Delivered:      e.delivered,
			PriorDelivered: e.rsPriorDelivered,
			PriorTime:      e.rsPriorTime,
			SendElapsed:    e.rsSendElapsed,
			AckElapsed:     e.rsAckElapsed,
			TxInFlight:     e.rsTxInFlight,
		}
	}

	// RS.delivered = C.delivered - RS.prior_delivered
	deliveredDelta := e.delivered - e.rsPriorDelivered

	// RS.delivery_rate = RS.delivered / RS.interval
	deliveryRate := BandwidthFromDelta(deliveredDelta, interval)

	return RateSample{
		DeliveryRate:   deliveryRate,
		IsAppLimited:   e.rsIsAppLimited,
		Interval:       interval,
		Delivered:      e.delivered,
		PriorDelivered: e.rsPriorDelivered,
		PriorTime:      e.rsPriorTime,
		SendElapsed:    e.rsSendElapsed,
		AckElapsed:     e.rsAckElapsed,
		TxInFlight:     e.rsTxInFlight,
	}
}

// MarkAppLimited sets the delivery-count watermark per spec §4.1.2.4:
//
//	C.app_limited = (C.delivered + C.inflight) ? : 1
//
// The watermark auto-clears in GenerateRateSample once C.delivered exceeds
// it, meaning all data that was in flight when app-limited was set has been
// delivered and the "bubble" has flushed.
func (e *DeliveryRateEstimator) MarkAppLimited(bytesInFlight protocol.ByteCount) {
	wm := e.delivered + protocol.ByteCount(bytesInFlight)
	if wm == 0 {
		wm = 1
	}
	e.appLimited = wm
}

// ClearAppLimited forces the connection out of app-limited state.
func (e *DeliveryRateEstimator) ClearAppLimited() {
	e.appLimited = 0
}

// IsAppLimited reports whether the connection is currently app-limited.
func (e *DeliveryRateEstimator) IsAppLimited() bool {
	return e.appLimited != 0
}

// Delivered returns the current cumulative delivered byte count.
func (e *DeliveryRateEstimator) Delivered() protocol.ByteCount {
	return e.delivered
}
