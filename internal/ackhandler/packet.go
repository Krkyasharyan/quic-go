package ackhandler

import (
	"sync"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

type packetWithPacketNumber struct {
	PacketNumber protocol.PacketNumber
	*packet
}

// A Packet is a packet
type packet struct {
	SendTime        monotime.Time
	StreamFrames    []StreamFrame
	Frames          []Frame
	LargestAcked    protocol.PacketNumber // InvalidPacketNumber if the packet doesn't contain an ACK
	Length          protocol.ByteCount
	EncryptionLevel protocol.EncryptionLevel

	IsPathMTUProbePacket bool // We don't report the loss of Path MTU probe packets to the congestion controller.

	includedInBytesInFlight bool
	isPathProbePacket       bool

	// Delivery rate estimation: snapshot of connection-level state at send time.
	deliveredAtSend     protocol.ByteCount // cumulative bytes delivered when this packet was sent
	deliveredTimeAtSend monotime.Time      // deliveredTime when this packet was sent
	firstSentTimeAtSend monotime.Time      // send time of first packet in flight when this was sent
	isAppLimitedAtSend  bool               // whether the connection was app-limited at send time
	bytesInFlightAtSend protocol.ByteCount // C.inflight when this packet was sent (for BBRv3 tx_in_flight)
	lostAtSend          protocol.ByteCount // C.lost when this packet was sent (for BBRv3 per-packet loss)
}

func (p *packet) Outstanding() bool {
	return !p.IsPathMTUProbePacket && !p.isPathProbePacket && p.IsAckEliciting()
}

func (p *packet) IsAckEliciting() bool {
	return len(p.StreamFrames) > 0 || len(p.Frames) > 0
}

var packetPool = sync.Pool{New: func() any { return &packet{} }}

func getPacket() *packet {
	p := packetPool.Get().(*packet)
	p.StreamFrames = nil
	p.Frames = nil
	p.LargestAcked = 0
	p.Length = 0
	p.EncryptionLevel = protocol.EncryptionLevel(0)
	p.SendTime = 0
	p.IsPathMTUProbePacket = false
	p.includedInBytesInFlight = false
	p.isPathProbePacket = false
	p.deliveredAtSend = 0
	p.deliveredTimeAtSend = 0
	p.firstSentTimeAtSend = 0
	p.isAppLimitedAtSend = false
	p.bytesInFlightAtSend = 0
	p.lostAtSend = 0
	return p
}

// We currently only return Packets back into the pool when they're acknowledged (not when they're lost).
// This simplifies the code, and gives the vast majority of the performance benefit we can gain from using the pool.
func putPacket(p *packet) {
	p.Frames = nil
	p.StreamFrames = nil
	packetPool.Put(p)
}
