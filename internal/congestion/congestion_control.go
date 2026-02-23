package congestion

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

// NewCongestionControl creates a congestion controller based on the algorithm selector.
func NewCongestionControl(
	algo protocol.CongestionControlAlgorithm,
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) SendAlgorithmWithDebugInfos {
	switch algo {
	case protocol.CongestionControlCubic:
		return NewCubicSender(clock, rttStats, connStats, initialMaxDatagramSize, false, qlogger)
	default:
		return NewBBRv3Sender(clock, rttStats, connStats, initialMaxDatagramSize, qlogger)
	}
}
