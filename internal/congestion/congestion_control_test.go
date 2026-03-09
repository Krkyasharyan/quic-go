package congestion

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func TestNewCongestionControlDefaultIsBBRv3(t *testing.T) {
	cc := NewCongestionControl(
		protocol.CongestionControlBBRv3,
		DefaultClock{},
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		1200,
		nil,
		"",
	)
	_, ok := cc.(*bbrv3Sender)
	require.True(t, ok, "default (BBRv3) should return *bbrv3Sender")
}

func TestNewCongestionControlCubic(t *testing.T) {
	cc := NewCongestionControl(
		protocol.CongestionControlCubic,
		DefaultClock{},
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		1200,
		nil,
		"",
	)
	_, ok := cc.(*cubicSender)
	require.True(t, ok, "Cubic should return *cubicSender")
}

func TestNewCongestionControlUnknownFallsBackToBBRv3(t *testing.T) {
	cc := NewCongestionControl(
		protocol.CongestionControlAlgorithm(99),
		DefaultClock{},
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		1200,
		nil,
		"",
	)
	_, ok := cc.(*bbrv3Sender)
	require.True(t, ok, "unknown algorithm should fall back to BBRv3")
}
