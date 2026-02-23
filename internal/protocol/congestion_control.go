package protocol

// CongestionControlAlgorithm identifies the congestion control algorithm to use.
type CongestionControlAlgorithm int

const (
	// CongestionControlBBRv3 selects the BBRv3 congestion control algorithm.
	// This is the default.
	CongestionControlBBRv3 CongestionControlAlgorithm = iota
	// CongestionControlCubic selects the Cubic congestion control algorithm.
	CongestionControlCubic
)
