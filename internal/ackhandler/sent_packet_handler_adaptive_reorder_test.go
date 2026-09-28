package ackhandler

import (
	"testing"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/internal/monotime"
	"github.com/apernet/quic-go/internal/protocol"
	"github.com/apernet/quic-go/internal/utils"
	"github.com/apernet/quic-go/internal/wire"
	publicMonotime "github.com/apernet/quic-go/monotime"

	"github.com/stretchr/testify/require"
)

// fakeSpuriousLossCC is a congestion controller that records spurious loss
// notifications, in order to check that they are forwarded to congestion
// controllers implementing congestion.SpuriousLossObserver.
type fakeSpuriousLossCC struct {
	spurious []int
}

var _ congestion.CongestionControlEx = &fakeSpuriousLossCC{}
var _ congestion.SpuriousLossObserver = &fakeSpuriousLossCC{}

func (f *fakeSpuriousLossCC) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {}
func (f *fakeSpuriousLossCC) TimeUntilSend(bytesInFlight congestion.ByteCount) publicMonotime.Time {
	return 0
}
func (f *fakeSpuriousLossCC) HasPacingBudget(now publicMonotime.Time) bool { return true }
func (f *fakeSpuriousLossCC) OnPacketSent(sentTime publicMonotime.Time, bytesInFlight congestion.ByteCount, packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool) {
}
func (f *fakeSpuriousLossCC) CanSend(bytesInFlight congestion.ByteCount) bool { return true }
func (f *fakeSpuriousLossCC) MaybeExitSlowStart()                              {}
func (f *fakeSpuriousLossCC) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount, priorInFlight congestion.ByteCount, eventTime publicMonotime.Time) {
}
func (f *fakeSpuriousLossCC) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount, priorInFlight congestion.ByteCount) {
}
func (f *fakeSpuriousLossCC) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime publicMonotime.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
}
func (f *fakeSpuriousLossCC) OnRetransmissionTimeout(packetsRetransmitted bool) {}
func (f *fakeSpuriousLossCC) SetMaxDatagramSize(size congestion.ByteCount)      {}
func (f *fakeSpuriousLossCC) InSlowStart() bool                                 { return false }
func (f *fakeSpuriousLossCC) InRecovery() bool                                  { return false }
func (f *fakeSpuriousLossCC) GetCongestionWindow() congestion.ByteCount         { return 1000 }
func (f *fakeSpuriousLossCC) OnSpuriousLoss(count int) {
	f.spurious = append(f.spurious, count)
}

// newAdaptiveReorderTestHandler returns a handler for the 1-RTT space with a
// fake congestion controller that records spurious loss notifications.
func newAdaptiveReorderTestHandler(t *testing.T) (*sentPacketHandler, *packetTracker, *fakeSpuriousLossCC) {
	t.Helper()
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		true,
		false,
		nil,
		protocol.PerspectiveServer,
		false,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)
	cc := &fakeSpuriousLossCC{}
	sph.SetCongestionControl(cc)
	return sph, &packetTracker{}, cc
}

// raiseReorderThreshold sends 20 packets 10ms apart and acknowledges them with a
// deep reordering pattern, such that packets 1, 2 and 3 are spuriously declared
// lost. Detecting those spurious losses raises the adaptive reordering
// threshold to 1.25 * (16 - 1) = 18.75.
func raiseReorderThreshold(t *testing.T, sph *sentPacketHandler, packets *packetTracker) monotime.Time {
	t.Helper()
	sendPacket := func(ti monotime.Time) protocol.PacketNumber {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	const rtt = time.Second
	start := monotime.Now()
	now := start
	var pns []protocol.PacketNumber
	for range 20 {
		pns = append(pns, sendPacket(now))
		now = now.Add(10 * time.Millisecond)
	}

	// ACK {0..6}: declares packets 1, 2, 3 lost (reordering threshold 3).
	now = start.Add(rtt)
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[6])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0], pns[6]}, packets.Acked)
	require.Equal(t, []protocol.PacketNumber{pns[1], pns[2], pns[3]}, packets.Lost)
	require.Equal(t, float64(packetThreshold), sph.reorderThreshold)

	// ACK {0..6, 12, 16}: packets 1, 2 and 3 turn out to be merely reordered.
	packets.Reset()
	now = now.Add(50 * time.Millisecond)
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2], pns[3], pns[4], pns[5], pns[6], pns[12], pns[16])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	return now
}

func TestAdaptiveReorderThresholdRaise(t *testing.T) {
	sph, packets, cc := newAdaptiveReorderTestHandler(t)
	lastAckTime := raiseReorderThreshold(t, sph, packets)

	// The largest observed reordering extent is Difference(16, 1) = 15,
	// so the threshold is raised to 1.25 * 15 = 18.75.
	require.Equal(t, 18.75, sph.reorderThreshold)
	require.Equal(t, []int{3}, cc.spurious)

	// While the threshold is raised, packets that lag behind the largest acked
	// by less than the new threshold are no longer declared lost.
	// Packets 7..11, 13..15, 17..19 are still outstanding; acknowledging 19
	// leaves 7 with a reordering extent of 12, which is below the threshold.
	packets.Reset()
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(19)},
		protocol.Encryption1RTT,
		lastAckTime.Add(30*time.Millisecond),
	)
	require.NoError(t, err)
	require.Empty(t, packets.Lost)
	require.Equal(t, 18.75, sph.reorderThreshold)
}

func TestAdaptiveReorderThresholdDecay(t *testing.T) {
	sph, packets, _ := newAdaptiveReorderTestHandler(t)
	lastAckTime := raiseReorderThreshold(t, sph, packets)

	sendPacket := func(ti monotime.Time) protocol.PacketNumber {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(ti, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		return pn
	}

	// After more than 4 smoothed RTTs (~4s) without any significant reordering,
	// the threshold decays by 25% per smoothed RTT.
	now := lastAckTime.Add(5 * time.Second)
	pn := sendPacket(now)
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn)},
		protocol.Encryption1RTT,
		now.Add(100*time.Millisecond),
	)
	require.NoError(t, err)
	require.Equal(t, 18.75*reorderThresholdDecayFactor, sph.reorderThreshold)

	// Decay is limited to one step per smoothed RTT.
	pn = sendPacket(now.Add(100 * time.Millisecond))
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn)},
		protocol.Encryption1RTT,
		now.Add(200*time.Millisecond),
	)
	require.NoError(t, err)
	require.Equal(t, 18.75*reorderThresholdDecayFactor, sph.reorderThreshold)

	pn = sendPacket(now.Add(time.Second))
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn)},
		protocol.Encryption1RTT,
		now.Add(time.Second+100*time.Millisecond),
	)
	require.NoError(t, err)
	require.Equal(t, 18.75*reorderThresholdDecayFactor*reorderThresholdDecayFactor, sph.reorderThreshold)
}

func TestAdaptiveReorderThresholdResetOnPathMigration(t *testing.T) {
	sph, packets, _ := newAdaptiveReorderTestHandler(t)
	lastAckTime := raiseReorderThreshold(t, sph, packets)
	require.Equal(t, 18.75, sph.reorderThreshold)

	sph.MigratedPath(lastAckTime.Add(time.Second), 1200)
	require.Equal(t, float64(packetThreshold), sph.reorderThreshold)
}

func TestAdaptiveReorderThresholdCap(t *testing.T) {
	sph, _, _ := newAdaptiveReorderTestHandler(t)
	now := monotime.Now()

	// Even an absurdly large observed reordering extent must not raise the
	// threshold beyond maxReorderThreshold.
	sph.updateReorderThreshold(100000, now)
	require.Equal(t, float64(maxReorderThreshold), sph.reorderThreshold)
	require.Equal(t, now, sph.lastReorderSignal)

	// A smaller observation that still exceeds the cap.
	sph2, _, _ := newAdaptiveReorderTestHandler(t)
	sph2.updateReorderThreshold(1000, now)
	require.Equal(t, float64(maxReorderThreshold), sph2.reorderThreshold)
}

func TestAdaptiveReorderThresholdNotAppliedTo0RTT(t *testing.T) {
	sph, packets, _ := newAdaptiveReorderTestHandler(t)
	sph.updateReorderThreshold(100, monotime.Now())
	require.Greater(t, sph.reorderThreshold, float64(packetThreshold))

	// Establish an RTT measurement so the time threshold doesn't interfere
	// with the packet threshold assertions below.
	now := monotime.Now()
	pn := sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pn)},
		protocol.Encryption1RTT,
		now.Add(time.Second),
	)
	require.NoError(t, err)

	// 0-RTT packets share the application data packet number space, but loss
	// detection for them keeps the fixed threshold: packet 0 is declared lost
	// at a reordering extent of 3, even though the adaptive threshold is 125.
	var pns []protocol.PacketNumber
	now = now.Add(time.Second)
	for range 5 {
		pn := sph.PopPacketNumber(protocol.Encryption0RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption0RTT, protocol.ECNNon, 1000, false, false)
		pns = append(pns, pn)
	}
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[3])},
		protocol.Encryption0RTT,
		now.Add(time.Second),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[0]}, packets.Lost)
	require.Equal(t, []protocol.PacketNumber{pn, pns[3]}, packets.Acked)
}

func TestAdaptiveReorderThresholdCleanPath(t *testing.T) {
	sph, packets, cc := newAdaptiveReorderTestHandler(t)

	var pns []protocol.PacketNumber
	now := monotime.Now()
	for range 10 {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		pns = append(pns, pn)
		now = now.Add(10 * time.Millisecond)
	}

	// In-order acknowledgments never raise the threshold.
	_, err := sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[0], pns[1], pns[2], pns[3], pns[4])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Empty(t, packets.Lost)
	require.Equal(t, float64(packetThreshold), sph.reorderThreshold)

	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[5], pns[6], pns[7], pns[8], pns[9])},
		protocol.Encryption1RTT,
		now,
	)
	require.NoError(t, err)
	require.Empty(t, packets.Lost)
	require.Equal(t, float64(packetThreshold), sph.reorderThreshold)
	require.Empty(t, cc.spurious)

	// Packet threshold loss detection keeps working with the default
	// sensitivity: acknowledging only packet 14 declares packets 10 and 11
	// lost (reordering extents 4 and 3).
	packets.Reset()
	for range 5 {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, protocol.Encryption1RTT, protocol.ECNNon, 1000, false, false)
		pns = append(pns, pn)
	}
	_, err = sph.ReceivedAck(
		&wire.AckFrame{AckRanges: ackRanges(pns[14])},
		protocol.Encryption1RTT,
		now.Add(10*time.Millisecond),
	)
	require.NoError(t, err)
	require.Equal(t, []protocol.PacketNumber{pns[10], pns[11]}, packets.Lost)
	require.Equal(t, float64(packetThreshold), sph.reorderThreshold)
}
