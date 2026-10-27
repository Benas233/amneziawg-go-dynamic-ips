/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
)

type Peer struct {
	isRunning         atomic.Bool
	keypairs          Keypairs
	handshake         Handshake
	device            *Device
	stopping          sync.WaitGroup // routines pending stop
	txBytes           atomic.Uint64  // bytes send to peer (endpoint)
	rxBytes           atomic.Uint64  // bytes received from peer
	lastHandshakeNano atomic.Int64   // nano seconds since epoch
	endpoint          struct {
		sync.Mutex
		val            conn.Endpoint
		hostname       string // original host:port if set via hostname, empty for static IPs
		clearSrcOnTx   bool   // signal to val.ClearSrc() prior to next packet transmission
		disableRoaming bool
	}

	hopDone atomic.Pointer[hopMark] // port hopping config and slot the endpoint was last moved for

	timers struct {
		retransmitHandshake     *Timer
		sendKeepalive           *Timer
		newHandshake            *Timer
		zeroKeyMaterial         *Timer
		persistentKeepalive     *Timer
		handshakeAttempts       atomic.Uint32
		needAnotherKeepalive    atomic.Bool
		sentLastMinuteHandshake atomic.Bool
	}

	state struct {
		sync.Mutex // protects against concurrent Start/Stop
	}

	queue struct {
		staged   chan *QueueOutboundElementsContainer // staged packets before a handshake is available
		outbound *autodrainingOutboundQueue           // sequential ordering of udp transmission
		inbound  *autodrainingInboundQueue            // sequential ordering of tun writing
	}

	cookieGenerator             CookieGenerator
	trieEntries                 list.List
	persistentKeepaliveInterval atomic.Uint32
}

// portHopConfig holds the port hopping settings. A published config is never
// modified; UAPI replaces it as a whole, so senders always see one consistent
// snapshot even while the settings change.
type portHopConfig struct {
	portRange     [2]uint16
	excludedPorts []uint16
	interval      uint64
}

// enabled reports whether port hopping is fully configured. Missing params
// (zero range or zero interval) disable hopping instead of causing a
// divide-by-zero.
func (c *portHopConfig) enabled() bool {
	return c != nil && c.portRange[0] > 0 && c.portRange[1] > 0 && c.portRange[0] <= c.portRange[1] && c.interval > 0
}

// slot returns the current time slot. Only valid if c is enabled.
func (c *portHopConfig) slot() uint64 {
	return uint64(time.Now().Unix()) / c.interval
}

// portHopSettings returns a copy of the current port hopping settings.
func (device *Device) portHopSettings() portHopConfig {
	if c := device.portHopping.Load(); c != nil {
		return *c
	}
	return portHopConfig{}
}

// updatePortHopping publishes a modified copy of the port hopping settings.
// The new config invalidates every peer's hopMark, so each peer re-hops on its
// next send. UAPI calls are serialized, so the copy cannot lose an update.
func (device *Device) updatePortHopping(modify func(*portHopConfig)) {
	c := device.portHopSettings()
	modify(&c)
	device.portHopping.Store(&c)
}

// hopMark records the config and slot a peer's endpoint port was last set for.
type hopMark struct {
	cfg  *portHopConfig
	slot uint64
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	if device.isClosed() {
		return nil, errors.New("device closed")
	}

	// lock resources
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()
	device.peers.Lock()
	defer device.peers.Unlock()

	hop := device.portHopSettings()
	minPort := hop.portRange[0]
	maxPort := hop.portRange[1]

	if minPort > 0 || maxPort > 0 {
		if minPort == 0 || maxPort == 0 {
			return nil, errors.New("invalid port hopping config: both min and max ports must be set")
		}
		if minPort > maxPort {
			return nil, errors.New("port hopping range set incorrectly: min port cannot be greater than max port")
		}
		if hop.interval <= 0 {
			return nil, errors.New("invalid port hopping config: port hopping interval must be greater than 0")
		}
	}

	if len(hop.excludedPorts) > 0 {
		if minPort == 0 || maxPort == 0 {
			return nil, errors.New("invalid port hopping config: excluded ports provided without a valid port range")
		}

		excludedMap := make(map[uint16]bool, len(hop.excludedPorts))
		for _, port := range hop.excludedPorts {
			excludedMap[port] = true
		}

		hasAvailablePort := false
		for p := minPort; p <= maxPort; p++ {
			if !excludedMap[p] {
				hasAvailablePort = true
				break
			}

			if p == 65535 {
				break
			}
		}

		if !hasAvailablePort {
			return nil, errors.New("invalid port hopping config: all ports in range are excluded")
		}
	}

	// check if over limit
	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer
	peer := new(Peer)

	peer.cookieGenerator.Init(pk)
	peer.device = device
	peer.queue.outbound = newAutodrainingOutboundQueue(device)
	peer.queue.inbound = newAutodrainingInboundQueue(device)
	peer.queue.staged = make(chan *QueueOutboundElementsContainer, QueueStagedSize)

	// map public key
	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}

	// pre-compute DH
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// reset endpoint
	peer.endpoint.Lock()
	peer.endpoint.val = nil
	peer.endpoint.disableRoaming = false
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.Unlock()

	// init timers
	peer.timersInit()

	// add
	device.peers.keyMap[pk] = peer

	return peer, nil
}

func (peer *Peer) SendBuffers(buffers [][]byte) error {
	// Must run before taking device.net below, as hopping takes it too.
	peer.hopToCurrentSlot(false)

	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.isClosed() {
		return nil
	}

	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	if endpoint == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}
	if peer.endpoint.clearSrcOnTx {
		endpoint.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()

	err := peer.device.net.bind.Send(buffers, endpoint)
	if err == nil {
		var totalLen uint64
		for _, b := range buffers {
			totalLen += uint64(len(b))
		}
		peer.txBytes.Add(totalLen)
	}
	return err
}

func (peer *Peer) String() string {
	src := peer.handshake.remoteStatic
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	return string(b)
}
func (peer *Peer) Start() {
	if peer.device.isClosed() {
		return
	}

	peer.state.Lock()
	defer peer.state.Unlock()

	if peer.isRunning.Load() {
		return
	}

	device := peer.device
	device.log.Verbosef("%v - Starting", peer)

	peer.stopping.Wait()
	peer.stopping.Add(2)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	peer.device.queue.encryption.wg.Add(1)

	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)

	batchSize := peer.device.BatchSize()
	go peer.RoutineSequentialSender(batchSize)
	go peer.RoutineSequentialReceiver(batchSize)

	if device.portHopping.Load().enabled() {
		peer.endpoint.Lock()
		peer.endpoint.disableRoaming = true
		peer.endpoint.Unlock()
	}

	peer.timersStart()

	peer.isRunning.Store(true)
}

// hopToCurrentSlot points the peer endpoint at the port for the current time
// slot. It runs before every send, but only does work when the config or slot
// changed since the endpoint was last moved, or when force is set (before each
// handshake initiation, as a final check).
func (peer *Peer) hopToCurrentSlot(force bool) {
	cfg := peer.device.portHopping.Load()
	if !cfg.enabled() {
		return
	}

	slot := cfg.slot()
	if m := peer.hopDone.Load(); !force && m != nil && m.cfg == cfg && m.slot == slot {
		return
	}

	peer.hopPort(cfg, slot)
}

// hopPort points the peer endpoint at the port for the given config and slot.
// The endpoint is read and replaced under one lock, so a concurrent UAPI
// endpoint change is never overwritten with the old address, and hopDone is
// only set once the endpoint really is on that port.
func (peer *Peer) hopPort(cfg *portHopConfig, slot uint64) {
	device := peer.device

	// Same lock order as SendBuffers: device.net, then endpoint.
	device.net.RLock()
	defer device.net.RUnlock()

	if device.isClosed() || device.net.bind == nil {
		return // not marked done, so the next send retries
	}

	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	if ep := peer.endpoint.val; ep != nil {
		hopped, changed, err := peer.hopEndpoint(device.net.bind, ep, cfg, slot)
		switch {
		case err != nil:
			device.log.Errorf("%v - Port hop failed for %s: %v", peer, ep.DstToString(), err)
		case changed:
			peer.endpoint.val = hopped
			peer.endpoint.clearSrcOnTx = true
			device.log.Verbosef("%v - Port hop to %s", peer, hopped.DstToString())
		}
	}

	// Marked even on error: retrying within the same slot would fail the same way.
	peer.hopDone.Store(&hopMark{cfg: cfg, slot: slot})
}

// hopEndpoint returns ep moved to the port for the given config and slot, and
// whether that differs from ep.
func (peer *Peer) hopEndpoint(bind conn.Bind, ep conn.Endpoint, cfg *portHopConfig, slot uint64) (conn.Endpoint, bool, error) {
	pubKeyBase64 := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	port := GeneratePortFromSequence([]byte(pubKeyBase64), slot, cfg.portRange[0], cfg.portRange[1], cfg.excludedPorts)
	newPort := strconv.Itoa(int(port))

	host, currentPort, err := net.SplitHostPort(ep.DstToString())
	if err != nil {
		return nil, false, err
	}
	if currentPort == newPort {
		return ep, false, nil
	}

	hopped, err := bind.ParseEndpoint(net.JoinHostPort(host, newPort))
	if err != nil {
		return nil, false, err
	}
	return hopped, true, nil
}

func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device

	// clear key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.next.Load())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushStagedPackets()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.mutex.Unlock()

	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()
}

func (peer *Peer) Stop() {
	peer.state.Lock()
	defer peer.state.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.device.log.Verbosef("%v - Stopping", peer)

	peer.timersStop()
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	peer.stopping.Wait()
	peer.device.queue.encryption.wg.Done() // no more writes to encryption queue from us

	peer.ZeroAndFlushAll()
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.disableRoaming {
		return
	}
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.val = endpoint
}

func (peer *Peer) markEndpointSrcForClearing() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.val == nil {
		return
	}
	peer.endpoint.clearSrcOnTx = true
}

func GeneratePortFromSequence(secretKey []byte, sequence uint64, portMin, portMax uint16, excluded []uint16) uint16 {
	if portMin >= portMax {
		return portMin
	}

	totalRange := uint32(portMax) - uint32(portMin) + 1

	// Count the distinct excluded ports inside the range, instead of walking
	// the whole range, so a hop stays cheap on the send path.
	excludedMap := make(map[uint16]bool, len(excluded))
	var excludedInRange uint32
	for _, p := range excluded {
		if !excludedMap[p] && p >= portMin && p <= portMax {
			excludedInRange++
		}
		excludedMap[p] = true
	}

	if excludedInRange >= totalRange {
		return portMin
	}

	portRange := uint64(totalRange)
	for attempt := uint64(0); attempt < 100; attempt++ {
		payload := make([]byte, 16)
		binary.BigEndian.PutUint64(payload[0:8], sequence)
		binary.BigEndian.PutUint64(payload[8:16], attempt)

		mac := hmac.New(sha256.New, secretKey)
		mac.Write(payload)
		hash := mac.Sum(nil)

		seed := binary.BigEndian.Uint64(hash[:8])
		candidatePort := portMin + uint16(seed%portRange)

		if !excludedMap[candidatePort] {
			return candidatePort
		}
	}

	return portMin
}
