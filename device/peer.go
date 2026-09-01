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
	"fmt"
	"log"
	"net"
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
	portHopSequence   atomic.Uint64
	endpoint          struct {
		sync.Mutex
		val            conn.Endpoint
		hostname       string // original host:port if set via hostname, empty for static IPs
		clearSrcOnTx   bool   // signal to val.ClearSrc() prior to next packet transmission
		disableRoaming bool
	}

	portHopStop chan struct{}

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

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	if device.isClosed() {
		return nil, errors.New("device closed")
	}

	// lock resources
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()
	device.peers.Lock()
	defer device.peers.Unlock()

	minPort := device.portHopping.portRange[0]
	maxPort := device.portHopping.portRange[1]

	if minPort > 0 || maxPort > 0 {
		if minPort == 0 || maxPort == 0 {
			return nil, errors.New("invalid port hopping config: both min and max ports must be set")
		}
		if minPort > maxPort {
			return nil, errors.New("port hopping range set incorrectly: min port cannot be greater than max port")
		}
	}

	if device.portHopping.interval <= 0 {
		return nil, errors.New("invalid port hopping config: port hopping interval must be greater than 0")
	}

	if len(device.portHopping.excludedPorts) > 0 {
		if minPort == 0 || maxPort == 0 {
			return nil, errors.New("invalid port hopping config: excluded ports provided without a valid port range")
		}

		excludedMap := make(map[uint16]bool, len(device.portHopping.excludedPorts))
		for _, port := range device.portHopping.excludedPorts {
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
	peer.stopping.Add(3)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	peer.device.queue.encryption.wg.Add(1)

	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)

	portHopStop := make(chan struct{})
	peer.portHopStop = portHopStop

	batchSize := peer.device.BatchSize()
	go peer.RoutineSequentialSender(batchSize)
	go peer.RoutineSequentialReceiver(batchSize)

	peer.endpoint.Lock()
	peer.endpoint.disableRoaming = true
	peer.endpoint.Unlock()

	peer.doSingleHop()

	peer.timersStart()

	go peer.PortHopRoutine(portHopStop)

	peer.isRunning.Store(true)
}

// doSingleHop calculates the current target port, updates memory, and resets handshake state.
func (peer *Peer) doSingleHop() bool {
	device := peer.device

	peer.endpoint.Lock()
	if peer.endpoint.val == nil {
		peer.endpoint.Unlock()
		return true
	}
	currentEndpointStr := peer.endpoint.val.DstToString()
	peer.endpoint.Unlock()

	host, _, err := net.SplitHostPort(currentEndpointStr)
	if err != nil {
		log.Printf("[PortHop] Failed to parse endpoint host: %v", err)
		return true
	}

	currentTime := time.Now().Unix()
	timeStep := device.portHopping.interval
	nextSeq := uint64(currentTime) / timeStep

	pubKeyBase64 := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	pubKeyBase64Bytes := []byte(pubKeyBase64)
	portMin := device.portHopping.portRange[0]
	portMax := device.portHopping.portRange[1]

	newPort := GeneratePortFromSequence(pubKeyBase64Bytes, nextSeq, portMin, portMax, device.portHopping.excludedPorts)
	newEndpointStr := fmt.Sprintf("%s:%d", host, newPort)

	if device.isClosed() {
		return false
	}

	device.net.RLock()
	bind := device.net.bind
	device.net.RUnlock()

	if bind == nil {
		return true
	}

	endpoint, err := bind.ParseEndpoint(newEndpointStr)
	if err != nil {
		log.Printf("[PortHop] ParseEndpoint error for %s: %v", newEndpointStr, err)
		return true
	}

	peer.endpoint.Lock()
	peer.endpoint.val = endpoint
	peer.endpoint.hostname = newEndpointStr
	peer.endpoint.clearSrcOnTx = true
	peer.endpoint.Unlock()

	peer.FlushStagedPackets()

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	return true
}

func (peer *Peer) PortHopRoutine(portHopStop <-chan struct{}) {
	defer peer.stopping.Done()

	ticker := time.NewTicker(time.Duration(peer.device.portHopping.interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-portHopStop:
			return
		case <-ticker.C:
			select {
			case <-portHopStop:
				return
			default:
			}

			if !peer.doSingleHop() {
				return
			}

			if peer.isRunning.Load() {
				peer.SendHandshakeInitiation(true)
			}
		}
	}
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
	close(peer.portHopStop)
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

	excludedMap := make(map[uint16]bool, len(excluded))
	for _, p := range excluded {
		excludedMap[p] = true
	}

	totalRange := uint32(portMax) - uint32(portMin) + 1
	var availablePorts uint32
	for p := uint32(portMin); p <= uint32(portMax); p++ {
		if !excludedMap[uint16(p)] {
			availablePorts++
		}
	}

	if availablePorts == 0 {
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

func (peer *Peer) PortHop(portHopStop <-chan struct{}) {
	defer peer.stopping.Done()
	device := peer.device

	ticker := time.NewTicker(time.Duration(peer.device.portHopping.interval) * time.Second)
	defer ticker.Stop()

	pubKeyBase64 := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	pubKeyBase64Bytes := []byte(pubKeyBase64)
	portMin := device.portHopping.portRange[0]
	portMax := device.portHopping.portRange[1]

	peer.endpoint.Lock()
	peer.endpoint.disableRoaming = true
	peer.endpoint.Unlock()

	doHop := func() bool {
		select {
		case <-portHopStop:
			return false
		default:
		}

		peer.endpoint.Lock()
		if peer.endpoint.val == nil {
			peer.endpoint.Unlock()
			return true
		}
		currentEndpointStr := peer.endpoint.val.DstToString()
		peer.endpoint.Unlock()

		host, _, err := net.SplitHostPort(currentEndpointStr)
		if err != nil {
			log.Printf("[PortHop] Failed to parse endpoint host: %v", err)
			return true
		}

		currentTime := time.Now().Unix()
		timeStep := int64(300)
		nextSeq := uint64(currentTime / timeStep)

		newPort := GeneratePortFromSequence(pubKeyBase64Bytes, nextSeq, portMin, portMax, device.portHopping.excludedPorts)
		newEndpointStr := fmt.Sprintf("%s:%d", host, newPort)

		if device.isClosed() {
			return false
		}

		device.net.RLock()
		bind := device.net.bind
		device.net.RUnlock()

		if bind == nil {
			return true
		}
		endpoint, err := bind.ParseEndpoint(newEndpointStr)
		if err != nil {
			log.Printf("[PortHop] ParseEndpoint error for %s: %v", newEndpointStr, err)
			return true
		}

		peer.endpoint.Lock()
		peer.endpoint.val = endpoint
		peer.endpoint.hostname = newEndpointStr
		peer.endpoint.Unlock()
		return true
	}

	if !doHop() {
		return
	}

	for {
		select {
		case <-portHopStop:
			return
		case <-ticker.C:
			if !doHop() {
				return
			}
		}
	}
}
