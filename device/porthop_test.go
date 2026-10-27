package device

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/tun/tuntest"
)

const (
	testHopInterval = 3600
	testHopMin      = 40000
	testHopMax      = 40999
	testStaticEP    = "127.0.0.1:51820"
)

// newPortHopPeer brings up a device with one peer pointed at testStaticEP.
// hopCfg is inserted between the private key and the peer section.
func newPortHopPeer(t *testing.T, hopCfg ...string) *Peer {
	t.Helper()
	priv, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPriv, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerPub := peerPriv.publicKey()

	dev := NewDevice(tuntest.NewChannelTUN().TUN(), bindtest.NewChannelBinds()[0], NewLogger(LogLevelError, ""))
	t.Cleanup(dev.Close)
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	cfg := append([]string{"private_key", hex.EncodeToString(priv[:])}, hopCfg...)
	cfg = append(cfg,
		"public_key", hex.EncodeToString(peerPub[:]),
		"endpoint", testStaticEP,
		"allowed_ip", "0.0.0.0/0",
	)
	if err := dev.IpcSet(uapiCfg(cfg...)); err != nil {
		t.Fatal(err)
	}
	return dev.LookupPeer(peerPub)
}

func portHopCfg() []string {
	return []string{
		"port_hop_interval", fmt.Sprint(testHopInterval),
		"port_hop_range", fmt.Sprintf("%d-%d", testHopMin, testHopMax),
	}
}

func peerEndpoint(p *Peer) string {
	p.endpoint.Lock()
	defer p.endpoint.Unlock()
	return p.endpoint.val.DstToString()
}

func setPeerEndpoint(t *testing.T, p *Peer, s string) {
	t.Helper()
	ep, err := p.device.net.bind.ParseEndpoint(s)
	if err != nil {
		t.Fatal(err)
	}
	p.endpoint.Lock()
	p.endpoint.val = ep
	p.endpoint.Unlock()
}

func currentHopEndpoint(p *Peer) string {
	key := []byte(base64.StdEncoding.EncodeToString(p.handshake.remoteStatic[:]))
	seq := uint64(time.Now().Unix()) / testHopInterval
	return fmt.Sprintf("127.0.0.1:%d", GeneratePortFromSequence(key, seq, testHopMin, testHopMax, nil))
}

func TestPortHopDisabledKeepsEndpoint(t *testing.T) {
	p := newPortHopPeer(t)
	p.SendBuffers([][]byte{{0}})
	p.SendHandshakeInitiation(false)
	if got := peerEndpoint(p); got != testStaticEP {
		t.Fatalf("endpoint changed without port hopping configured: %s", got)
	}
}

func TestPortHopOnSend(t *testing.T) {
	p := newPortHopPeer(t, portHopCfg()...)
	p.SendBuffers([][]byte{{0}})
	if got, want := peerEndpoint(p), currentHopEndpoint(p); got != want {
		t.Fatalf("endpoint after send = %s, want %s", got, want)
	}
}

func TestPortHopOnSlotChange(t *testing.T) {
	p := newPortHopPeer(t, portHopCfg()...)
	p.SendBuffers([][]byte{{0}})

	// Pretend the last hop happened in an earlier slot, onto that slot's port.
	setPeerEndpoint(t, p, testStaticEP)
	p.hopDone.Store(&hopMark{cfg: p.device.portHopping.Load(), slot: 1})

	p.SendBuffers([][]byte{{0}})
	if got, want := peerEndpoint(p), currentHopEndpoint(p); got != want {
		t.Fatalf("endpoint after slot change = %s, want %s", got, want)
	}
}

func TestPortHopHandshakeRechecksPort(t *testing.T) {
	p := newPortHopPeer(t, portHopCfg()...)
	p.SendBuffers([][]byte{{0}})

	// Same slot, but the endpoint moved without going through UAPI or a hop.
	setPeerEndpoint(t, p, testStaticEP)

	p.SendHandshakeInitiation(false)
	if got, want := peerEndpoint(p), currentHopEndpoint(p); got != want {
		t.Fatalf("endpoint after handshake initiation = %s, want %s", got, want)
	}
}

func TestPortHopUAPIEndpointNeverUsesBasePort(t *testing.T) {
	p := newPortHopPeer(t, portHopCfg()...)
	p.SendBuffers([][]byte{{0}})

	pk := hex.EncodeToString(p.handshake.remoteStatic[:])
	if err := p.device.IpcSet(uapiCfg("public_key", pk, "endpoint", testStaticEP)); err != nil {
		t.Fatal(err)
	}
	if got, want := peerEndpoint(p), currentHopEndpoint(p); got != want {
		t.Fatalf("endpoint right after UAPI set = %s, want %s", got, want)
	}
}

func TestPortHopConfigChangeRehops(t *testing.T) {
	p := newPortHopPeer(t, portHopCfg()...)
	p.SendBuffers([][]byte{{0}})

	if err := p.device.IpcSet(uapiCfg("port_hop_range", "50000-50999")); err != nil {
		t.Fatal(err)
	}
	p.SendBuffers([][]byte{{0}})

	key := []byte(base64.StdEncoding.EncodeToString(p.handshake.remoteStatic[:]))
	seq := uint64(time.Now().Unix()) / testHopInterval
	want := fmt.Sprintf("127.0.0.1:%d", GeneratePortFromSequence(key, seq, 50000, 50999, nil))
	if got := peerEndpoint(p); got != want {
		t.Fatalf("endpoint after range change + send = %s, want %s", got, want)
	}
}

// A hop racing with a UAPI endpoint change must never put the old host back.
// The real bind is needed here, as bindtest endpoints drop the host.
func TestPortHopConcurrentEndpointSet(t *testing.T) {
	priv, _ := newPrivateKey()
	peerPriv, _ := newPrivateKey()
	peerPub := peerPriv.publicKey()
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	t.Cleanup(dev.Close)
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	cfg := append([]string{"private_key", hex.EncodeToString(priv[:]), "listen_port", "0"}, portHopCfg()...)
	cfg = append(cfg, "public_key", hex.EncodeToString(peerPub[:]), "endpoint", "127.0.0.1:51820")
	if err := dev.IpcSet(uapiCfg(cfg...)); err != nil {
		t.Fatal(err)
	}
	p := dev.LookupPeer(peerPub)
	pk := hex.EncodeToString(peerPub[:])

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var hops [4]atomic.Int64 // completed hops per goroutine
	for i := range hops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					p.hopToCurrentSlot(true)
					hops[i].Add(1)
				}
			}
		}()
	}
	// Keep changing the range, so the hops above really move the port (and
	// write the endpoint) instead of finding it already correct.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				dev.IpcSet(uapiCfg("port_hop_range", []string{"40000-40999", "50000-50999"}[i%2]))
			}
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
	}()

	for i := 0; i < 1000; i++ {
		want := []string{"127.0.0.1", "127.0.0.2"}[i%2]
		if err := dev.IpcSet(uapiCfg("public_key", pk, "endpoint", want+":51820")); err != nil {
			t.Fatal(err)
		}
		// Let every hop that was already in flight finish before checking.
		for g := range hops {
			for n := hops[g].Load(); hops[g].Load() == n; {
				runtime.Gosched()
			}
		}
		ap, err := netip.ParseAddrPort(peerEndpoint(p))
		if err != nil {
			t.Fatal(err)
		}
		if got := ap.Addr().String(); got != want {
			t.Fatalf("iteration %d: endpoint host %s, want %s", i, got, want)
		}
	}
}

// Changing the hopping settings while traffic flows must not panic (e.g. a
// divide-by-zero when the interval is set to 0).
func TestPortHopRuntimeConfigChange(t *testing.T) {
	p := newPortHopPeer(t, portHopCfg()...)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					p.SendBuffers([][]byte{{0}})
				}
			}
		}()
	}
	for i := 0; i < 500; i++ {
		iv := []string{"60", "0", "3600"}[i%3]
		rng := []string{"40000-40999", "50000-50010", "0-0"}[i%3]
		p.device.IpcSet(uapiCfg("port_hop_interval", iv, "port_hop_range", rng, "port_hop_excluded", "40001,50002"))
	}
	close(stop)
	wg.Wait()
}

func TestGeneratePortFromSequenceExcluded(t *testing.T) {
	key := []byte("test-key")
	excluded := []uint16{40001, 40003, 40003, 39999}
	for seq := uint64(0); seq < 5000; seq++ {
		port := GeneratePortFromSequence(key, seq, 40000, 40004, excluded)
		if port < 40000 || port > 40004 || port == 40001 || port == 40003 {
			t.Fatalf("slot %d: got port %d", seq, port)
		}
	}
	if port := GeneratePortFromSequence(key, 1, 40000, 40001, []uint16{40000, 40001}); port != 40000 {
		t.Fatalf("all ports excluded: got %d, want range start", port)
	}
}
