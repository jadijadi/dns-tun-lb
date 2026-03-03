package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/miekg/dns"
)

type backendPool struct {
	domainSuffix string
	backends     []BackendConfig
	ring         *hashRing
}

type server struct {
	cfg          *Config
	conn         net.PacketConn
	dnsttPools   []backendPool
	forwardAddr  *net.UDPAddr
}

func newServer(cfg *Config) (*server, error) {
	conn, err := net.ListenPacket("udp", cfg.Global.ListenAddress)
	if err != nil {
		return nil, err
	}

	var forwardAddr *net.UDPAddr
	if cfg.Global.DefaultDNSBehavior.Mode == DefaultDNSModeForward {
		if cfg.Global.DefaultDNSBehavior.ForwardResolver == "" {
			return nil, fmt.Errorf("default_dns_behavior.mode is 'forward' but forward_resolver is empty")
		}
		forwardAddr, err = net.ResolveUDPAddr("udp", cfg.Global.DefaultDNSBehavior.ForwardResolver)
		if err != nil {
			return nil, err
		}
	}

	var dnsttPools []backendPool
	for _, p := range cfg.Protocols.Dnstt.Pools {
		if p.DomainSuffix == "" || len(p.Backends) == 0 {
			continue
		}
		ring := newHashRing(p.Backends, 0)
		dnsttPools = append(dnsttPools, backendPool{
			domainSuffix: p.DomainSuffix,
			backends:     p.Backends,
			ring:         ring,
		})
	}

	return &server{
		cfg:         cfg,
		conn:        conn,
		dnsttPools:  dnsttPools,
		forwardAddr: forwardAddr,
	}, nil
}

func (s *server) serve() error {
	defer s.conn.Close()
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		go s.handlePacket(packet, addr)
	}
}

func (s *server) handlePacket(packet []byte, src net.Addr) {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		s.forwardOrDrop(packet, src)
		return
	}

	// dnstt handling
	for _, pool := range s.dnsttPools {
		if !classifyDNSTT(&msg, pool.domainSuffix) {
			continue
		}
		sid, ok := extractDNSTTSessionID(&msg, pool.domainSuffix)
		if !ok {
			s.forwardOrDrop(packet, src)
			return
		}
		backend := pool.ring.choose("dnstt", pool.domainSuffix, sid)
		logDebugf("dnstt session %x -> backend %s (%s)", sid, backend.ID, backend.Address)
		s.forwardToBackend(packet, src, backend.Address)
		return
	}

	s.forwardOrDrop(packet, src)
}

func (s *server) forwardOrDrop(packet []byte, src net.Addr) {
	if s.forwardAddr == nil {
		return
	}
	// Simple stateless forward: send to resolver, copy response back.
	resolverConn, err := net.DialUDP("udp", nil, s.forwardAddr)
	if err != nil {
		logErrorf("forward dial: %v", err)
		return
	}
	defer resolverConn.Close()

	if _, err := resolverConn.Write(packet); err != nil {
		logErrorf("forward write: %v", err)
		return
	}

	resp := make([]byte, 4096)
	n, _, err := resolverConn.ReadFrom(resp)
	if err != nil {
		logErrorf("forward read: %v", err)
		return
	}
	if _, err := s.conn.WriteTo(resp[:n], src); err != nil {
		logErrorf("forward reply: %v", err)
	}
}

func (s *server) forwardToBackend(packet []byte, src net.Addr, backendAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", backendAddr)
	if err != nil {
		logErrorf("resolve backend: %v", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logErrorf("dial backend: %v", err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		logErrorf("write backend: %v", err)
		return
	}

	resp := make([]byte, 4096)
	n, _, err := conn.ReadFrom(resp)
	if err != nil {
		logErrorf("read backend: %v", err)
		return
	}
	if _, err := s.conn.WriteTo(resp[:n], src); err != nil {
		logErrorf("reply backend: %v", err)
	}
}

func main() {
	configPath := flag.String("config", "lb.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		initLogger("") // ensure logger initialized for error path
		logErrorf("load config: %v", err)
		os.Exit(1)
	}

	initLogger(cfg.Logging.Level)

	s, err := newServer(cfg)
	if err != nil {
		logErrorf("init server: %v", err)
		os.Exit(1)
	}

	logInfof("listening on %s", cfg.Global.ListenAddress)
	logInfof("configured %d dnstt pool(s)", len(s.dnsttPools))
	for _, p := range s.dnsttPools {
		logDebugf("dnstt pool %q suffix=%q backends=%d", p.domainSuffix, p.domainSuffix, len(p.backends))
	}

	if err := s.serve(); err != nil {
		logErrorf("serve error: %v", err)
		os.Exit(1)
	}
}

