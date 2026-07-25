package iosmobile

import (
	"errors"
	"io"
	"net/netip"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
)

type engineSessionState uint8

const (
	engineSessionIdle engineSessionState = iota
	engineSessionPrepared
	engineSessionRunning
	engineSessionStopping
	engineSessionStopped
)

type privateKeyLoader func() ([]byte, error)

// EngineSession owns one non-restartable Nebula runtime. Its gomobile surface
// accepts authenticated configuration and packet bytes but has no private-key
// getter, file path, command, or arbitrary execution primitive.
type EngineSession struct {
	mu        sync.Mutex
	sendMu    sync.Mutex
	receiveMu sync.Mutex
	loadKey   privateKeyLoader
	state     engineSessionState
	control   *nebula.Control
	bridge    *packetFlowBridge
}

// NewEngineSession binds one session to an extension-only Keychain identity.
func NewEngineSession(
	accessGroup string,
	identityID string,
) (*EngineSession, error) {
	if err := validateIdentityScope(accessGroup, identityID); err != nil {
		return nil, err
	}
	return newEngineSession(func() ([]byte, error) {
		return loadPrivateKey(accessGroup, identityID)
	}), nil
}

func newEngineSession(loader privateKeyLoader) *EngineSession {
	return &EngineSession{
		loadKey: loader,
		state:   engineSessionIdle,
	}
}

// FrameworkIdentity returns the digest that Prepare requires in the handoff.
func (s *EngineSession) FrameworkIdentity() string {
	return FrameworkIdentitySHA256()
}

// Prepare verifies the complete configuration and constructs an unstarted
// Nebula control with its in-memory callback device.
func (s *EngineSession) Prepare(configurationJSON string) error {
	if s == nil {
		return errors.New("engine session is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != engineSessionIdle || s.loadKey == nil {
		return errors.New("engine session cannot be prepared")
	}
	privateKey, err := s.loadKey()
	if err != nil {
		return errors.New("engine identity key is unavailable")
	}
	defer clear(privateKey)
	verified, err := verifyEngineConfiguration(
		configurationJSON,
		privateKey,
	)
	if err != nil {
		return err
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.PanicLevel)
	var bridge *packetFlowBridge
	factory := overlay.DeviceFactory(
		func(
			_ *config.C,
			_ *logrus.Logger,
			networks []netip.Prefix,
			_ int,
		) (overlay.Device, error) {
			if bridge != nil {
				return nil, errors.New(
					"Nebula requested multiple packet devices",
				)
			}
			var bridgeErr error
			bridge, bridgeErr = newPacketFlowBridge(networks)
			if bridgeErr != nil {
				return nil, bridgeErr
			}
			return bridge.device, nil
		},
	)
	control, err := nebula.Main(
		verified.parsed,
		false,
		"mesh-ios-packet-tunnel",
		logger,
		factory,
	)
	if err != nil || bridge == nil {
		if bridge != nil {
			bridge.close()
		}
		return errors.New("initialize signed Nebula engine")
	}
	s.control = control
	s.bridge = bridge
	s.state = engineSessionPrepared
	return nil
}

// Start activates the already prepared Nebula control.
func (s *EngineSession) Start() error {
	if s == nil {
		return errors.New("engine session is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != engineSessionPrepared || s.control == nil || s.bridge == nil {
		return errors.New("engine session cannot start")
	}
	s.control.Start()
	s.state = engineSessionRunning
	return nil
}

// Send injects one complete IPv4 or IPv6 packet from NEPacketTunnelFlow.
func (s *EngineSession) Send(packet []byte) error {
	if s == nil {
		return errors.New("engine session is unavailable")
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	if s.state != engineSessionRunning || s.bridge == nil {
		s.mu.Unlock()
		return errors.New("engine session is not running")
	}
	bridge := s.bridge
	s.mu.Unlock()
	return bridge.inject(packet)
}

// Receive blocks until Nebula emits one complete packet or the session stops.
func (s *EngineSession) Receive() ([]byte, error) {
	if s == nil {
		return nil, errors.New("engine session is unavailable")
	}
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	s.mu.Lock()
	if s.state == engineSessionStopping || s.state == engineSessionStopped {
		s.mu.Unlock()
		return nil, io.EOF
	}
	if s.state != engineSessionRunning || s.bridge == nil {
		s.mu.Unlock()
		return nil, errors.New("engine session is not running")
	}
	bridge := s.bridge
	s.mu.Unlock()
	return bridge.next()
}

// Rebind asks Nebula to reopen its UDP listener after an Apple path change.
func (s *EngineSession) Rebind() error {
	if s == nil {
		return errors.New("engine session is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != engineSessionRunning || s.control == nil {
		return errors.New("engine session is not running")
	}
	s.control.RebindUDPServer()
	return nil
}

// Stop is idempotent and permanently closes the session.
func (s *EngineSession) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	switch s.state {
	case engineSessionStopping, engineSessionStopped:
		s.mu.Unlock()
		return
	}
	control := s.control
	bridge := s.bridge
	s.state = engineSessionStopping
	s.mu.Unlock()

	if control != nil {
		control.Stop()
	} else if bridge != nil {
		bridge.close()
	}

	s.mu.Lock()
	s.control = nil
	s.bridge = nil
	s.loadKey = nil
	s.state = engineSessionStopped
	s.mu.Unlock()
}
