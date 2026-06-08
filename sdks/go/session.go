package sibna

import (
	"fmt"
	"time"
)

// ── SessionConfig ──────────────────────────────────────────────────────────

type SessionConfig struct {
	MaxSkippedMessages int
	MaxChainMessages   int
}

func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		MaxSkippedMessages: MaxSkippedMessages,
		MaxChainMessages:   MaxChainMessages,
	}
}

// ── Session ────────────────────────────────────────────────────────────────

type Session struct {
	Config       *SessionConfig
	Ratchet      *DoubleRatchet
	SessionID    string
	EstablishedAt float64
	PeerID       []byte
}

func NewSession(config *SessionConfig) *Session {
	if config == nil {
		config = DefaultSessionConfig()
	}
	return &Session{
		Config:    config,
		SessionID: generateSessionID(),
	}
}

func (s *Session) IsEstablished() bool {
	return s.Ratchet != nil
}

func (s *Session) MessagesSent() int {
	if s.Ratchet != nil {
		return s.Ratchet.MessagesSent
	}
	return 0
}

func (s *Session) MessagesReceived() int {
	if s.Ratchet != nil {
		return s.Ratchet.MessagesReceived
	}
	return 0
}

// ── Initiator ──────────────────────────────────────────────────────────────

func (s *Session) InitiateAsInitiator(
	identity, ephemeral *X25519KeyPair,
	peerBundle *PreKeyBundle,
	ourDeviceID, peerDeviceID []byte,
) ([]byte, error) {
	result, err := X3DHInitiator(
		identity,
		ephemeral,
		peerBundle,
		ourDeviceID,
		peerDeviceID,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("x3dh initiator: %w", err)
	}

	s.Ratchet, err = DoubleRatchetFromSharedSecret(
		result.SharedSecret,
		ephemeral.PrivateKeyBytes(),
		peerBundle.SignedPreKey,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("init ratchet: %w", err)
	}
	s.EstablishedAt = float64(time.Now().Unix())
	s.PeerID = append([]byte{}, peerBundle.IdentityKey...)

	return ephemeral.PublicKeyBytes(), nil
}

// ── Responder ──────────────────────────────────────────────────────────────

func (s *Session) InitiateAsResponder(
	identity, signedPrekey *X25519KeyPair,
	onetimePrekey *X25519KeyPair,
	peerIdentity, peerEphemeral []byte,
	ourDeviceID, peerDeviceID []byte,
) error {
	result, err := X3DHResponder(
		identity,
		signedPrekey,
		onetimePrekey,
		peerIdentity,
		peerEphemeral,
		ourDeviceID,
		peerDeviceID,
		nil,
	)
	if err != nil {
		return fmt.Errorf("x3dh responder: %w", err)
	}

	s.Ratchet, err = DoubleRatchetFromSharedSecret(
		result.SharedSecret,
		signedPrekey.PrivateKeyBytes(),
		peerEphemeral,
		false,
	)
	if err != nil {
		return fmt.Errorf("init ratchet: %w", err)
	}
	s.EstablishedAt = float64(time.Now().Unix())
	s.PeerID = append([]byte{}, peerIdentity...)
	return nil
}

// ── FromSharedSecret (testing) ─────────────────────────────────────────────

func SessionFromSharedSecret(
	sharedSecret, localDHPrivate, remoteDHPublic []byte,
	roleIsInitiator bool,
) (*Session, error) {
	ratchet, err := DoubleRatchetFromSharedSecret(
		sharedSecret,
		localDHPrivate,
		remoteDHPublic,
		roleIsInitiator,
	)
	if err != nil {
		return nil, err
	}
	return &Session{
		Config:        DefaultSessionConfig(),
		Ratchet:       ratchet,
		SessionID:     generateSessionID(),
		EstablishedAt: float64(time.Now().Unix()),
	}, nil
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────

func (s *Session) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	if s.Ratchet == nil {
		return nil, fmt.Errorf("session not established")
	}
	return s.Ratchet.RatchetEncrypt(plaintext, associatedData)
}

func (s *Session) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if s.Ratchet == nil {
		return nil, fmt.Errorf("session not established")
	}
	return s.Ratchet.RatchetDecrypt(ciphertext, associatedData)
}

// ── Helpers ────────────────────────────────────────────────────────────────

func generateSessionID() string {
	b, _ := RandomBytes(16)
	return fmt.Sprintf("%x", b)
}
