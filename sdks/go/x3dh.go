package sibna

import (
	"fmt"
)

// ── PreKeyBundle ───────────────────────────────────────────────────────────

type PreKeyBundle struct {
	IdentityKey            []byte // Ed25519 public key (32 bytes)
	X25519IdentityKey      []byte // X25519 public key (32 bytes)
	SignedPreKey           []byte // X25519 public key (32 bytes)
	SignedPreKeySignature  []byte // Ed25519 signature (64 bytes)
	OneTimePreKey          []byte // X25519 public key (32 bytes, optional)
	RegistrationID         int
	DeviceID               int
}

func (pb *PreKeyBundle) IsExpired() bool {
	return false
}

// ── X3DHResult ─────────────────────────────────────────────────────────────

type X3DHResult struct {
	SharedSecret []byte
	DHResults    [][]byte
	SessionID    string
}

// ── x3dh_initiator ────────────────────────────────────────────────────────

func X3DHInitiator(
	identityKeypair, ephemeralKeypair *X25519KeyPair,
	peerBundle *PreKeyBundle,
	ourDeviceID, peerDeviceID, transcriptHashExt []byte,
) (*X3DHResult, error) {
	if ourDeviceID == nil {
		ourDeviceID = make([]byte, 16)
	}
	if peerDeviceID == nil {
		peerDeviceID = make([]byte, 16)
	}
	if transcriptHashExt == nil {
		transcriptHashExt = make([]byte, 32)
	}

	// DH computations
	dh1, err := identityKeypair.DH(peerBundle.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("DH1: %w", err)
	}
	dh2, err := ephemeralKeypair.DH(peerBundle.X25519IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("DH2: %w", err)
	}
	dh3, err := ephemeralKeypair.DH(peerBundle.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("DH3: %w", err)
	}

	dhResults := [][]byte{dh1, dh2, dh3}
	var dh4 []byte
	if len(peerBundle.OneTimePreKey) > 0 {
		dh4, err = ephemeralKeypair.DH(peerBundle.OneTimePreKey)
		if err != nil {
			return nil, fmt.Errorf("DH4: %w", err)
		}
		dhResults = append(dhResults, dh4)
	}

	// Transcript hash
	parts := [][]byte{
		identityKeypair.PublicKeyBytes(),
		ephemeralKeypair.PublicKeyBytes(),
		peerBundle.X25519IdentityKey,
		peerBundle.SignedPreKey,
	}
	if len(peerBundle.OneTimePreKey) > 0 {
		parts = append(parts, peerBundle.OneTimePreKey)
	}
	parts = append(parts, ourDeviceID, peerDeviceID)
	transcriptHash := Blake3Hash(parts...)

	// HKDF transcript binding
	combinedTranscript := HKDF(transcriptHash, transcriptHashExt, []byte("SibnaX3DH_TranscriptBind_v3"), 32)

	// Derive shared secret
	sharedSecret := deriveSharedSecret(dh1, dh2, dh3, dh4, combinedTranscript)

	return &X3DHResult{
		SharedSecret: sharedSecret,
		DHResults:    dhResults,
	}, nil
}

// ── x3dh_responder ────────────────────────────────────────────────────────

func X3DHResponder(
	identityKeypair, signedPreKeypair *X25519KeyPair,
	onetimePreKeypair *X25519KeyPair,
	peerIdentity, peerEphemeral []byte,
	ourDeviceID, peerDeviceID, transcriptHashExt []byte,
) (*X3DHResult, error) {
	if ourDeviceID == nil {
		ourDeviceID = make([]byte, 16)
	}
	if peerDeviceID == nil {
		peerDeviceID = make([]byte, 16)
	}
	if transcriptHashExt == nil {
		transcriptHashExt = make([]byte, 32)
	}

	// DH computations (reversed perspective from initiator)
	dh1, err := signedPreKeypair.DH(peerIdentity)
	if err != nil {
		return nil, fmt.Errorf("DH1: %w", err)
	}
	dh2, err := identityKeypair.DH(peerEphemeral)
	if err != nil {
		return nil, fmt.Errorf("DH2: %w", err)
	}
	dh3, err := signedPreKeypair.DH(peerEphemeral)
	if err != nil {
		return nil, fmt.Errorf("DH3: %w", err)
	}

	dhResults := [][]byte{dh1, dh2, dh3}
	var dh4 []byte
	if onetimePreKeypair != nil {
		dh4, err = onetimePreKeypair.DH(peerEphemeral)
		if err != nil {
			return nil, fmt.Errorf("DH4: %w", err)
		}
		dhResults = append(dhResults, dh4)
	}

	// Transcript hash
	parts := [][]byte{
		peerIdentity,
		peerEphemeral,
		identityKeypair.PublicKeyBytes(),
		signedPreKeypair.PublicKeyBytes(),
	}
	if onetimePreKeypair != nil {
		parts = append(parts, onetimePreKeypair.PublicKeyBytes())
	}
	parts = append(parts, peerDeviceID, ourDeviceID)
	transcriptHash := Blake3Hash(parts...)

	// HKDF transcript binding
	combinedTranscript := HKDF(transcriptHash, transcriptHashExt, []byte("SibnaX3DH_TranscriptBind_v3"), 32)

	// Derive shared secret
	sharedSecret := deriveSharedSecret(dh1, dh2, dh3, dh4, combinedTranscript)

	return &X3DHResult{
		SharedSecret: sharedSecret,
		DHResults:    dhResults,
	}, nil
}

// ── Shared secret derivation ──────────────────────────────────────────────

func deriveSharedSecret(dh1, dh2, dh3, dh4, transcriptHash []byte) []byte {
	concatenated := make([]byte, 0, len(dh1)+len(dh2)+len(dh3))
	concatenated = append(concatenated, dh1...)
	concatenated = append(concatenated, dh2...)
	concatenated = append(concatenated, dh3...)
	if dh4 != nil {
		concatenated = append(concatenated, dh4...)
	}

	return HKDF(concatenated, transcriptHash, []byte("SibnaX3DH_v3"), KeyLength)
}
