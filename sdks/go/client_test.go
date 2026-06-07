// Package sibna provides the Go SDK for the Sibna Protocol v3.0.1.
package sibna

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	if len(identity.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(identity.PublicKey), ed25519.PublicKeySize)
	}
	if len(identity.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("private key length = %d, want %d", len(identity.PrivateKey), ed25519.PrivateKeySize)
	}
}

func TestIdentityFromSeed(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	identity, err := IdentityFromSeed(seed)
	if err != nil {
		t.Fatalf("IdentityFromSeed failed: %v", err)
	}
	if len(identity.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key length = %d, want %d", len(identity.PublicKey), ed25519.PublicKeySize)
	}
}

func TestIdentityFromSeedInvalidLength(t *testing.T) {
	_, err := IdentityFromSeed(make([]byte, 16))
	if err == nil {
		t.Error("expected error for invalid seed length")
	}
}

func TestPublicKeyHex(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	hexStr := identity.PublicKeyHex()
	if len(hexStr) != 64 {
		t.Errorf("hex length = %d, want 64", len(hexStr))
	}
	_, err = hex.DecodeString(hexStr)
	if err != nil {
		t.Errorf("invalid hex string: %v", err)
	}
}

func TestSign(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	data := []byte("test message")
	sig := identity.Sign(data)
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
}

func TestSignHex(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	data := []byte("test message")
	sigHex := identity.SignHex(data)
	if len(sigHex) != 128 {
		t.Errorf("hex signature length = %d, want 128", len(sigHex))
	}
}

func TestPadUnpadRoundtrip(t *testing.T) {
	data := []byte("Hello, World!")
	padded, err := PadPayload(data)
	if err != nil {
		t.Fatalf("PadPayload failed: %v", err)
	}
	if len(padded)%PaddingBlock != 0 {
		t.Errorf("padded length %d is not a multiple of %d", len(padded), PaddingBlock)
	}
	unpadded, err := UnpadPayload(padded)
	if err != nil {
		t.Fatalf("UnpadPayload failed: %v", err)
	}
	if !bytes.Equal(unpadded, data) {
		t.Errorf("unpadded = %v, want %v", unpadded, data)
	}
}

func TestPadEmpty(t *testing.T) {
	padded, err := PadPayload([]byte{})
	if err != nil {
		t.Fatalf("PadPayload failed: %v", err)
	}
	if len(padded)%PaddingBlock != 0 {
		t.Errorf("padded length %d is not a multiple of %d", len(padded), PaddingBlock)
	}
	unpadded, err := UnpadPayload(padded)
	if err != nil {
		t.Fatalf("UnpadPayload failed: %v", err)
	}
	if len(unpadded) != 0 {
		t.Errorf("unpadded length = %d, want 0", len(unpadded))
	}
}

func TestUnpadEmpty(t *testing.T) {
	_, err := UnpadPayload([]byte{})
	if err == nil {
		t.Error("expected error for empty payload")
	}
}

func TestMakeSignedEnvelope(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	envelope, err := MakeSignedEnvelope(identity, "aabbccdd", "deadbeef", false)
	if err != nil {
		t.Fatalf("MakeSignedEnvelope failed: %v", err)
	}
	if envelope.RecipientID != "aabbccdd" {
		t.Errorf("recipient_id = %s, want aabbccdd", envelope.RecipientID)
	}
	if envelope.PayloadHex != "deadbeef" {
		t.Errorf("payload_hex = %s, want deadbeef", envelope.PayloadHex)
	}
	if envelope.SenderID != identity.PublicKeyHex() {
		t.Errorf("sender_id mismatch")
	}
}

func TestVersion(t *testing.T) {
	if Version != "3.0.1" {
		t.Errorf("Version = %s, want 3.0.1", Version)
	}
}

// FIX: Phase 3.1 — proves the Go padder now uses the same wire format
// as the Rust core. The fixture is a hand-built byte string with the
// canonical layout:
//
//	[ 0x03 | 0xAA 0xBB 0xCC | "hello" | (1024 - 12) zero bytes | 0x10 0x00 ]
//
// Where 0x10 0x00 is the little-endian 16-bit pad_len (16 = 0x10).
// UnpadPayload must recover "hello".
func TestUnpadPayload_WireFormatMatchesRust(t *testing.T) {
	const want = "hello"
	const prefixLen = 3
	const padLen = 16

	// Build the canonical Rust wire format.
	buf := make([]byte, 0, PaddingBlock)
	buf = append(buf, byte(prefixLen))
	buf = append(buf, 0xAA, 0xBB, 0xCC)
	buf = append(buf, []byte(want)...)
	buf = append(buf, make([]byte, padLen)...)
	var le [2]byte
	binary.LittleEndian.PutUint16(le[:], uint16(padLen))
	buf = append(buf, le[0], le[1])

	if got := len(buf); got != PaddingBlock {
		t.Fatalf("fixture length = %d, want %d (one block)", got, PaddingBlock)
	}

	got, err := UnpadPayload(buf)
	if err != nil {
		t.Fatalf("UnpadPayload failed: %v", err)
	}
	if string(got) != want {
		t.Errorf("unpadded = %q, want %q", got, want)
	}
}

// FIX: Phase 3.1 — SIBNA-2026-018 parity: 64 trials on a fixed
// plaintext must hit at least 2 distinct on-wire sizes. With
// extra_blocks ∈ 0..7 there are 8 possible sizes (1..8 blocks of
// 1024 bytes each), so the test has effectively zero probability of
// false failure.
func TestPaddingSizeDistribution_NotConstant(t *testing.T) {
	msg := []byte("constant-size message")
	sizes := make(map[int]struct{}, 8)
	for i := 0; i < 64; i++ {
		p, err := PadPayload(msg)
		if err != nil {
			t.Fatalf("PadPayload failed on iteration %d: %v", i, err)
		}
		if len(p)%PaddingBlock != 0 {
			t.Fatalf("padded length %d is not a multiple of %d", len(p), PaddingBlock)
		}
		sizes[len(p)] = struct{}{}
	}
	if len(sizes) < 2 {
		t.Errorf("expected at least 2 distinct padded sizes across 64 trials, got %d (sizes: %v)",
			len(sizes), sizes)
	}
	// Sanity: sizes are bounded by MAX_EXTRA_BLOCKS
	for s := range sizes {
		maxAllowed := PaddingBlock * (1 + PaddingMaxExtraBlocks)
		if s > maxAllowed {
			t.Errorf("padded size %d exceeds max allowed %d", s, maxAllowed)
		}
	}
}

// FIX: Phase 3.1 — prefix noise must be in the [1, 8] range on every
// call (regression test for the format).
func TestPadPayload_PrefixLenInRange(t *testing.T) {
	for i := 0; i < 32; i++ {
		p, err := PadPayload([]byte("ping"))
		if err != nil {
			t.Fatalf("PadPayload: %v", err)
		}
		pl := int(p[0])
		if pl < 1 || pl > 8 {
			t.Errorf("prefix_len = %d, want 1..=8", pl)
		}
	}
}
