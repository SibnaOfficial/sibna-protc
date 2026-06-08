package sibna

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

const (
	KeyLength    = 32
	NonceLength  = 12
	TagLength    = 16
	MinCompatibleVersion = 9
)

// Low-order X25519 points to reject
var lowOrderPoints = map[string]bool{
	"0000000000000000000000000000000000000000000000000000000000000000": true,
	"0100000000000000000000000000000000000000000000000000000000000000": true,
	"e0eb8a3114509de3500459450f1f56e39cc03814c13efc4b3fb0839e41f80f17": true,
	"c3ada28304f53665966e72ca07de5614a4c00ceb534fbb99767401c0295c590f": true,
	"504c00c7ff6616830ca1da120b0bba22a2f44157298b3cd579e95138d96f8c17": true,
	"d8527d1f006f51e8b6542d6ae27e09eb88aec0c71e9c75cfd2c17d4d2b13d00e": true,
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7e": true,
	"f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": true,
}

// ── Ed25519KeyPair ──────────────────────────────────────────────────────────

type Ed25519KeyPair struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewEd25519KeyPair() (*Ed25519KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	return &Ed25519KeyPair{privateKey: priv, publicKey: pub}, nil
}

func Ed25519KeyPairFromSeed(seed []byte) (*Ed25519KeyPair, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("seed must be 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519KeyPair{privateKey: priv, publicKey: pub}, nil
}

func (kp *Ed25519KeyPair) PublicKeyBytes() []byte {
	return []byte(kp.publicKey)
}

func (kp *Ed25519KeyPair) PrivateKeyBytes() []byte {
	return []byte(kp.privateKey)
}

func (kp *Ed25519KeyPair) Seed() []byte {
	return kp.privateKey.Seed()
}

func (kp *Ed25519KeyPair) Sign(data []byte) []byte {
	return ed25519.Sign(kp.privateKey, data)
}

func (kp *Ed25519KeyPair) Verify(data, signature []byte) bool {
	return ed25519.Verify(kp.publicKey, data, signature)
}

func Ed25519VerifyWithKey(publicKey, data, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), data, signature)
}

// ── X25519KeyPair ──────────────────────────────────────────────────────────

type X25519KeyPair struct {
	privateKey []byte
	publicKey  []byte
}

func NewX25519KeyPair() (*X25519KeyPair, error) {
	priv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 basepoint mult: %w", err)
	}
	return &X25519KeyPair{privateKey: priv, publicKey: pub}, nil
}

func X25519KeyPairFromSeed(seed []byte) (*X25519KeyPair, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("seed must be 32 bytes")
	}
	pub, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 basepoint mult: %w", err)
	}
	return &X25519KeyPair{privateKey: append([]byte{}, seed...), publicKey: pub}, nil
}

func X25519KeyPairFromPrivateBytes(priv []byte) (*X25519KeyPair, error) {
	if len(priv) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 basepoint mult: %w", err)
	}
	return &X25519KeyPair{privateKey: append([]byte{}, priv...), publicKey: pub}, nil
}

func (kp *X25519KeyPair) PublicKeyBytes() []byte {
	return append([]byte{}, kp.publicKey...)
}

func (kp *X25519KeyPair) PrivateKeyBytes() []byte {
	return append([]byte{}, kp.privateKey...)
}

func (kp *X25519KeyPair) Seed() []byte {
	return append([]byte{}, kp.privateKey...)
}

func (kp *X25519KeyPair) DH(remotePublic []byte) ([]byte, error) {
	if len(remotePublic) != 32 {
		return nil, fmt.Errorf("remote public key must be 32 bytes")
	}
	pubHex := hexEncode(remotePublic)
	if lowOrderPoints[pubHex] {
		return nil, fmt.Errorf("rejecting low-order X25519 public key")
	}
	shared, err := curve25519.X25519(kp.privateKey, remotePublic)
	if err != nil {
		return nil, fmt.Errorf("x25519 DH: %w", err)
	}
	return shared, nil
}

func GenerateX25519KeyPair() (*X25519KeyPair, error) {
	return NewX25519KeyPair()
}

// ── HKDF-SHA256 ────────────────────────────────────────────────────────────

func HKDFExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func HKDFExpand(prk, info []byte, length int) []byte {
	n := (length + 31) / 32
	okm := make([]byte, 0, n*32)
	prev := make([]byte, 0)
	for i := 1; i <= n; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length]
}

func HKDF(ikm, salt, info []byte, length int) []byte {
	if salt == nil {
		salt = make([]byte, KeyLength)
	}
	prk := HKDFExtract(salt, ikm)
	return HKDFExpand(prk, info, length)
}

// ── HMAC-SHA256 ────────────────────────────────────────────────────────────

func HMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// ── SHA-256 / SHA-512 ──────────────────────────────────────────────────────

func SHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func SHA512(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// ── Blake3 (SHA-256 fallback) ──────────────────────────────────────────────

func Blake3Hash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// ── ChaCha20-Poly1305 ─────────────────────────────────────────────────────

func ChaCha20Poly1305Encrypt(key, plaintext, associatedData, nonce []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, fmt.Errorf("key must be %d bytes", KeyLength)
	}
	if nonce == nil {
		nonce = make([]byte, NonceLength)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("random nonce: %w", err)
		}
	}
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305: %w", err)
	}
	ct := cipher.Seal(nil, nonce, plaintext, associatedData)
	return append(nonce, ct...), nil
}

func ChaCha20Poly1305Decrypt(key, data, associatedData []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, fmt.Errorf("key must be %d bytes", KeyLength)
	}
	if len(data) < NonceLength+TagLength {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := data[:NonceLength]
	ct := data[NonceLength:]
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305: %w", err)
	}
	return cipher.Open(nil, nonce, ct, associatedData)
}

// ── DeriveIdentityKeys ─────────────────────────────────────────────────────

func DeriveIdentityKeys(masterSeed []byte) (*Ed25519KeyPair, *X25519KeyPair, error) {
	edSeed := HKDF(masterSeed, nil, []byte("SibnaIdentityKey_Ed25519_v1"), 32)
	xSeed := HKDF(masterSeed, nil, []byte("SibnaIdentityKey_X25519_v1"), 32)
	edKp, err := Ed25519KeyPairFromSeed(edSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("derive ed25519: %w", err)
	}
	xKp, err := X25519KeyPairFromSeed(xSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("derive x25519: %w", err)
	}
	return edKp, xKp, nil
}

// ── RandomBytes ────────────────────────────────────────────────────────────

func RandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("random bytes: %w", err)
	}
	return b, nil
}

// ── Helpers ────────────────────────────────────────────────────────────────

func hexEncode(data []byte) string {
	const hexTable = "0123456789abcdef"
	var sb strings.Builder
	for _, b := range data {
		sb.WriteByte(hexTable[b>>4])
		sb.WriteByte(hexTable[b&0x0f])
	}
	return sb.String()
}

// BytesToUint32LE reads a little-endian uint32.
func BytesToUint32LE(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

// Uint32LEToBytes writes a little-endian uint32.
func Uint32LEToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
