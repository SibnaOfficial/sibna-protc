package sibna

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	MaxGroupSize          = 256
	MaxGroupMessageSize   = 10 * 1024 * 1024
	DefaultKeyExpirationSecs = 7 * 86400
)

// ── SenderKey ──────────────────────────────────────────────────────────────

type SenderKey struct {
	ChainKey       []byte
	MessageNumber  int
	KeyID          int
	CreatedAt      float64
	Expiration     float64
}

func SenderKeyGenerate(keyID int) *SenderKey {
	chainKey, _ := RandomBytes(KeyLength)
	return &SenderKey{
		ChainKey:      chainKey,
		MessageNumber: 0,
		KeyID:         keyID,
		CreatedAt:     float64(time.Now().Unix()),
		Expiration:    float64(time.Now().Unix() + DefaultKeyExpirationSecs),
	}
}

func (sk *SenderKey) NextMessageKey() ([]byte, error) {
	if sk.Expiration > 0 && time.Now().Unix() > int64(sk.Expiration) {
		return nil, fmt.Errorf("sender key expired")
	}

	// message_key = HKDF(chain_key, info="SibnaGroupMessageKey_v3")
	messageKey := HKDF(sk.ChainKey, nil, []byte("SibnaGroupMessageKey_v3"), KeyLength)

	// next_chain = HKDF(chain_key, info="SibnaGroupChainKey_v3")
	nextChain := HKDF(sk.ChainKey, nil, []byte("SibnaGroupChainKey_v3"), KeyLength)

	sk.ChainKey = nextChain
	sk.MessageNumber++
	return messageKey, nil
}

func (sk *SenderKey) IsExpired() bool {
	if sk.Expiration <= 0 {
		return false
	}
	return time.Now().Unix() > int64(sk.Expiration)
}

func (sk *SenderKey) AgeSecs() float64 {
	return float64(time.Now().Unix() - int64(sk.CreatedAt))
}

func (sk *SenderKey) NeedsRotation() bool {
	return sk.IsExpired() || sk.AgeSecs() > 86400
}

// ── SenderKeyMessage ──────────────────────────────────────────────────────

type SenderKeyMessage struct {
	GroupID          []byte
	SenderPublicKey  []byte
	EncryptedKey     []byte
	Signature        []byte
	KeyID            int
	Timestamp        float64
}

func (msg *SenderKeyMessage) SignableBytes() []byte {
	data := make([]byte, 0, len(msg.GroupID)+4+len(msg.EncryptedKey)+8)
	data = append(data, msg.GroupID...)
	keyIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyIDBytes, uint32(msg.KeyID))
	data = append(data, keyIDBytes...)
	data = append(data, msg.EncryptedKey...)
	tsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBytes, uint64(int64(msg.Timestamp)))
	data = append(data, tsBytes...)
	return data
}

func (msg *SenderKeyMessage) Sign(identity *Ed25519KeyPair) []byte {
	msg.Signature = identity.Sign(msg.SignableBytes())
	return msg.Signature
}

func (msg *SenderKeyMessage) VerifySignature() bool {
	if len(msg.Signature) != 64 {
		return false
	}
	return Ed25519VerifyWithKey(msg.SenderPublicKey, msg.SignableBytes(), msg.Signature)
}

func (msg *SenderKeyMessage) ToBytes() []byte {
	groupIDLen := len(msg.GroupID)
	senderKeyLen := len(msg.SenderPublicKey)
	encKeyLen := len(msg.EncryptedKey)
	sigLen := len(msg.Signature)

	data := make([]byte, 0, groupIDLen+senderKeyLen+4+8+4+encKeyLen+4+sigLen)
	data = append(data, msg.GroupID...)
	data = append(data, msg.SenderPublicKey...)
	keyIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyIDBytes, uint32(msg.KeyID))
	data = append(data, keyIDBytes...)
	tsBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBytes, uint64(int64(msg.Timestamp)))
	data = append(data, tsBytes...)
	encKeyLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(encKeyLenBytes, uint32(encKeyLen))
	data = append(data, encKeyLenBytes...)
	data = append(data, msg.EncryptedKey...)
	sigLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sigLenBytes, uint32(sigLen))
	data = append(data, sigLenBytes...)
	data = append(data, msg.Signature...)
	return data
}

func SenderKeyMessageFromBytes(data []byte) (*SenderKeyMessage, error) {
	if len(data) < 32+32+4+8+4+4 {
		return nil, fmt.Errorf("data too short")
	}
	offset := 0
	groupID := append([]byte{}, data[offset:offset+32]...)
	offset += 32
	senderPublicKey := append([]byte{}, data[offset:offset+32]...)
	offset += 32
	keyID := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	timestamp := float64(int64(binary.LittleEndian.Uint64(data[offset : offset+8])))
	offset += 8
	encKeyLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	encryptedKey := append([]byte{}, data[offset:offset+encKeyLen]...)
	offset += encKeyLen
	sigLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	signature := append([]byte{}, data[offset:offset+sigLen]...)

	return &SenderKeyMessage{
		GroupID:         groupID,
		SenderPublicKey: senderPublicKey,
		EncryptedKey:    encryptedKey,
		Signature:       signature,
		KeyID:           keyID,
		Timestamp:       timestamp,
	}, nil
}

// ── GroupSession ──────────────────────────────────────────────────────────

type GroupSession struct {
	GroupID            []byte
	SenderKey          *SenderKey
	SenderKeys         map[string]*SenderKey // public_key_hex -> SenderKey
	KeyRotationCount   int
}

func GroupSessionCreate(groupID []byte) *GroupSession {
	if groupID == nil {
		groupID, _ = RandomBytes(32)
	}
	s := &GroupSession{
		GroupID:  append([]byte{}, groupID...),
		SenderKeys: make(map[string]*SenderKey),
	}
	s.SenderKey = SenderKeyGenerate(0)
	return s
}

func (gs *GroupSession) Encrypt(plaintext []byte) ([]byte, error) {
	if gs.SenderKey == nil {
		return nil, fmt.Errorf("no sender key — join or create group first")
	}

	mk, err := gs.SenderKey.NextMessageKey()
	if err != nil {
		return nil, fmt.Errorf("sender key chain exhausted: %w", err)
	}

	nonce, err := RandomBytes(NonceLength)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	msgNumber := gs.SenderKey.MessageNumber - 1

	// AD: group_id || key_id || message_number
	ad := make([]byte, 0, 32+4+4)
	ad = append(ad, gs.GroupID...)
	keyIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyIDBytes, uint32(gs.SenderKey.KeyID))
	ad = append(ad, keyIDBytes...)
	msgNumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgNumBytes, uint32(msgNumber))
	ad = append(ad, msgNumBytes...)

	ciphertext, err := ChaCha20Poly1305Encrypt(mk, plaintext, ad, nonce)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// Wire format: group_id(32) || key_id(4) || message_number(4) || ciphertext+tag
	wire := make([]byte, 0, 32+4+4+len(ciphertext))
	wire = append(wire, gs.GroupID...)
	wire = append(wire, keyIDBytes...)
	wire = append(wire, msgNumBytes...)
	wire = append(wire, ciphertext...)
	return wire, nil
}

func (gs *GroupSession) GetKeyDistributionMessages(
	identity *Ed25519KeyPair,
	memberPublicKeys [][]byte,
) ([]*SenderKeyMessage, error) {
	if gs.SenderKey == nil {
		return nil, fmt.Errorf("no sender key")
	}

	var messages []*SenderKeyMessage
	for _, memberPub := range memberPublicKeys {
		ephemeral, err := GenerateX25519KeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral: %w", err)
		}
		shared, err := ephemeral.DH(memberPub)
		if err != nil {
			return nil, fmt.Errorf("DH: %w", err)
		}
		encKey := HKDF(shared, nil, []byte("SibnaGroupKeyDistribute_v3"), KeyLength)
		encrypted, err := ChaCha20Poly1305Encrypt(encKey, gs.SenderKey.ChainKey, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("encrypt key: %w", err)
		}

		msg := &SenderKeyMessage{
			GroupID:         gs.GroupID,
			SenderPublicKey: identity.PublicKeyBytes(),
			EncryptedKey:    encrypted,
			Signature:       nil,
			KeyID:           gs.SenderKey.KeyID,
			Timestamp:       float64(time.Now().Unix()),
		}
		msg.Sign(identity)
		messages = append(messages, msg)
	}

	return messages, nil
}

func (gs *GroupSession) ProcessKeyDistribution(
	msg *SenderKeyMessage,
	ourX25519 *X25519KeyPair,
	ephemeralPublic []byte,
) error {
	if !msg.VerifySignature() {
		return fmt.Errorf("invalid signature on key distribution message")
	}

	shared, err := ourX25519.DH(ephemeralPublic)
	if err != nil {
		return fmt.Errorf("DH: %w", err)
	}
	encKey := HKDF(shared, nil, []byte("SibnaGroupKeyDistribute_v3"), KeyLength)
	chainKey, err := ChaCha20Poly1305Decrypt(encKey, msg.EncryptedKey, nil)
	if err != nil {
		return fmt.Errorf("decrypt key: %w", err)
	}

	key := fmt.Sprintf("%x", msg.SenderPublicKey)
	gs.SenderKeys[key] = &SenderKey{
		ChainKey: chainKey,
		KeyID:    msg.KeyID,
	}
	return nil
}

func (gs *GroupSession) Decrypt(ciphertext []byte, senderPublicKey []byte) ([]byte, error) {
	if len(ciphertext) < 32+4+4+NonceLength+16 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	offset := 0
	groupID := ciphertext[offset : offset+32]
	offset += 32
	keyID := int(binary.LittleEndian.Uint32(ciphertext[offset : offset+4]))
	offset += 4
	msgNumber := int(binary.LittleEndian.Uint32(ciphertext[offset : offset+4]))
	offset += 4
	encryptedPart := ciphertext[offset:]

	if !bytesEqual(groupID, gs.GroupID) {
		return nil, fmt.Errorf("group ID mismatch")
	}

	key := fmt.Sprintf("%x", senderPublicKey)
	senderKey, ok := gs.SenderKeys[key]
	if !ok {
		return nil, fmt.Errorf("no sender key for this sender")
	}

	if senderKey.KeyID != keyID {
		return nil, fmt.Errorf("key ID mismatch: expected %d, got %d", senderKey.KeyID, keyID)
	}

	// Skip ahead if needed
	for senderKey.MessageNumber < msgNumber {
		_, err := senderKey.NextMessageKey()
		if err != nil {
			return nil, fmt.Errorf("sender key chain exhausted")
		}
	}

	mk, err := senderKey.NextMessageKey()
	if err != nil {
		return nil, fmt.Errorf("sender key chain exhausted")
	}

	nonce := encryptedPart[:NonceLength]
	actualCT := encryptedPart[NonceLength:]

	// AD: group_id || key_id || message_number
	ad := make([]byte, 0, 32+4+4)
	ad = append(ad, gs.GroupID...)
	keyIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(keyIDBytes, uint32(keyID))
	ad = append(ad, keyIDBytes...)
	msgNumBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(msgNumBytes, uint32(msgNumber))
	ad = append(ad, msgNumBytes...)

	// ChaCha20Poly1305Decrypt expects data = nonce || ciphertext || tag
	data := append(nonce, actualCT...)
	return ChaCha20Poly1305Decrypt(mk, data, ad)
}

func (gs *GroupSession) RotateSenderKey() *SenderKey {
	gs.KeyRotationCount++
	gs.SenderKey = SenderKeyGenerate(gs.KeyRotationCount)
	return gs.SenderKey
}
