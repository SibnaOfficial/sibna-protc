package sibna

import (
	"fmt"
	"time"
)

const (
	MessageKeySeed  byte = 0x01
	ChainKeySeed    byte = 0x02
	HeaderKeySeed   byte = 0x03

	InitialKDFSalt = "SibnaSession_v3"
	InitialKDFInfo = "SibnaRootAndChainKey_v3"
	DHRatchetInfo   = "SibnaRatchet_v3"

	MaxChainMessages   = 4000
	MaxSkippedMessages = 2000
)

// ── ChainKey ────────────────────────────────────────────────────────────────

type ChainKey struct {
	Key         []byte
	Index       int
	CreatedAt   float64
	MaxMessages int
}

func NewChainKey(key []byte) *ChainKey {
	return &ChainKey{
		Key:         append([]byte{}, key...),
		Index:       0,
		CreatedAt:   time.Now().Unix(),
		MaxMessages: MaxChainMessages,
	}
}

func (ck *ChainKey) NextMessageKey() ([]byte, *ChainKey, error) {
	if ck.Index >= ck.MaxMessages {
		return nil, nil, fmt.Errorf("chain exhausted")
	}
	mk := HMACSHA256(ck.Key, []byte{MessageKeySeed})
	nextCkBytes := HMACSHA256(ck.Key, []byte{ChainKeySeed})
	nextCk := &ChainKey{
		Key:         nextCkBytes,
		Index:       ck.Index + 1,
		CreatedAt:   ck.CreatedAt,
		MaxMessages: ck.MaxMessages,
	}
	return mk, nextCk, nil
}

func (ck *ChainKey) DeriveHeaderKey() []byte {
	return HMACSHA256(ck.Key, []byte{HeaderKeySeed})
}

func (ck *ChainKey) RemainingMessages() int {
	r := ck.MaxMessages - ck.Index
	if r < 0 {
		return 0
	}
	return r
}

// ── DoubleRatchet ──────────────────────────────────────────────────────────

type DoubleRatchet struct {
	RootKey          []byte
	SendingChain     *ChainKey
	ReceivingChain   *ChainKey
	DHLocalPrivate   []byte
	DHLocalPublic    []byte
	DHRemotePublic   []byte
	PreviousCounter  int
	MaxSkip          int
	SkippedKeys      map[string][]byte
	MessagesSent     int
	MessagesReceived int
	CreatedAt        float64
	LastActivity     float64
}

func NewDoubleRatchet(
	rootKey []byte,
	sendingChain, receivingChain *ChainKey,
	dhLocalPrivate, dhLocalPublic, dhRemotePublic []byte,
	previousCounter, maxSkip int,
) *DoubleRatchet {
	return &DoubleRatchet{
		RootKey:          append([]byte{}, rootKey...),
		SendingChain:     sendingChain,
		ReceivingChain:   receivingChain,
		DHLocalPrivate:   append([]byte{}, dhLocalPrivate...),
		DHLocalPublic:    append([]byte{}, dhLocalPublic...),
		DHRemotePublic:   append([]byte{}, dhRemotePublic...),
		PreviousCounter:  previousCounter,
		MaxSkip:          maxSkip,
		SkippedKeys:      make(map[string][]byte),
		MessagesSent:     0,
		MessagesReceived: 0,
		CreatedAt:        time.Now().Unix(),
		LastActivity:     time.Now().Unix(),
	}
}

func DoubleRatchetFromSharedSecret(
	sharedSecret, localDHPrivate, remoteDHPublic []byte,
	roleIsInitiator bool,
) (*DoubleRatchet, error) {
	if len(sharedSecret) != KeyLength {
		return nil, fmt.Errorf("shared_secret must be 32 bytes")
	}

	okm := HKDF(sharedSecret, []byte(InitialKDFSalt), []byte(InitialKDFInfo), 64)
	rootKey := okm[:32]
	chainKeyBytes := okm[32:]

	localPub, err := curve25519ScalarMult(localDHPrivate)
	if err != nil {
		return nil, fmt.Errorf("derive local public: %w", err)
	}

	var sendingChain, receivingChain *ChainKey
	if roleIsInitiator {
		sendingChain = NewChainKey(chainKeyBytes)
		receivingChain = nil
	} else {
		sendingChain = nil
		receivingChain = NewChainKey(chainKeyBytes)
	}

	return NewDoubleRatchet(
		rootKey,
		sendingChain,
		receivingChain,
		localDHPrivate,
		localPub,
		remoteDHPublic,
		0,
		MaxSkippedMessages,
	), nil
}

func curve25519ScalarMult(priv []byte) ([]byte, error) {
	kp, err := X25519KeyPairFromPrivateBytes(priv)
	if err != nil {
		return nil, err
	}
	return kp.PublicKeyBytes(), nil
}

// ── Root key KDF ───────────────────────────────────────────────────────────

func (dr *DoubleRatchet) kdfRK(dhOut []byte) ([]byte, []byte) {
	okm := HKDF(dhOut, dr.RootKey, []byte(DHRatchetInfo), 64)
	return okm[:32], okm[32:]
}

// ── DH Ratchet step ────────────────────────────────────────────────────────

func (dr *DoubleRatchet) dhRatchetStep() error {
	// Save previous receiving chain index for skipped key tracking
	if dr.ReceivingChain != nil {
		dr.PreviousCounter = dr.ReceivingChain.Index
	}

	// Receive step: use EXISTING local key
	existingLocal, err := X25519KeyPairFromPrivateBytes(dr.DHLocalPrivate)
	if err != nil {
		return fmt.Errorf("existing local key: %w", err)
	}
	dhOutRecv, err := existingLocal.DH(dr.DHRemotePublic)
	if err != nil {
		return fmt.Errorf("DH recv: %w", err)
	}
	dr.RootKey, recvChainKey := dr.kdfRK(dhOutRecv)
	dr.ReceivingChain = NewChainKey(recvChainKey)

	// Send step: generate new key pair
	newLocal, err := GenerateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("generate new local: %w", err)
	}
	dr.DHLocalPrivate = newLocal.PrivateKeyBytes()
	dr.DHLocalPublic = newLocal.PublicKeyBytes()
	dhOutSend, err := newLocal.DH(dr.DHRemotePublic)
	if err != nil {
		return fmt.Errorf("DH send: %w", err)
	}
	dr.RootKey, sendChainKey := dr.kdfRK(dhOutSend)
	dr.SendingChain = NewChainKey(sendChainKey)

	return nil
}

// ── Try skipped keys ───────────────────────────────────────────────────────

func skippedKeyID(remotePub []byte, messageNumber int) string {
	return fmt.Sprintf("%s:%d", hexEncode(remotePub), messageNumber)
}

func (dr *DoubleRatchet) trySkippedMessageKey(remoteDHPub []byte, messageNumber int) []byte {
	id := skippedKeyID(remoteDHPub, messageNumber)
	mk, ok := dr.SkippedKeys[id]
	if ok {
		delete(dr.SkippedKeys, id)
		return mk
	}
	return nil
}

func (dr *DoubleRatchet) skipMessageKeys(until int) error {
	if dr.ReceivingChain == nil {
		return nil
	}
	for dr.ReceivingChain.Index < until {
		result, err := dr.ReceivingChain.NextMessageKey()
		if err != nil {
			break
		}
		mk, nextCk := result
		id := skippedKeyID(dr.DHRemotePublic, dr.ReceivingChain.Index)
		dr.SkippedKeys[id] = mk
		if len(dr.SkippedKeys) > dr.MaxSkip {
			for k := range dr.SkippedKeys {
				delete(dr.SkippedKeys, k)
				break
			}
		}
		dr.ReceivingChain = nextCk
	}
	return nil
}

// ── Encrypt ────────────────────────────────────────────────────────────────

func (dr *DoubleRatchet) RatchetEncrypt(plaintext, associatedData []byte) ([]byte, error) {
	// If no sending chain, do a DH ratchet step to create one
	if dr.SendingChain == nil {
		if dr.DHRemotePublic == nil {
			return nil, fmt.Errorf("no remote DH public key")
		}
		newLocal, err := GenerateX25519KeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate local: %w", err)
		}
		dr.DHLocalPrivate = newLocal.PrivateKeyBytes()
		dr.DHLocalPublic = newLocal.PublicKeyBytes()
		dhOut, err := newLocal.DH(dr.DHRemotePublic)
		if err != nil {
			return nil, fmt.Errorf("DH ratchet: %w", err)
		}
		dr.RootKey, sendChainKey := dr.kdfRK(dhOut)
		dr.SendingChain = NewChainKey(sendChainKey)
	}

	// Capture message number BEFORE advancing the chain
	msgNum := dr.SendingChain.Index

	result, err := dr.SendingChain.NextMessageKey()
	if err != nil {
		return nil, fmt.Errorf("chain exhausted: %w", err)
	}
	messageKey, nextCk := result
	dr.SendingChain = nextCk

	dr.MessagesSent++
	dr.LastActivity = time.Now().Unix()

	// Build header: dh_public(32) + message_number(4 LE)
	header := make([]byte, 0, KeyLength+4)
	header = append(header, dr.DHLocalPublic...)
	header = append(header, Uint32LEToBytes(uint32(msgNum&0xFFFFFFFF))...)

	// Nonce: 8 random + 4 message_number LE
	noncePrefix, err := RandomBytes(8)
	if err != nil {
		return nil, fmt.Errorf("nonce random: %w", err)
	}
	nonce := make([]byte, 0, NonceLength)
	nonce = append(nonce, noncePrefix...)
	nonce = append(nonce, Uint32LEToBytes(uint32(msgNum&0xFFFFFFFF))...)

	// AD = caller's AD + header
	fullAD := make([]byte, 0, len(associatedData)+len(header))
	fullAD = append(fullAD, associatedData...)
	fullAD = append(fullAD, header...)

	ciphertext, err := ChaCha20Poly1305Encrypt(messageKey, plaintext, fullAD, nonce)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	wire := make([]byte, 0, len(header)+len(ciphertext))
	wire = append(wire, header...)
	wire = append(wire, ciphertext...)
	return wire, nil
}

// ── Decrypt ────────────────────────────────────────────────────────────────

func (dr *DoubleRatchet) RatchetDecrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if len(ciphertext) < KeyLength+4+NonceLength+TagLength {
		return nil, fmt.Errorf("ciphertext too short")
	}

	remoteDHPub := ciphertext[:KeyLength]
	msgNum := int(BytesToUint32LE(ciphertext[KeyLength : KeyLength+4]))
	encryptedPart := ciphertext[KeyLength+4:]

	// Try skipped key first
	mk := dr.trySkippedMessageKey(remoteDHPub, msgNum)
	if mk != nil {
		// Got skipped key, use it directly
	} else {
		// Check if from new remote key
		if !bytesEqual(remoteDHPub, dr.DHRemotePublic) {
			// Discard old receiving chain and skipped keys (forward secrecy)
			dr.ReceivingChain = nil
			dr.SkippedKeys = make(map[string][]byte)
			// Perform DH ratchet
			dr.DHRemotePublic = append([]byte{}, remoteDHPub...)
			if err := dr.dhRatchetStep(); err != nil {
				return nil, fmt.Errorf("dh ratchet: %w", err)
			}
		}

		// Skip ahead to the needed message number
		if dr.ReceivingChain == nil {
			return nil, fmt.Errorf("no receiving chain")
		}
		if err := dr.skipMessageKeys(msgNum); err != nil {
			return nil, fmt.Errorf("skip keys: %w", err)
		}
		result, err := dr.ReceivingChain.NextMessageKey()
		if err != nil {
			return nil, fmt.Errorf("receiving chain exhausted: %w", err)
		}
		mk, _ = result
	}

	// Build header for AD verification
	header := make([]byte, 0, KeyLength+4)
	header = append(header, remoteDHPub...)
	header = append(header, Uint32LEToBytes(uint32(msgNum&0xFFFFFFFF))...)
	fullAD := make([]byte, 0, len(associatedData)+len(header))
	fullAD = append(fullAD, associatedData...)
	fullAD = append(fullAD, header...)

	plaintext, err := ChaCha20Poly1305Decrypt(mk, encryptedPart, fullAD)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	dr.MessagesReceived++
	dr.LastActivity = time.Now().Unix()
	return plaintext, nil
}

func (dr *DoubleRatchet) CurrentMessageNumber() int {
	return dr.MessagesSent + dr.MessagesReceived
}

// ── Helpers ────────────────────────────────────────────────────────────────

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
