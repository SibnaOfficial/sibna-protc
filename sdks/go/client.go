// Package sibna provides the Go SDK for the Sibna Protocol v3.0.1.
//
// Full HTTP + WebSocket client SDK with:
//   - Ed25519 identity keys (using crypto/ed25519)
//   - JWT Auth: challenge-response flow
//   - PreKey management (upload / fetch)
//   - Sealed + Signed envelope messaging
//   - Message padding (metadata resistance)
//   - WebSocket real-time relay
//   - Offline inbox polling
package sibna

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	Version = "3.0.1"
	// PaddingBlock is the default block size used by PadPayload.
	// Matches PaddingMode::Standard in the Rust core.
	PaddingBlock = 1024

	// PaddingMaxExtraBlocks is the maximum number of *additional* full
	// blocks of random padding that may be appended on top of the minimum
	// needed to reach the next block boundary. With cap = 7, the on-wire
	// size of a given plaintext can occupy any of 8 distinct padded sizes.
	//
	// FIX: Phase 3.1 — SIBNA-2026-018 parity with the Rust core. The
	// previous Go implementation always produced a deterministic block
	// size, defeating the metadata-resistance property of the format.
	PaddingMaxExtraBlocks = 7

	// PaddingMaxBytes is the maximum value that can be encoded in the
	// 2-byte LE trailing length field.
	PaddingMaxBytes = 65535

	// PaddingMinOverhead is the minimum non-plaintext bytes in the padded
	// format: 1 (prefix_len) + 1 (min prefix noise) + 2 (trailing LE
	// pad_len).
	PaddingMinOverhead = 4
)

// Errors
var (
	ErrAuthFailed    = errors.New("authentication failed")
	ErrNetworkError  = errors.New("network error")
	ErrCryptoError   = errors.New("cryptographic error")
	ErrRateLimited   = errors.New("rate limited (HTTP 429)")
	ErrNotAuthorized = errors.New("not authorized (HTTP 401)")
	ErrInvalidArg    = errors.New("invalid argument")
)

// ── Identity ─────────────────────────────────────────────────────────────────

// Identity represents an Ed25519 keypair
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// GenerateIdentity creates a new Ed25519 identity keypair
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCryptoError, err)
	}
	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

// IdentityFromSeed creates an identity from a 32-byte seed
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("%w: seed must be 32 bytes, got %d", ErrInvalidArg, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Identity{PublicKey: priv.Public().(ed25519.PublicKey), PrivateKey: priv}, nil
}

// PublicKeyHex returns the 64-character hex encoded public key
func (id *Identity) PublicKeyHex() string {
	return hex.EncodeToString(id.PublicKey)
}

// Sign signs data with the private key
func (id *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(id.PrivateKey, data)
}

// SignHex signs data and returns hex-encoded signature
func (id *Identity) SignHex(data []byte) string {
	return hex.EncodeToString(id.Sign(data))
}

// ── Message Padding ──────────────────────────────────────────────────────────
//
// FIX: Phase 3.1 — the on-wire padding format used to be a 3-byte
// front-loaded header `[indicator(1)|pad_len(2,BE)|plaintext|padding]`
// and always produced a single deterministic block size. The Rust core
// uses a different shape that is also wire-incompatible with itself
// across SDKs (Go, Python, JavaScript all used their own ad-hoc
// variants), so a Go client could not interoperate with the Rust
// relay or any other SDK.
//
// The new format matches the Rust core's `core/src/crypto/padding.rs`
// `pad_message` exactly:
//
//	[ 1-byte prefix_len (1..=8) | prefix_noise (prefix_len bytes)
//	  | plaintext | random padding (pad_len bytes)
//	  | 2-byte LE padding_len ]
//
// Properties (mirroring SIBNA-2026-018 in the Rust core):
//   - prefix_len and prefix_noise randomise the visible length within
//     the same block, defeating range inference.
//   - extra_blocks is drawn uniformly from 0..=PaddingMaxExtraBlocks
//     so two messages of identical plaintext length do not necessarily
//     produce the same on-wire size.

// PadPayload adds metadata-resistance padding to data.
//
// The result is a multiple of PaddingBlock bytes. An empty plaintext
// is allowed (it is the carrier for cover / dummy traffic in the
// privacy modes).
func PadPayload(data []byte) ([]byte, error) {
	// 1. Random prefix_len in [1, 8].
	var prefixLenByte [1]byte
	if _, err := rand.Read(prefixLenByte[:]); err != nil {
		return nil, fmt.Errorf("%w: rand.Read failed: %v", ErrCryptoError, err)
	}
	prefixLen := int(prefixLenByte[0]%8) + 1

	prefixNoise := make([]byte, prefixLen)
	if _, err := rand.Read(prefixNoise); err != nil {
		return nil, fmt.Errorf("%w: rand.Read failed: %v", ErrCryptoError, err)
	}

	// 2. Compute the minimum trailing bytes to reach the next block boundary.
	minTotal := 1 + prefixLen + len(data) + 2
	remainder := minTotal % PaddingBlock
	minPadLen := PaddingBlock - remainder
	if remainder == 0 {
		minPadLen = 0
	}

	// 3. SIBNA-2026-018: randomise the per-block suffix length.
	//    extra_blocks ∈ [0, min(MAX_EXTRA_BLOCKS, max_blocks_for_budget)]
	maxBlocksForBudget := (PaddingMaxBytes - minPadLen) / PaddingBlock
	if maxBlocksForBudget < 0 {
		maxBlocksForBudget = 0
	}
	capBlocks := maxBlocksForBudget
	if capBlocks > PaddingMaxExtraBlocks {
		capBlocks = PaddingMaxExtraBlocks
	}

	var extraByte [1]byte
	if _, err := rand.Read(extraByte[:]); err != nil {
		return nil, fmt.Errorf("%w: rand.Read failed: %v", ErrCryptoError, err)
	}
	extraBlocks := int(extraByte[0]) % (capBlocks + 1)
	padLen := minPadLen + extraBlocks*PaddingBlock

	if padLen > PaddingMaxBytes {
		return nil, fmt.Errorf("%w: computed pad_len %d exceeds maximum %d", ErrCryptoError, padLen, PaddingMaxBytes)
	}

	// 4. Build the output: [prefix_len | prefix_noise | data | padding | pad_len(2 LE)].
	total := minTotal + padLen
	out := make([]byte, total)
	pos := 0
	out[pos] = byte(prefixLen)
	pos++
	copy(out[pos:], prefixNoise)
	pos += prefixLen
	copy(out[pos:], data)
	pos += len(data)
	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("%w: rand.Read failed: %v", ErrCryptoError, err)
		}
		copy(out[pos:], padding)
		pos += padLen
	}
	// Trailing 2-byte little-endian pad_len.
	binary.LittleEndian.PutUint16(out[pos:], uint16(padLen))
	pos += 2

	if pos != total {
		// Defensive: this should be unreachable.
		return nil, fmt.Errorf("%w: internal padding size mismatch (pos=%d, total=%d)", ErrCryptoError, pos, total)
	}
	return out, nil
}

// UnpadPayload removes metadata-resistance padding from padded.
//
// Returns the original plaintext. Any malformed input produces an
// error rather than a silently-wrong result.
func UnpadPayload(padded []byte) ([]byte, error) {
	if len(padded) < PaddingMinOverhead {
		return nil, errors.New("padded payload too short")
	}

	prefixLen := int(padded[0])
	if prefixLen < 1 || prefixLen > 8 {
		return nil, fmt.Errorf("invalid prefix_len: %d", prefixLen)
	}
	if 1+prefixLen+2 > len(padded) {
		return nil, errors.New("padded payload truncated before plaintext")
	}

	// Trailing 2-byte little-endian pad_len.
	lo := uint16(padded[len(padded)-2])
	hi := uint16(padded[len(padded)-1])
	padLen := int(lo | (hi << 8))

	totalOverhead := 1 + prefixLen + padLen + 2
	if totalOverhead > len(padded) {
		return nil, errors.New("invalid padding length")
	}

	plaintextLen := len(padded) - totalOverhead
	start := 1 + prefixLen
	return padded[start : start+plaintextLen], nil
}

// ── Signed Envelope ──────────────────────────────────────────────────────────

// SignedEnvelope represents an end-to-end authenticated message
type SignedEnvelope struct {
	RecipientID  string `json:"recipient_id"`
	PayloadHex   string `json:"payload_hex"`
	SenderID     string `json:"sender_id"`
	Timestamp    int64  `json:"timestamp"`
	MessageID    string `json:"message_id"`
	SignatureHex string `json:"signature_hex"`
	Compressed   bool   `json:"compressed"`
}

// MakeSignedEnvelope creates a signed envelope with Ed25519 signature
func MakeSignedEnvelope(identity *Identity, recipientID, payloadHex string, compress bool) (*SignedEnvelope, error) {
	messageID := generateUUID()
	timestamp := time.Now().Unix()

	// Build signing payload: SHA-512(recipient_id || payload_hex || timestamp || message_id)
	h := sha512.New()
	h.Write([]byte(recipientID))
	h.Write([]byte(payloadHex))
	binary.Write(h, binary.LittleEndian, timestamp)
	h.Write([]byte(messageID))
	signingHash := h.Sum(nil)

	signature := identity.Sign(signingHash)

	return &SignedEnvelope{
		RecipientID:  recipientID,
		PayloadHex:   payloadHex,
		SenderID:     identity.PublicKeyHex(),
		Timestamp:    timestamp,
		MessageID:    messageID,
		SignatureHex: hex.EncodeToString(signature),
		Compressed:   compress,
	}, nil
}

// VerifySignedEnvelope verifies a received envelope's signature
func VerifySignedEnvelope(envelope *SignedEnvelope) bool {
	keyBytes, err := hex.DecodeString(envelope.SenderID)
	if err != nil || len(keyBytes) != 32 {
		return false
	}
	sigBytes, err := hex.DecodeString(envelope.SignatureHex)
	if err != nil || len(sigBytes) != 64 {
		return false
	}

	h := sha512.New()
	h.Write([]byte(envelope.RecipientID))
	h.Write([]byte(envelope.PayloadHex))
	binary.Write(h, binary.LittleEndian, envelope.Timestamp)
	h.Write([]byte(envelope.MessageID))
	signingHash := h.Sum(nil)

	return ed25519.Verify(keyBytes, signingHash, sigBytes)
}

// ── HTTP Client ──────────────────────────────────────────────────────────────

// Client is the Sibna HTTP client
type Client struct {
	serverURL string
	identity  *Identity
	jwtToken  string
	http      *http.Client
	mu        sync.RWMutex
}

// NewClient creates a new Sibna SDK client.
//
// pinnedCertPEM (optional): path to a PEM file containing the server's
// expected TLS certificate or its CA. When set, the client rejects any
// TLS certificate not matching this file — even if signed by a trusted CA.
// Leave empty to use the system trust store (acceptable for development).
func NewClient(serverURL string, pinnedCertPEM ...string) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if len(pinnedCertPEM) > 0 && pinnedCertPEM[0] != "" {
		// FIX: TLS certificate pinning — load the pinned PEM and build a custom
		// root CA pool that trusts ONLY that certificate.
		pemData, err := os.ReadFile(pinnedCertPEM[0])
		if err != nil {
			return nil, fmt.Errorf("pinnedCertPEM: cannot read %q: %w", pinnedCertPEM[0], err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("pinnedCertPEM: %q contains no valid PEM certificates", pinnedCertPEM[0])
		}
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13, // Enforce TLS 1.3 minimum
		}
	} else if strings.HasPrefix(serverURL, "https://") {
		log.Println("[sibna-sdk] WARNING: HTTPS server without certificate pinning. " +
			"Pass a pinnedCertPEM path for production deployments.")
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return &Client{
		serverURL: serverURL,
		http:      &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

// SetIdentity binds an Identity to this client instance
func (c *Client) SetIdentity(id *Identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.identity = id
}

// IdentityHex returns the hex-encoded public key
func (c *Client) IdentityHex() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.identity == nil {
		return ""
	}
	return c.identity.PublicKeyHex()
}

// JWTToken returns the current JWT token
func (c *Client) JWTToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.jwtToken
}

// Authenticate performs the full Ed25519 challenge-response flow to get a JWT
func (c *Client) Authenticate() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.identity == nil {
		return "", fmt.Errorf("%w: no identity loaded, call SetIdentity first", ErrAuthFailed)
	}

	// Step 1: Request challenge from server
	challengeReq := map[string]string{
		"identity_key_hex": c.identity.PublicKeyHex(),
	}
	challengeReqBody, _ := json.Marshal(challengeReq)

	resp, err := c.http.Post(
		c.serverURL+"/v1/auth/challenge",
		"application/json",
		bytes.NewReader(challengeReqBody),
	)
	if err != nil {
		return "", fmt.Errorf("%w: challenge request failed: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", ErrRateLimited
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: challenge failed: HTTP %d - %s", ErrAuthFailed, resp.StatusCode, string(body))
	}

	var challengeResp struct {
		ChallengeHex string `json:"challenge_hex"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&challengeResp); err != nil {
		return "", fmt.Errorf("%w: failed to decode challenge response: %v", ErrAuthFailed, err)
	}

	// Step 2: Sign the challenge
	challengeBytes, err := hex.DecodeString(challengeResp.ChallengeHex)
	if err != nil {
		return "", fmt.Errorf("%w: invalid challenge hex: %v", ErrCryptoError, err)
	}
	signature := c.identity.Sign(challengeBytes)

	// Step 3: Prove ownership
	proveReq := map[string]string{
		"identity_key_hex": c.identity.PublicKeyHex(),
		"challenge_hex":    challengeResp.ChallengeHex,
		"signature_hex":    hex.EncodeToString(signature),
	}
	proveReqBody, _ := json.Marshal(proveReq)

	resp, err = c.http.Post(
		c.serverURL+"/v1/auth/prove",
		"application/json",
		bytes.NewReader(proveReqBody),
	)
	if err != nil {
		return "", fmt.Errorf("%w: prove request failed: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: prove failed: HTTP %d - %s", ErrAuthFailed, resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Token      string `json:"token"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("%w: failed to decode token response: %v", ErrAuthFailed, err)
	}

	c.jwtToken = tokenResp.Token
	return c.jwtToken, nil
}

// Health checks server health
func (c *Client) Health() (map[string]interface{}, error) {
	resp, err := c.http.Get(c.serverURL + "/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// UploadPrekey uploads a signed PreKeyBundle to the server
func (c *Client) UploadPrekey(bundleHex string, isLastResort bool) error {
	c.mu.RLock()
	token := c.jwtToken
	c.mu.RUnlock()

	reqBody, _ := json.Marshal(map[string]interface{}{
		"bundle_hex":     bundleHex,
		"is_last_resort": isLastResort,
	})

	req, err := http.NewRequest(
		"POST",
		c.serverURL+"/v1/prekeys/upload",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return errors.New("bundle replay detected")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: upload prekey failed: HTTP %d", ErrNetworkError, resp.StatusCode)
	}
	return nil
}

// FetchPrekeys returns all PreKeyBundles for a root identity (one per device)
func (c *Client) FetchPrekeys(rootIDHex string) ([]string, error) {
	resp, err := c.http.Get(c.serverURL + "/v1/prekeys/" + rootIDHex)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: fetch prekeys failed: HTTP %d", ErrNetworkError, resp.StatusCode)
	}

	var result struct {
		BundlesHex []string `json:"bundles_hex"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.BundlesHex, nil
}

// SendMessage sends a sealed envelope with optional Ed25519 signature
func (c *Client) SendMessage(recipientID string, payloadHex string, sign bool) (int, error) {
	c.mu.RLock()
	identity := c.identity
	c.mu.RUnlock()

	var body interface{}
	if sign && identity != nil {
		envelope, err := MakeSignedEnvelope(identity, recipientID, payloadHex, false)
		if err != nil {
			return 0, err
		}
		body = envelope
	} else {
		body = map[string]interface{}{
			"recipient_id": recipientID,
			"payload_hex":  payloadHex,
			"compressed":   false,
		}
	}

	reqBody, _ := json.Marshal(body)
	resp, err := c.http.Post(
		c.serverURL+"/v1/messages/send",
		"application/json",
		bytes.NewReader(reqBody),
	)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// SendMessageMulti performs fan-out encryption delivery to multiple devices
func (c *Client) SendMessageMulti(messages map[string]string, sign bool) map[string]int {
	results := make(map[string]int)
	for rcptID, payload := range messages {
		status, err := c.SendMessage(rcptID, payload, sign)
		if err != nil {
			results[rcptID] = 0
		} else {
			results[rcptID] = status
		}
	}
	return results
}

// FetchInbox retrieves queued offline messages
func (c *Client) FetchInbox() ([]*SignedEnvelope, error) {
	c.mu.RLock()
	identity := c.identity
	token := c.jwtToken
	c.mu.RUnlock()

	if identity == nil || token == "" {
		return nil, fmt.Errorf("%w: must authenticate before fetching inbox", ErrAuthFailed)
	}

	url := fmt.Sprintf("%s/v1/messages/inbox?identity_key_hex=%s&token=%s",
		c.serverURL, identity.PublicKeyHex(), token)

	resp, err := c.http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: inbox fetch failed: HTTP %d", ErrNetworkError, resp.StatusCode)
	}

	var result struct {
		Messages []*SignedEnvelope `json:"messages"`
		Count    int               `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Verify signatures on all messages
	verified := make([]*SignedEnvelope, 0, len(result.Messages))
	for _, msg := range result.Messages {
		if VerifySignedEnvelope(msg) {
			verified = append(verified, msg)
		}
	}
	return verified, nil
}

// ── WebSocket Client ─────────────────────────────────────────────────────────

// WebSocketClient provides real-time sealed envelope relay
type WebSocketClient struct {
	serverURL string
	token     string
	identity  *Identity
	conn      *websocket.Conn
	mu        sync.Mutex
	onMessage func(*SignedEnvelope)
	tlsConfig *tls.Config // FIX: carry TLS config for pinning in WS connections
}

// NewWebSocketClient creates a new WebSocket client.
// Pass the same tlsConfig used by the HTTP Client for consistent pinning.
func NewWebSocketClient(serverURL, token string, identity *Identity, tlsConfig ...*tls.Config) *WebSocketClient {
	wsc := &WebSocketClient{
		serverURL: serverURL,
		token:     token,
		identity:  identity,
	}
	if len(tlsConfig) > 0 {
		wsc.tlsConfig = tlsConfig[0]
	}
	return wsc
}

// Connect establishes a WebSocket connection.
// If the client was created with a pinnedCertPEM, the same TLS pinning
// is applied to the WebSocket connection.
func (ws *WebSocketClient) Connect(onMessage func(*SignedEnvelope)) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	wsURL := ws.serverURL
	// Convert http(s) to ws(s)
	if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss" + wsURL[5:]
	} else if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws" + wsURL[4:]
	}
	wsURL = wsURL + "/ws?token=" + ws.token

	ws.onMessage = onMessage

	// FIX: Use the same TLS config as the HTTP client when available
	dialer := *websocket.DefaultDialer
	if ws.tlsConfig != nil {
		dialer.TLSClientConfig = ws.tlsConfig
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("%w: WebSocket dial failed: %v", ErrNetworkError, err)
	}
	ws.conn = conn

	// Start receive loop
	go ws.receiveLoop()
	return nil
}

func (ws *WebSocketClient) receiveLoop() {
	for {
		_, message, err := ws.conn.ReadMessage()
		if err != nil {
			return
		}

		var envelope SignedEnvelope
		if err := json.Unmarshal(message, &envelope); err != nil {
			continue
		}

		if ws.onMessage != nil {
			if VerifySignedEnvelope(&envelope) {
				ws.onMessage(&envelope)
			}
		}
	}
}

// Send sends a sealed envelope over WebSocket
func (ws *WebSocketClient) Send(recipientID, payloadHex string) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if ws.conn == nil {
		return fmt.Errorf("%w: WebSocket not connected", ErrNetworkError)
	}

	envelope, err := MakeSignedEnvelope(ws.identity, recipientID, payloadHex, false)
	if err != nil {
		return err
	}

	data, _ := json.Marshal(envelope)
	return ws.conn.WriteMessage(websocket.BinaryMessage, data)
}

// Disconnect closes the WebSocket connection
func (ws *WebSocketClient) Disconnect() error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	if ws.conn != nil {
		err := ws.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		ws.conn.Close()
		ws.conn = nil
		return err
	}
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// generateUUID returns a cryptographically random RFC 4122 version 4 UUID.
// FIX: Old version mixed a sequential counter into the UUID, making it
// partially predictable (counter leaks message ordering to anyone who obtains
// two UUIDs). UUIDs are message deduplication IDs — they must be unguessable.
func generateUUID() string {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		// crypto/rand failure is fatal — fall back to a timestamp-seeded value
		// rather than silently returning zeros, but log the anomaly.
		log.Printf("[sibna-sdk] WARN: crypto/rand failed in generateUUID: %v — using fallback", err)
		binary.BigEndian.PutUint64(uuid[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(uuid[8:], uint64(time.Now().UnixNano()^0xDEADBEEF))
	}
	// Set RFC 4122 version 4 and variant bits
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
