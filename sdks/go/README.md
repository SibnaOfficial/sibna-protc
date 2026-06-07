# Sibna Protocol — Go SDK

> **Sibna Protocol v3.0.1** — relay client with sealed-envelope messaging, identity management, and metadata-resistant padding.
> This document reflects the code that is actually shipped in `sdks/go/client.go`. Anything not listed below is not implemented in this SDK.

## What this SDK is

The Go SDK is a **transport + envelope** layer for talking to a Sibna relay server. It is **not** a self-contained end-to-end cryptography stack — the encrypted application message is expected to be produced by a separate component (e.g. the Rust core) and passed in as a hex string.

What is implemented in `sdks/go/client.go`:

| Capability | Implemented? | Notes |
|---|---|---|
| Ed25519 identity keypair generation | ✅ | `GenerateIdentity` (uses `crypto/ed25519`). |
| Ed25519 sign / verify | ✅ | `Identity.Sign`, `VerifySignedEnvelope`. |
| Sealed-envelope message format | ✅ | `MakeSignedEnvelope`. |
| Block-aligned payload padding (1 KiB blocks) | ✅ | `PadPayload`, `UnpadPayload`. |
| HTTP client (REST) | ✅ | `Client`. |
| WebSocket client (real-time relay) | ✅ | `WebSocketClient` (uses `gorilla/websocket`). |
| TLS certificate pinning (PEM) | ✅ | `NewClient(url, "/path/to/server.pem")`. TLS 1.3 minimum. |
| TLS configuration shared between HTTP and WebSocket | ✅ | Pass the `*tls.Config` from the HTTP client to `NewWebSocketClient` so both connections pin the same certificate. |
| Fan-out to multiple recipients | ✅ | `SendMessageMulti`. |
| Offline inbox polling with signature verification | ✅ | `FetchInbox` calls `VerifySignedEnvelope` on every message. |
| UUIDv4 message identifiers | ✅ | `generateUUID` uses `crypto/rand`. |
| Thread-safe token / identity access | ✅ | `sync.RWMutex` on the `Client`. |

What is **not** implemented:

- ❌ X3DH handshake — not present.
- ❌ Double Ratchet — not present.
- ❌ Group messaging / sender keys — not present.
- ❌ Safety number / verification QR — not present.
- ❌ Application-level encryption — the SDK signs the envelope and pads the payload, but does **not** encrypt the application message.

If you need end-to-end encrypted messaging, pair this SDK with `sibna-core` (Rust) or the Java SDK.

## Requirements

- Go 1.21+
- `github.com/gorilla/websocket` (declared in `go.mod`).

## Installation

```bash
cd sdks/go
go mod download
```

The package is not currently published as a Go module. Import it from this source tree.

## Module layout

```
sdks/go/
├── client.go         # All public API
├── client_test.go
├── go.mod
├── go.sum
└── README.md
```

The package name is `sibna` (declared by `package sibna` in `client.go`).

## Quick start

```go
package main

import (
    "fmt"
    "log"
    sibna "github.com/SibnaOfficial/sibna-protc/sdks/go"
)

func main() {
    // 1. Create the HTTP client with TLS pinning
    client, err := sibna.NewClient("https://sibna.example.com", "/etc/sibna/server.pem")
    if err != nil {
        log.Fatal(err)
    }

    // 2. Generate or load an identity
    id, err := sibna.GenerateIdentity()
    if err != nil {
        log.Fatal(err)
    }
    client.SetIdentity(id)

    // 3. Authenticate
    token, err := client.Authenticate()
    if err != nil {
        log.Fatal(err)
    }
    _ = token

    // 4. Upload a PreKey bundle (produced by the Rust core)
    if err := client.UploadPrekey("bundle-hex...", false); err != nil {
        log.Fatal(err)
    }

    // 5. Send a sealed envelope
    status, err := client.SendMessage("<recipient-hex>", "<payload-hex>", true)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("HTTP status:", status)

    // 6. Poll the offline inbox
    inbox, err := client.FetchInbox()
    if err != nil {
        log.Fatal(err)
    }
    for _, env := range inbox {
        fmt.Println(env.MessageID, env.SenderID)
    }

    // 7. WebSocket real-time
    //    Pass the same TLS config so WS uses the pinned cert.
    ws := sibna.NewWebSocketClient("https://sibna.example.com", token, id,
        // The pinnedCertPEM is the *tls.Config built by NewClient. If you
        // want to share it, you can build your own with the same options.
    )
    _ = ws
}
```

## API reference

### Constants

```go
const (
    Version      = "3.0.1"
    PaddingBlock = 1024
)
```

### Errors

```go
var (
    ErrAuthFailed    = errors.New("authentication failed")
    ErrNetworkError  = errors.New("network error")
    ErrCryptoError   = errors.New("cryptographic error")
    ErrRateLimited   = errors.New("rate limited (HTTP 429)")
    ErrNotAuthorized = errors.New("not authorized (HTTP 401)")
    ErrInvalidArg    = errors.New("invalid argument")
)
```

### `type Identity`

```go
type Identity struct {
    PrivateKey ed25519.PrivateKey
    PublicKey  ed25519.PublicKey
}
```

| Function | Description |
|---|---|
| `GenerateIdentity() (*Identity, error)` | Random Ed25519 keypair from `crypto/rand`. |
| `IdentityFromSeed(seed []byte) (*Identity, error)` | Deterministically derive a keypair from a 32-byte seed. |
| `id.PublicKeyHex() string` | 64-character hex of the public key. |
| `id.Sign(data []byte) []byte` | 64-byte Ed25519 signature. |
| `id.SignHex(data []byte) string` | Hex-encoded signature. |

### Padding

```go
padded, err := sibna.PadPayload(data)
orig,  err := sibna.UnpadPayload(padded)
```

> **Wire-format note:** the Go SDK uses a different padding layout than the Python and JavaScript SDKs. The first byte is an 8-bit indicator, and the next two bytes are a big-endian padding length. Total output is always a multiple of `PaddingBlock` (1024). If you are exchanging padded payloads between Go and another SDK, pad and unpad in the **same** language. The Go layout is **not** identical to the layout in `core/`, which uses a 1-byte prefix length followed by random prefix noise.

### `func MakeSignedEnvelope` and `func VerifySignedEnvelope`

```go
env, err := sibna.MakeSignedEnvelope(identity, recipientID, payloadHex, compress)
ok  := sibna.VerifySignedEnvelope(env)
```

`SignedEnvelope` fields:

| Field | JSON tag | Notes |
|---|---|---|
| `RecipientID`  | `recipient_id`  | The server routes on this; payload is opaque. |
| `PayloadHex`   | `payload_hex`   | Encrypted application message. |
| `SenderID`     | `sender_id`     | Ed25519 public key of the sender (hex). |
| `Timestamp`    | `timestamp`     | Unix seconds. |
| `MessageID`    | `message_id`    | Random UUIDv4. |
| `SignatureHex` | `signature_hex` | Ed25519 over `SHA-512(recipient_id ‖ payload_hex ‖ timestamp ‖ message_id)`. |
| `Compressed`   | `compressed`    | Reserved. |

### `type Client` (HTTP)

```go
func NewClient(serverURL string, pinnedCertPEM ...string) (*Client, error)
```

If the first `pinnedCertPEM` argument is a non-empty path, the client builds a `*tls.Config` with a custom `RootCAs` containing only that certificate and sets `MinVersion: tls.VersionTLS13`. If no PEM is supplied but the URL is `https://`, a warning is printed and the system trust store is used with TLS 1.2 minimum.

| Method | Description |
|---|---|
| `SetIdentity(*Identity)` | Bind an identity. |
| `IdentityHex() string` | Hex of the bound identity, or `""`. |
| `JWTToken() string` | Current token. |
| `Authenticate() (string, error)` | Ed25519 challenge-response → JWT. |
| `Health() (map[string]any, error)` | `GET /health`. |
| `UploadPrekey(bundleHex string, isLastResort bool) error` | `POST /v1/prekeys/upload`. |
| `FetchPrekeys(rootIDHex string) ([]string, error)` | `GET /v1/prekeys/{root_id}`. Returns `nil, nil` on 404. |
| `SendMessage(recipientID, payloadHex string, sign bool) (int, error)` | `POST /v1/messages/send`. |
| `SendMessageMulti(messages map[string]string, sign bool) map[string]int` | Fan-out. Per-recipient status, 0 on error. |
| `FetchInbox() ([]*SignedEnvelope, error)` | `GET /v1/messages/inbox`. Drops envelopes whose signature does not verify. |

### `type WebSocketClient`

```go
func NewWebSocketClient(serverURL, token string, identity *Identity, tlsConfig ...*tls.Config) *WebSocketClient
```

| Method | Description |
|---|---|
| `Connect(onMessage func(*SignedEnvelope)) error` | Open the WebSocket. Starts a background goroutine that reads and dispatches `*SignedEnvelope` to `onMessage` **only after** `VerifySignedEnvelope` succeeds. |
| `Send(recipientID, payloadHex string) error` | Send a signed envelope. |
| `Disconnect() error` | Send a close frame and close the connection. |

## Security notes

- **TLS pinning** is enforced when `pinnedCertPEM` is supplied. The pinned certificate becomes the only trust anchor; the system CA store is ignored.
- **TLS 1.3 minimum** is required when a pinned cert is provided. Without pinning, the client uses TLS 1.2 minimum.
- **Signature verification** is performed in `FetchInbox` (HTTP) and inside `WebSocketClient.receiveLoop` (WebSocket). Invalid envelopes are silently dropped.
- **Randomness** is sourced from `crypto/rand` (Go's OS CSPRNG) for key generation, padding, and UUIDs.
- **Thread safety**: the `Client` uses a `sync.RWMutex` to protect the identity and token. It is safe to call `SendMessage` and `FetchInbox` from multiple goroutines.
- **The WebSocket goroutine does not terminate on read errors**; a closed connection will keep the goroutine alive until the underlying transport signals a clean close. Always call `Disconnect()` from a defer.

## Limitations

- The Go SDK is the **envelope and transport layer only**. It does not implement X3DH, Double Ratchet, or group messaging. Use `sibna-core` or the Java SDK for the cryptographic layer.
- The padding format differs from the Rust core, the Python SDK, and the JavaScript SDK. Do not exchange padded payloads across language boundaries.
- The package is not currently published as a Go module.

## License

Apache-2.0 OR MIT
