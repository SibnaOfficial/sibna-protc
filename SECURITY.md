# Security Model

This document outlines the threat model, assumptions, and limitations of the Sibna Protocol.

## Status

This project implements modern cryptographic standards but has not undergone an independent external security audit. It is intended for research and integration by developers who understand the underlying protocols.

## Threat Model

The protocol provides protections against the following scenarios:
- Active MITM attacks (assuming out-of-band Safety Number verification is performed)
- Local DB extraction (authenticity is protected via HMAC)
- Key recovery from memory (keys zeroize on drop)

The protocol does not provide complete protection against a Global Passive Adversary (GPA). Users requiring strong network anonymity should route connections through Tor or a SOCKS5 proxy.

## Cryptographic Protections

- Confidentiality: ChaCha20-Poly1305 (256-bit) AEAD
- Quantum Resistance: Hybrid ML-KEM-768 and X25519
- Timing attack mitigation: Constant-time comparisons via the `subtle` crate
- Replay protection: Atomic message counters and timestamps
- Sealed Sender: The server routes envelopes without knowing the sender identity
- Traffic analysis mitigation: Constant-length padding limits length exposure

## Known Limitations

### 1. Global Passive Adversary (GPA)
Sibna provides padding and cover traffic but cannot completely protect against correlation attacks by an adversary monitoring the entire network.

### 2. Trust On First Use (TOFU)
The initial key exchange is vulnerable to active interception. The library pins public keys on first contact to prevent subsequent tampering, but developers must implement their own out-of-band verification mechanism (Safety Numbers) for the initial exchange.

### 3. Anonymity
Network-level anonymity is not built-in. IP addresses of peers are visible to the routing server unless a proxy is explicitly configured in `P2pConfig`.

### 4. Hardware Side Channels
We use standard constant-time cryptographic libraries. However, there is no inherent protection against hardware architectural side channels such as Spectre or Meltdown.

## Vulnerability Disclosure

Please report security issues to `security@sibna.dev`.
