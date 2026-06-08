# Security Policy — Sibna Protocol v3.0.1

> [!CAUTION]
> **Security Disclaimer**: Sibna is an experimental cryptographic implementation. It has not undergone formal 3rd-party review. Cryptographic software should not be deployed in critical production environments without independent validation.

---

## Project Maturity: Security-Hardened Research Prototype

> [!IMPORTANT]
> Sibna v3.0.1 is an architectural implementation designed with high-assurance security invariants. It has been engineered to mitigate common side-channel vulnerabilities and evaluated through internal statistical benchmarks. A formal independent security audit has not been performed.

---

## 1. Adversarial Model (Dolev-Yao)

The Sibna Protocol is analyzed against a **Dolev-Yao** adversary $\mathcal{A}$ with the following capabilities:
- **Network Access**: $\mathcal{A}$ can read, intercept, and inject any message on the relay or P2P transport layers.
- **Session Compromise**: A compromise of $\mathcal{A}$'s session-specific ephemeral state does not impact the confidentiality of previous or future sessions (**Forward Secrecy / Break-in Recovery**).
- **Hardness**: We assume $\mathcal{A}$ cannot solve the **Computational Diffie-Hellman (CDH)** or **Module-LWE** problems in polynomial time.

## 2. Technical Mitigations & Engineering Status

| Security Property | Engineering Mechanism | Status |
|-------------------|-----------------------|--------|
| **Confidentiality** | ChaCha20-Poly1305 AEAD | Implemented |
| **Quantum Safety** | ML-KEM-768 Hybrid | Under Evaluation |
| **Handshake Safety** | Lexicographical Role Resolution | Modeled |
| **Forward Secrecy** | HMAC-SHA256 Ratchets | Implemented |
| **Side-Channel Stability** | `subtle` Constant-Time Primitives | Internal Evaluation Ongoing |
| **Memory Hygiene** | `Zeroize` & Memory Pinning | Implemented |
| **Traffic Analysis** | Noise-Prefix Padding (up to 64KB) | Implemented |
| **Identity Anchoring** | Cryptographic TOFU Pinning | Policy Enforced |

---

## 3. Non-Guarantees & Known Limitations

Sibna v3.0.1 is an experimental research prototype. It does **not** provide guarantees against:
1.  **Hardware Side-Channels**: Resistance is software-layer only. Differential Power Analysis (DPA) is outside the design scope.
2.  **Compromised Shared Infrastructure**: Micro-architectural attacks (e.g., Spectre) in virtualized cloud environments may impact timing stability.
3.  **Root/Kernel Compromise**: A compromised host environment can bypass physical memory pinning and secure storage.

---

## 4. Formal Mitigation Strategies

### 4.1 Traffic Analysis (Passive Observer)
- **Strategy:** Fixed-block padding with random noise prefixes and an internal encrypted length field.
- **Observed Behavior:** Ciphertext length is decoupled from plaintext size up to the configured block boundary (1KB - 64KB).

### 4.2 Simultaneous Handshake (Role Confusion)
- **Strategy:** Consensus-driven role resolution based on public key lexicographical order.
- **Observed Behavior:** Initiator/Responder roles are resolved deterministically without server arbitration.

### 4.3 Identity Impersonation (MITM)
- **Strategy:** Cryptographic Identity Pinning. 
- **Observed Behavior:** Session establishment is aborted if a peer's identity key deviates from the pinned cache (TOFU).

---

## Vulnerability Disclosure

**Do not open public issues for security vulnerabilities.**  
Please report security concerns privately to:  
📧 `contact.sibna.dev`
