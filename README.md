# Schnorr-auth: A Rust-Based Implementation of Mutual Authentication Using Schnorr Proofs, Fiat–Shamir Transformation, and ECDH

## Abstract

This project presents a Rust implementation of a mutual authentication protocol based on Schnorr’s zero-knowledge proof of knowledge over the Ristretto group (Curve25519). The protocol enables two entities, such as an IoT client and a server, to authenticate each other without revealing private keys, followed by the derivation of a shared session key using the Elliptic Curve Diffie-Hellman (ECDH) mechanism. The **Fiat–Shamir transformation** is applied to convert the interactive Schnorr identification protocol into a non-interactive zero-knowledge proof, securely binding session context via the Merlin transcript framework. A hierarchical key derivation function (HKDF) is then applied to generate a secure 256-bit session key, and all sensitive data are securely erased using memory zeroization techniques. The implementation serves as a demonstration of cryptographic design principles suitable for resource-constrained environments and lightweight secure communications.

---

## 1. Introduction

In modern distributed systems, particularly in the Internet of Things (IoT) ecosystem, devices are often deployed in untrusted environments where traditional authentication mechanisms may be impractical due to computational or bandwidth limitations. Zero-knowledge proofs (ZKPs) offer a means to authenticate entities without exposing sensitive information, providing resistance against replay and impersonation attacks.

This project implements a two-party mutual authentication protocol that combines a Schnorr identification scheme (enhanced with the Fiat–Shamir transformation) and an ECDH-based key exchange. The purpose is to demonstrate the feasibility of constructing an efficient authentication and key agreement mechanism using modern cryptographic primitives implemented in Rust.

---

## 2. Background and Motivation

The Schnorr proof of knowledge protocol, introduced by Claus Schnorr in 1989, is a foundational construction in modern cryptography for proving possession of a secret key corresponding to a public value without disclosing the key itself. Its simplicity and efficiency make it suitable for constrained devices.

In the original Schnorr identification scheme, the verifier issues a random challenge to the prover. To make the protocol non-interactive and more practical for distributed systems, the **Fiat–Shamir transformation** replaces this challenge with a deterministic cryptographic hash derived from the current protocol transcript. This modification results in a **non-interactive zero-knowledge proof (NIZKP)** that retains the security guarantees of the original protocol while eliminating the need for real-time interaction.

By combining Schnorr authentication (via the Fiat–Shamir heuristic) with ECDH key exchange, this project creates a framework where both parties:

1. Prove possession of their respective private keys (mutual authentication).
2. Establish a shared session key used for subsequent secure communication.

Rust was chosen for implementation due to its emphasis on safety, memory management, and performance—key factors in security-critical and embedded system applications.

---

## 3. Methodology

### 3.1 Protocol Overview

The protocol proceeds through the following phases:

1. **Static Key Generation**
   Each participant generates a long-term keypair `(x, X = g·x)` where `g` is the Ristretto basepoint.

2. **Nonce Exchange**
   Both participants generate random nonces to ensure session freshness.

3. **Schnorr Proof Generation (Fiat–Shamir Form)**
   Each party computes a non-interactive proof of knowledge of its secret key using the Fiat–Shamir heuristic:

```
r ← random scalar
a = g·r
c = H(g, X, a, context)
s = r + c·x
```

The proof consists of `(a, s)` and can be verified using the equation:

```
g·s = a + X·c
```

The challenge `c` is deterministically derived via a cryptographic hash of the protocol transcript, effectively replacing the verifier’s interactive challenge.

4. **Proof Verification**
   Each side verifies the other’s proof using a transcript mechanism (Merlin) to ensure all components are bound to the session context and are tamper-resistant.

5. **Ephemeral Key Exchange (ECDH)**
   Both sides generate ephemeral keypairs and compute a shared secret:

```
shared = peer_pub · sk_eph
```

6. **Session Key Derivation**
   The shared secret is expanded into a 256-bit session key using HKDF with SHA-256:

```
K = HKDF(Sha256, shared, info = nonces)
```

7. **Zeroization**
   All sensitive scalars are securely erased using the `zeroize` crate.

---

### 3.2 Fiat–Shamir Transformation in Detail

To eliminate the need for interactive challenge–response exchanges, this implementation applies the **Fiat–Shamir heuristic** to the Schnorr proof. In the traditional interactive version, the verifier sends a random challenge `c` to the prover after receiving the commitment `a = g·r`. The transformation replaces this step with a deterministic computation of the challenge:

```
c = H(g, X, a, context)
```

Here, `context` includes session-specific data such as nonces, participant identifiers, or other transcript elements. This approach transforms the interactive proof into a **non-interactive zero-knowledge proof (NIZKP)**, allowing verification without real-time communication.

In this project, the Fiat–Shamir transformation is implemented using the **Merlin transcript framework**, which ensures that all relevant session data are incorporated into the hash function. This binding of data prevents replay attacks and cross-session forgeries, enhancing both the integrity and security of the authentication process.

---

## 4. Implementation Details

### 4.1 Software Dependencies

The project utilizes the following Rust crates:

```toml
[dependencies]
curve25519-dalek = "4"
merlin = "3"
rand = "0.8"
hkdf = "0.12"
sha2 = "0.10"
hex = "0.4"
zeroize = "1.6"
```

### 4.2 Execution

Clone the repository and execute the demonstration using Cargo:

```bash
git clone https://github.com/firzen1912/Schnorr-auth.git
cd Schnorr-auth
cargo run
```

### 4.3 Example Output

```
=== Schnorr + ECDH Mutual Authentication Demo ===

--- Static Key Generation ---
Client public key:  4a8f8e...
Server public key:  7b3d9c...

--- Proof Verification ---
Client proof verified: true
Server proof verified: true
Both proofs verified successfully!

Session key matches on both sides!
Secrets zeroized securely.
```

---

## 5. Security Considerations

This implementation is a proof-of-concept designed for educational and research purposes. It does not include network-layer protections or resistance to side-channel attacks. For deployment in real-world environments, additional safeguards are necessary:

* Binding of identities and session metadata to proofs.
* Integration of message authentication codes (MACs) or digital signatures.
* Use of secure transport (TLS or DTLS) for message transmission.
* Incorporation of key confirmation to prevent unknown key-share attacks.

---

## 6. Future Work and Conclusion

This project demonstrates the construction of a secure, mutual authentication protocol combining Schnorr zero-knowledge proofs, the Fiat–Shamir transformation, and elliptic-curve key exchange within the Rust programming environment. The resulting implementation highlights the practicality of zero-knowledge-based authentication for lightweight and resource-constrained devices, bridging academic theory and practical cybersecurity applications.

Future development can extend this prototype into a fully functional lightweight authentication framework for IoT networks. Potential directions include:

1. Implementing real client-server communication over TCP, MQTT, or CoAP.
2. Incorporating symmetric encryption for secure message exchange using the derived session key.
3. Evaluating performance on embedded platforms such as Raspberry Pi or ESP32.

These future directions aim to strengthen the system’s real-world applicability and scalability while maintaining its efficiency and security under constrained computational conditions.

---

## References

1. C. Schnorr, "Efficient Identification and Signatures for Smart Cards," *Advances in Cryptology – CRYPTO '89*, Springer, 1989.
2. A. Fiat and A. Shamir, “How to Prove Yourself: Practical Solutions to Identification and Signature Problems,” *CRYPTO ’86*, Springer, 1986.
3. H. Krawczyk, "HKDF: Extract-and-Expand Key Derivation Function (RFC 5869)," IETF, 2010.
4. Curve25519-dalek documentation: [https://docs.rs/curve25519-dalek/latest/curve25519_dalek/](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/)
5. Merlin transcripts documentation: [https://docs.rs/merlin/latest/merlin/](https://docs.rs/merlin/latest/merlin/)
6. Rust Zeroize crate: [https://crates.io/crates/zeroize](https://crates.io/crates/zeroize)

---

## Author

**Khang Tran**
Research Focus: IoT Security, Zero-Knowledge Proofs, and Lightweight Authentication

License: MIT

---
