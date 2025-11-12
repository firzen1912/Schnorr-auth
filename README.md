
```markdown
# Schnorr-auth: A Rust-Based Implementation of Mutual Authentication Using Schnorr Proofs and ECDH

## Abstract

This project presents a Rust implementation of a mutual authentication protocol based on Schnorr’s zero-knowledge proof of knowledge over the Ristretto group (Curve25519). The protocol enables two entities, such as an IoT client and a server, to authenticate each other without revealing private keys, followed by the derivation of a shared session key using the Elliptic Curve Diffie-Hellman (ECDH) mechanism. A hierarchical key derivation function (HKDF) is applied to generate a secure 256-bit session key, and all sensitive data are securely erased using memory zeroization techniques. The implementation serves as a demonstration of cryptographic design principles suitable for resource-constrained environments and lightweight secure communications.

---

## 1. Introduction

In modern distributed systems, particularly in the Internet of Things (IoT) ecosystem, devices are often deployed in untrusted environments where traditional authentication mechanisms may be impractical due to computational or bandwidth limitations. Zero-knowledge proofs (ZKPs) offer a means to authenticate entities without exposing sensitive information, providing resistance against replay and impersonation attacks.

This project implements a two-party mutual authentication protocol that combines a Schnorr identification scheme with an ECDH-based key exchange. The purpose is to demonstrate the feasibility of constructing an efficient authentication and key agreement mechanism using modern cryptographic primitives implemented in Rust.

---

## 2. Background and Motivation

The Schnorr proof of knowledge protocol, introduced by Claus Schnorr in 1989, is a foundational construction in modern cryptography for proving possession of a secret key corresponding to a public value without disclosing the key itself. Its simplicity and efficiency make it suitable for constrained devices.

By combining Schnorr authentication with ECDH key exchange, this project creates a framework where both parties:
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

3. **Schnorr Proof Generation**  
   Each party computes a proof of knowledge of its secret key:
```

r ← random scalar
a = g·r
c = H(g, X, a)
s = r + c·x

```
The proof consists of `(a, s)` and can be verified using the equation:
```

g·s = a + X·c

```

4. **Proof Verification**  
Each side verifies the other’s proof using a transcript mechanism (Merlin) to ensure binding to the session context.

5. **Ephemeral Key Exchange (ECDH)**  
Both sides generate ephemeral keypairs and compute a shared secret:
```

shared = peer_pub · sk_eph

```

6. **Session Key Derivation**  
The shared secret is expanded into a 256-bit session key using HKDF with SHA-256:
```

K = HKDF(Sha256, shared, info = nonces)

````

7. **Zeroization**  
All sensitive scalars are securely erased using the `zeroize` crate.

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
````

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

## 6. Future Work

Further development could extend this prototype into a fully functional lightweight authentication framework for IoT networks. Future directions include:

* Implementing real client-server communication over TCP, MQTT, or CoAP.
* Incorporating symmetric encryption for secure message exchange using the derived session key.
* Extending to multi-party settings or hierarchical trust models.
* Evaluating performance on embedded hardware such as Raspberry Pi or ESP32 platforms.
* Exploring advanced zero-knowledge protocols (e.g., Sigma or zk-SNARK-based authentication).

---

## 7. Conclusion

This project demonstrates the construction of a secure, mutual authentication protocol combining Schnorr zero-knowledge proofs and elliptic-curve key exchange within the Rust programming environment. The resulting implementation highlights the practicality of zero-knowledge-based authentication for lightweight and resource-constrained devices, bridging academic theory and practical cybersecurity applications.

---

## References

1. C. Schnorr, "Efficient Identification and Signatures for Smart Cards," *Advances in Cryptology – CRYPTO '89*, Springer, 1989.
2. H. Krawczyk, "HKDF: Extract-and-Expand Key Derivation Function (RFC 5869)," IETF, 2010.
3. Curve25519-dalek documentation: [https://docs.rs/curve25519-dalek/latest/curve25519_dalek/](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/)
4. Merlin transcripts documentation: [https://docs.rs/merlin/latest/merlin/](https://docs.rs/merlin/latest/merlin/)
5. Rust Zeroize crate: [https://crates.io/crates/zeroize](https://crates.io/crates/zeroize)

---

## Author

**Firzen1912**
Research focus: IoT Security, Zero-Knowledge Proofs, and Lightweight Authentication
License: MIT

```

---
