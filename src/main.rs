use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use merlin::Transcript;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

/// Generate a random scalar
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Create a Schnorr proof of knowledge for secret `x`
fn schnorr_prove(x: &Scalar, label: &'static [u8]) -> (RistrettoPoint, RistrettoPoint, Scalar, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * x;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;

    let mut t = Transcript::new(label);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());

    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    let c = Scalar::from_bytes_mod_order_wide(&buf);

    let s = r + c * x;
    (pubkey, a, s, c)
}

/// Verify Schnorr proof
fn schnorr_verify(pubkey: &RistrettoPoint, a: &RistrettoPoint, s: &Scalar, label: &'static [u8]) -> bool {
    let mut t = Transcript::new(label);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());

    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    let c = Scalar::from_bytes_mod_order_wide(&buf);

    let lhs = RISTRETTO_BASEPOINT_POINT * s;
    let rhs = a + pubkey * c;
    //println!("LHS Is {:?}",lhs);
    //println!("RHS Is{:?}",rhs);
    lhs == rhs
}

/// Derive shared session key via ECDH + HKDF
fn derive_session_key(secret: &Scalar, peer_pub: &RistrettoPoint, nonce1: &[u8; 32], nonce2: &[u8; 32]) -> [u8; 32] {
    let shared = peer_pub * secret;
    let shared_bytes = shared.compress().to_bytes();

    let mut info = Vec::new();
    info.extend_from_slice(nonce1);
    info.extend_from_slice(nonce2);

    let hk = Hkdf::<Sha256>::new(Some(&info), &shared_bytes);
    let mut okm = [0u8; 32];
    hk.expand(b"session key", &mut okm).unwrap();
    okm
}

fn print_hex(label: &str, bytes: impl AsRef<[u8]>) {
    println!("{:<25}{}", format!("{}:", label), hex::encode(bytes.as_ref()));
}

fn main() {
    println!("=== Schnorr + ECDH Mutual Authentication Demo (Debug Mode) ===\n");

    // === Step 1: Generate static keypairs ===
    let mut client_static_secret = random_scalar();
    let client_static_pub = RISTRETTO_BASEPOINT_POINT * client_static_secret;
    let mut server_static_secret = random_scalar();
    let server_static_pub = RISTRETTO_BASEPOINT_POINT * server_static_secret;

    println!("--- Static Key Generation ---");
    println!("Client secret:      {:?}", client_static_secret);
    print_hex("Client public key", client_static_pub.compress().to_bytes());
    println!("Server secret:      {:?}", server_static_secret);
    print_hex("Server public key", server_static_pub.compress().to_bytes());
    println!();

    // === Step 2: Nonce exchange ===
    let mut rng = OsRng;
    let mut client_nonce = [0u8; 32];
    let mut server_nonce = [0u8; 32];
    rng.fill_bytes(&mut client_nonce);
    rng.fill_bytes(&mut server_nonce);

    println!("--- Nonce Exchange ---");
    print_hex("Client nonce", client_nonce);
    print_hex("Server nonce", server_nonce);
    println!();

    // === Step 3: Create Schnorr proofs ===
    println!("--- Schnorr Proof Generation ---");
    let (client_pub, client_a, client_s, client_c) = schnorr_prove(&client_static_secret, b"client_schnorr");
    let (server_pub, server_a, server_s, server_c) = schnorr_prove(&server_static_secret, b"server_schnorr");

    print_hex("Client commitment (a)", client_a.compress().to_bytes());
    print_hex("Client challenge (c)", client_c.to_bytes());
    println!("Client response (s):  {:?}", client_s);
    print_hex("Server commitment (a)", server_a.compress().to_bytes());
    print_hex("Server challenge (c)", server_c.to_bytes());
    println!("Server response (s):  {:?}", server_s);
    println!();

    // === Step 4: Verify proofs ===
    println!("--- Proof Verification ---");
    let client_ok = schnorr_verify(&client_pub, &client_a, &client_s, b"client_schnorr");
    let server_ok = schnorr_verify(&server_pub, &server_a, &server_s, b"server_schnorr");
    println!("Client proof verified: {}", client_ok);
    println!("Server proof verified: {}", server_ok);
    if !client_ok || !server_ok {
        println!(" Authentication failed");
        return;
    }
    println!(" Both proofs verified successfully!\n");

    // === Step 5: Ephemeral ECDH ===
    println!("--- Ephemeral Key Exchange ---");
    let mut client_eph_secret = random_scalar();
    let client_eph_pub = RISTRETTO_BASEPOINT_POINT * client_eph_secret;
    let mut server_eph_secret = random_scalar();
    let server_eph_pub = RISTRETTO_BASEPOINT_POINT * server_eph_secret;

    print_hex("Client ephemeral pub", client_eph_pub.compress().to_bytes());
    print_hex("Server ephemeral pub", server_eph_pub.compress().to_bytes());
    println!();

    // === Step 6: Derive session key ===
    println!("--- Session Key Derivation ---");
    let client_key = derive_session_key(&client_eph_secret, &server_eph_pub, &client_nonce, &server_nonce);
    let server_key = derive_session_key(&server_eph_secret, &client_eph_pub, &client_nonce, &server_nonce);

    print_hex("Client derived key", client_key);
    print_hex("Server derived key", server_key);

    assert_eq!(client_key, server_key);
    println!(" Session key matches on both sides!\n");

    // === Step 7: Zeroize secrets ===
    println!("--- Zeroization ---");
    client_static_secret.zeroize();
    server_static_secret.zeroize();
    client_eph_secret.zeroize();
    server_eph_secret.zeroize();
    println!(" Secrets zeroized securely.\n");

    println!("=== Secure Mutual Authentication Complete ===");
}
