// src/schnorr_auth.rs
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;


/// Create a non-interactive Schnorr proof of knowledge of `x`.
/// Returns (pubkey, commitment a, response s).
pub fn schnorr_prove(x: &Scalar) -> (RistrettoPoint, RistrettoPoint, Scalar) {
    let mut rng = OsRng;
    let pubkey = RISTRETTO_BASEPOINT_POINT * x;        // P = G*x

    // Prover: pick random r, compute a = G*r
    let r = Scalar::random(&mut rng);
    let a = RISTRETTO_BASEPOINT_POINT * r;

    // Fiat-Shamir: transcript -> challenge c
    let mut t = Transcript::new(b"schnorr_proof");
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    let c = Scalar::from_bytes_mod_order_wide(&buf);

    // response s = r + c * x
    let s = r + c * x;

    (pubkey, a, s)
}

/// Verify Schnorr proof (pubkey, a, s).
pub fn schnorr_verify(pubkey: &RistrettoPoint, a: &RistrettoPoint, s: &Scalar) -> bool {
    // recreate challenge c = H(pubkey || a)
    let mut t = Transcript::new(b"schnorr_proof");
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    let c = Scalar::from_bytes_mod_order_wide(&buf);

    // Check: G*s == a + P*c
    let lhs = RISTRETTO_BASEPOINT_POINT * s;
    let rhs = a + pubkey * c;
    //println!("LHS Is {:?}",lhs);
    //println!("RHS Is{:?}",rhs);
    lhs == rhs
}

fn main() {
    let mut rng = OsRng;

    // Step 1: generate secret scalar (private key)
    let secret = Scalar::random(&mut rng);

    // Step 2: Prover creates proof of knowledge of secret
    let (pubkey, a, s) = schnorr_prove(&secret);

    // Tampering test (Test for failure)
    let tamper_value = Scalar::from(100u64); // A simple, non-zero value
    let s_tampered = s + tamper_value;

    // Step 3: Verifier checks the proof
    let verified = schnorr_verify(&pubkey, &a, &s);

    // Step 4: Print results
    println!("=== Schnorr Authentication Demo ===");
    println!("Secret (not sent): {:?}", secret);
    println!("Public key (compressed): {}", hex::encode(pubkey.compress().to_bytes()));
    println!("Commitment a (compressed): {}", hex::encode(a.compress().to_bytes()));
    println!("Response s: {:?}", s);
    println!("Verification result: {}", verified);

    if verified {
        println!("Proof verified successfully!");
    } else {
        println!("Proof verification failed!");
    }
}

