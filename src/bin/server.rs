use std::io::{Read, Write};
use std::net::TcpListener;

// Crypto imports
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use merlin::Transcript;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

// === Common Crypto Helpers (same as in client) ===

fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Schnorr prove: returns (pubkey, a, s)
fn schnorr_prove(x: &Scalar, label: &'static [u8]) -> (RistrettoPoint, RistrettoPoint, Scalar) {
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
    (pubkey, a, s)
}

fn schnorr_verify(pubkey: &RistrettoPoint, a: &RistrettoPoint, s: &Scalar, label: &'static [u8]) -> bool {
    let mut t = Transcript::new(label);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());

    let mut buf = [0u8; 64];
    t.challenge_bytes(b"c", &mut buf);
    let c = Scalar::from_bytes_mod_order_wide(&buf);

    let lhs = RISTRETTO_BASEPOINT_POINT * s;
    let rhs = a + pubkey * c;
    lhs == rhs
}

fn derive_session_key(
    secret: &Scalar,
    peer_pub: &RistrettoPoint,
    nonce1: &[u8; 32],
    nonce2: &[u8; 32],
) -> [u8; 32] {
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

// === Network helpers (mirror client.rs) ===

fn recv_exact(stream: &mut impl Read, buf: &mut [u8]) -> std::io::Result<()> {
    stream.read_exact(buf)
}

fn send_all(stream: &mut impl Write, buf: &[u8]) -> std::io::Result<()> {
    stream.write_all(buf)
}

fn recv_point(stream: &mut impl Read) -> std::io::Result<RistrettoPoint> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b)?;
    let comp = CompressedRistretto(b);
    comp.decompress().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Ristretto point")
    })
}

fn recv_scalar(stream: &mut impl Read) -> std::io::Result<Scalar> {
    let mut b = [0u8; 32];
    stream.read_exact(&mut b)?;
    let ct_opt = Scalar::from_canonical_bytes(b);
    if ct_opt.is_some().unwrap_u8() == 1 {
        Ok(ct_opt.unwrap())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid scalar",
        ))
    }
}

// === Main server logic: mutual authentication ===

fn main() -> std::io::Result<()> {
    // Listen on port 4000 (matches client.rs)
    let listener = TcpListener::bind("0.0.0.0:4000")?;
    println!("Server listening on 0.0.0.0:4000");

    // For a real system, you would load a persistent static keypair from disk/flash.
    let mut server_static_secret = random_scalar();
    let server_static_pub = RISTRETTO_BASEPOINT_POINT * server_static_secret;

    for stream in listener.incoming() {
        let mut stream = stream?;
        println!("Client connected.");

        // === Step 1: Receive client credentials ===
        let client_static_pub = recv_point(&mut stream)?;
        let client_a = recv_point(&mut stream)?;
        let client_s = recv_scalar(&mut stream)?;
        let mut client_nonce = [0u8; 32];
        recv_exact(&mut stream, &mut client_nonce)?;
        let client_eph_pub = recv_point(&mut stream)?;

        println!("Received client credentials and proof components.");

        // === Step 2: Verify client's Schnorr proof ===
        let client_ok =
            schnorr_verify(&client_static_pub, &client_a, &client_s, b"client_schnorr");
        println!("Client proof ok: {}", client_ok);
        if !client_ok {
            eprintln!("Client proof failed! Aborting authentication.");
            // Zeroize secret and continue waiting for the next client
            server_static_secret.zeroize();
            continue;
        }

        // === Step 3: Generate server nonce, ephemeral key, and Schnorr proof ===
        let mut server_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut server_nonce);

        let mut server_eph_secret = random_scalar();
        let server_eph_pub = RISTRETTO_BASEPOINT_POINT * server_eph_secret;

        let (server_pub_from_prove, server_a, server_s) =
            schnorr_prove(&server_static_secret, b"server_schnorr");
        // Sanity check: pubkey from proof matches our server_static_pub
        assert_eq!(
            server_pub_from_prove.compress().to_bytes(),
            server_static_pub.compress().to_bytes()
        );

        // === Step 4: Send server credentials to client ===
        send_all(&mut stream, &server_static_pub.compress().to_bytes())?;
        send_all(&mut stream, &server_a.compress().to_bytes())?;
        send_all(&mut stream, &server_s.to_bytes())?;
        send_all(&mut stream, &server_nonce)?;
        send_all(&mut stream, &server_eph_pub.compress().to_bytes())?;
        stream.flush()?;
        println!("Sent server credentials and proof components.");

        // === Step 5: Derive shared session key ===
        let server_key = derive_session_key(
            &server_eph_secret,
            &client_eph_pub,
            &client_nonce,
            &server_nonce,
        );
        println!("Server derived session key: {}", hex::encode(server_key));

        // === Step 6: Zeroize secrets ===
        server_eph_secret.zeroize();
        println!("Ephemeral secret zeroized. Handshake complete.");

        // If you want the server to handle only one client, break here.
        // break;
    }

    // Final cleanup: zeroize long-term secret (if server is exiting)
    server_static_secret.zeroize();
    println!("Server static secret zeroized.");

    Ok(())
}
