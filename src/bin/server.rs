use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Instant;
use std::thread;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use merlin::Transcript;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

// ----------------------------------------------------
// Crypto helpers
// ----------------------------------------------------

fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

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

    RISTRETTO_BASEPOINT_POINT * s == a + pubkey * c
}

fn derive_session_key(
    secret: &Scalar,
    peer_pub: &RistrettoPoint,
    n1: &[u8; 32],
    n2: &[u8; 32],
) -> [u8; 32] {
    let shared = peer_pub * secret;
    let shared_bytes = shared.compress().to_bytes();

    let mut info = Vec::new();
    info.extend_from_slice(n1);
    info.extend_from_slice(n2);

    let hk = Hkdf::<Sha256>::new(Some(&info), &shared_bytes);
    let mut okm = [0u8; 32];
    hk.expand(b"session key", &mut okm).unwrap();
    okm
}

// ----------------------------------------------------
// Network helpers WITH BYTE COUNTING
// ----------------------------------------------------

fn send_all(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    *sent += buf.len();
    stream.write_all(buf)
}

fn recv_exact(stream: &mut impl Read, buf: &mut [u8], recv: &mut usize) -> std::io::Result<()> {
    stream.read_exact(buf)?;
    *recv += buf.len();
    Ok(())
}

fn recv_point(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<RistrettoPoint> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid point"))
}

fn recv_scalar(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Scalar> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    let ct = Scalar::from_canonical_bytes(b);
    if ct.is_some().unwrap_u8() == 1 {
        Ok(ct.unwrap())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid scalar"))
    }
}

// ----------------------------------------------------
// SERVER CLIENT HANDLER
// ----------------------------------------------------

fn handle_client(mut stream: std::net::TcpStream, server_static_secret: Scalar, server_static_pub: RistrettoPoint) {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    println!("Server: New client {}", stream.peer_addr().unwrap());

    // === Receive client credentials ===
    let client_static_pub = recv_point(&mut stream, &mut recv).unwrap();
    let client_a = recv_point(&mut stream, &mut recv).unwrap();
    let client_s = recv_scalar(&mut stream, &mut recv).unwrap();

    let mut client_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut client_nonce, &mut recv).unwrap();

    let client_eph_pub = recv_point(&mut stream, &mut recv).unwrap();

    // === Verify client ===
    let ok = schnorr_verify(&client_static_pub, &client_a, &client_s, b"client_schnorr");
    println!("Server: Client authentication = {}", ok);

    if !ok {
        eprintln!("Server: Invalid client proof");
        return;
    }

    // === Server generates proof + ephemeral keys ===
    let (spub2, server_a, server_s) =
        schnorr_prove(&server_static_secret, b"server_schnorr");
    assert_eq!(spub2.compress().to_bytes(), server_static_pub.compress().to_bytes());

    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);

    let server_eph_secret = random_scalar();
    let server_eph_pub = RISTRETTO_BASEPOINT_POINT * server_eph_secret;

    // === Send server credentials ===
    send_all(&mut stream, &server_static_pub.compress().to_bytes(), &mut sent).unwrap();
    send_all(&mut stream, &server_a.compress().to_bytes(), &mut sent).unwrap();
    send_all(&mut stream, &server_s.to_bytes(), &mut sent).unwrap();
    send_all(&mut stream, &server_nonce, &mut sent).unwrap();
    send_all(&mut stream, &server_eph_pub.compress().to_bytes(), &mut sent).unwrap();

    stream.flush().unwrap();

    // === Derive key ===
    let key =
        derive_session_key(&server_eph_secret, &client_eph_pub, &client_nonce, &server_nonce);

    println!(
        "Server: Session key for {} = {}",
        stream.peer_addr().unwrap(),
        hex::encode(key)
    );

    let duration = start.elapsed();

    println!(
        "SERVER METRICS -> Client {} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        stream.peer_addr().unwrap(), duration, sent, recv
    );
}

// ----------------------------------------------------
// MAIN SERVER
// ----------------------------------------------------

fn main() -> std::io::Result<()> {
    println!("Server: Listening on 0.0.0.0:4000");
    let listener = TcpListener::bind("0.0.0.0:4000")?;

    // One static key for all clients
    let server_static_secret = random_scalar();
    let server_static_pub = RISTRETTO_BASEPOINT_POINT * server_static_secret;

    loop {
        let (stream, _) = listener.accept()?;

        let ss = server_static_secret.clone();
        let sp = server_static_pub.clone();

        thread::spawn(move || {
            handle_client(stream, ss, sp);
        });
    }
}
