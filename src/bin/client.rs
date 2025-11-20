use std::io::{Read, Write};
use std::net::TcpStream;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use merlin::Transcript;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

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

    let lhs = RISTRETTO_BASEPOINT_POINT * s;
    let rhs = a + pubkey * c;
    lhs == rhs
}

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
    comp.decompress().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid point"))
}

fn recv_scalar(stream: &mut impl std::io::Read) -> std::io::Result<Scalar> {
    let mut b = [0u8; 32];
    stream.read_exact(&mut b)?;

    let ct_opt = Scalar::from_canonical_bytes(b);
    if ct_opt.is_some().unwrap_u8() == 1 {
        Ok(ct_opt.unwrap())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid scalar"))
    }
}

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:4000")?;
    println!("Connected to server.");

    // Client static keys
    let mut client_static_secret = random_scalar();
    let client_static_pub = RISTRETTO_BASEPOINT_POINT * client_static_secret;

    // Nonce and ephemeral key
    let mut client_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut client_nonce);

    let mut client_eph_secret = random_scalar();
    let client_eph_pub = RISTRETTO_BASEPOINT_POINT * client_eph_secret;

    // Schnorr proof
    let (client_pub_from_prove, client_a, client_s) = schnorr_prove(&client_static_secret, b"client_schnorr");
    assert_eq!(client_pub_from_prove.compress().to_bytes(), client_static_pub.compress().to_bytes());

    // Send client_static_pub, a, s, nonce, ephemeral pub
    send_all(&mut stream, &client_static_pub.compress().to_bytes())?;
    send_all(&mut stream, &client_a.compress().to_bytes())?;
    send_all(&mut stream, &client_s.to_bytes())?;
    send_all(&mut stream, &client_nonce)?;
    send_all(&mut stream, &client_eph_pub.compress().to_bytes())?;
    stream.flush()?;

    // Receive server_static_pub, a, s, nonce, ephemeral pub
    let server_static_pub = recv_point(&mut stream)?;
    let server_a = recv_point(&mut stream)?;
    let server_s = recv_scalar(&mut stream)?;
    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce)?;
    let server_eph_pub = recv_point(&mut stream)?;

    // Verify server proof
    let ok = schnorr_verify(&server_static_pub, &server_a, &server_s, b"server_schnorr");
    println!("Server proof ok: {}", ok);
    if !ok {
        eprintln!("Server proof failed");
        client_static_secret.zeroize();
        client_eph_secret.zeroize();
        return Ok(());
    }

    // Derive session key
    let client_key = derive_session_key(&client_eph_secret, &server_eph_pub, &client_nonce, &server_nonce);
    println!("Client derived session key: {}", hex::encode(client_key));

    client_static_secret.zeroize();
    client_eph_secret.zeroize();

    Ok(())
}
