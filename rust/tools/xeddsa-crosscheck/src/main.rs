//! Batch XEdDSA cross-check driver.
//!
//! stdin, one command per line:
//!   S <seed_hex32> <z_hex64> <msg_hex>      -> "S <sig_hex64> <pub_hex32>"
//!   V <pub_hex32> <msg_hex> <sig_hex64>     -> "V ACCEPT" | "V REJECT"
//! `msg_hex` may be empty (represented as "-").

use core::convert::Infallible;
use mlkb_crypto::xeddsa;
use mlkb_crypto::{X25519PublicKey, X25519SecretKey};
use rand_core::{TryCryptoRng, TryRng};
use std::io::{self, BufRead, Write};

struct FixedZ([u8; 64], bool);

impl TryRng for FixedZ {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("sign must use fill_bytes")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("sign must use fill_bytes")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert!(!self.1, "sign drew randomness twice");
        assert_eq!(dst.len(), 64, "sign drew {} bytes", dst.len());
        self.1 = true;
        dst.copy_from_slice(&self.0);
        Ok(())
    }
}
impl TryCryptoRng for FixedZ {}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0, "odd hex: {s}");
    (0..b.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn enhex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn a32(v: Vec<u8>) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}
fn a64(v: Vec<u8>) -> [u8; 64] {
    v.try_into().expect("64 bytes")
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        match f[0] {
            "S" => {
                let sk = X25519SecretKey::from_bytes(a32(unhex(f[1])));
                let mut rng = FixedZ(a64(unhex(f[2])), false);
                let msg = unhex(f[3]);
                let sig = xeddsa::sign(&sk, &msg, &mut rng);
                writeln!(
                    out,
                    "S {} {}",
                    enhex(&sig),
                    enhex(sk.public_key().as_bytes())
                )
                .unwrap();
            }
            "V" => {
                let pk = X25519PublicKey::from_bytes(a32(unhex(f[1])));
                let msg = unhex(f[2]);
                let sig = a64(unhex(f[3]));
                let ok = xeddsa::verify(&pk, &msg, &sig).is_ok();
                writeln!(out, "V {}", if ok { "ACCEPT" } else { "REJECT" }).unwrap();
            }
            other => panic!("bad command {other}"),
        }
        out.flush().unwrap();
    }
}
