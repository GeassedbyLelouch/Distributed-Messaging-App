//! The randomness boundary (spec M1 §G.2, §I.3, parent §11 gate 6).
//!
//! Parent §11 gate 6 forbids this crate a clock, an RNG and a global. M1 §G.2
//! resolves the resulting conflict for the AEAD nonce by *injecting* it, and
//! §I.3 records that the injection point is `mlkb-session` and that it is the
//! sole remaining defence against nonce reuse.
//!
//! The ratchet needs three more random things than a nonce — a fresh X25519
//! keypair, a fresh ML-KEM-1024 keypair, and an ML-KEM encapsulation — so
//! injecting bare values one call at a time would put the *choice of what to
//! encapsulate to* in the caller's hands. [`Entropy`] is the same injection
//! done once: the caller supplies the source, this crate decides what is drawn
//! and, critically, **which key an encapsulation targets**.

use mlkb_crypto::{
    KemCiphertext, KemDecapsulationKey, KemEncapsulationKey, KemSharedSecret, X25519SecretKey,
};
use mlkb_secrets::Nonce192;

/// The randomness `mlkb-protocol` draws, supplied from outside
/// (spec M1 §G.2, §I.3).
///
/// # The obligation this trait carries
///
/// Every method must be backed by the platform CSPRNG. M1 §I.3 states the
/// residual plainly and it applies here unchanged: `CryptoRng` is a safe
/// marker trait, a constant-output "RNG" repeats nonces, and under
/// XChaCha20-Poly1305 a repeated `(key, nonce)` pair is keystream reuse plus
/// Poly1305 one-time-key recovery. The key half of that pair cannot be
/// defended — M1 §G.3 requires `ChainKey: Clone`, so two byte-identical
/// [`mlkb_crypto::MessageKey`]s can always exist — so the whole property rests
/// on this trait's implementer.
///
/// `mlkb-testkit`'s deterministic implementation exists for KATs and fuzzing
/// and **must never be reachable from a production constructor** (M1 §I.3).
///
/// # Why `encapsulate` is here and not a caller-supplied value
///
/// [`KemEncapsulationKey::encapsulate`] needs an RNG, so it cannot be called
/// from this crate directly. Taking a caller-minted `(KemCiphertext,
/// KemSharedSecret)` pair instead would let a caller encapsulate to a key of
/// its own choosing while this crate believed it had targeted the peer's — the
/// PQ leg would still be structurally present (parent §4.1) but would no
/// longer bind the peer. Passing the *target* down and receiving the pair back
/// keeps that decision inside the state machine.
pub trait Entropy {
    /// A fresh X25519 secret key, for a DH ratchet step (spec M1 §D.2) or for
    /// the initiator's PQXDH ephemeral (spec M1 §C.1).
    fn x25519_secret(&mut self) -> X25519SecretKey;

    /// A fresh ML-KEM-1024 keypair, published as `"ek"` on the next
    /// chain-opening message (spec M1 §D.3).
    fn kem_keypair(&mut self) -> KemDecapsulationKey;

    /// A fresh 192-bit AEAD nonce (spec parent §5.1, M1 §G.2).
    fn nonce(&mut self) -> Nonce192;

    /// One ML-KEM-1024 encapsulation to `to` (spec M1 §D.2).
    fn encapsulate(&mut self, to: &KemEncapsulationKey) -> (KemCiphertext, KemSharedSecret);
}
