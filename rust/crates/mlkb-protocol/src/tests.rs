//! The protocol, end to end (spec M1 §C, §D, parent §4, §6.3, §8.1).
//!
//! These are behaviour tests, not unit tests: every one of them runs a real
//! PQXDH handshake between two parties with real keys, and drives real frames
//! between them. A test that passes here is a statement that two independent
//! ends of this protocol agree.
//!
//! The list is the one the M1 §D specification implies, plus the two defects
//! the Python implementation actually shipped:
//!
//! | test | what it pins |
//! |---|---|
//! | `c1_*` | the handshake, both `ikm` arities (M1 §C.1) |
//! | `d2_*`, `d3_*` | the hybrid ratchet and its message (M1 §D.2, §D.3) |
//! | `d4_*` | the skipped-key store, both bounds, no eviction (M1 §D.4) |
//! | `d7_*` | the audit's D7 defect: a failed open must not spend a cached key |
//! | `a1_*`, `a3_*` | the frame MAC ordering and the epoch rule (M1 §A) |
//! | `c4_*`, `s63_*` | replay, floor and first contact (M1 §C.4, parent §6.3) |

#![allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use alloc::vec::Vec;

use mlkb_secrets::ProtocolError;
use mlkb_wire::{Frame, IdentityId, MAX_FRAME_PAYLOAD, PrekeyBundleV2};

use crate::testkit::{DetRng, MisdirectedKemEntropy, OPK_ID, Party, TestEntropy};
use crate::{
    Event, HandshakeGuard, MAX_SKIP_PER_CHAIN, MAX_SKIPPED_KEYS_PER_SESSION, Plan, Role, Session,
    initiate, respond, verify_bundle,
};

const ALICE_DEVICE: u32 = 1;
const BOB_DEVICE: u32 = 2;
const FIRST_SEQ: u64 = 7;

// ---------------------------------------------------------------------------
// scaffolding
// ---------------------------------------------------------------------------

/// Two parties and the bundle one of them published.
struct World {
    alice: Party,
    bob: Party,
    bundle: PrekeyBundleV2,
    with_opk: bool,
}

fn world(with_opk: bool) -> World {
    let mut rng = DetRng::new(0x5eed_0000_0001);
    let alice = Party::generate(&mut rng, ALICE_DEVICE);
    let bob = Party::generate(&mut rng, BOB_DEVICE);
    let bundle = bob.bundle(&mut rng, with_opk);
    World {
        alice,
        bob,
        bundle,
        with_opk,
    }
}

impl World {
    /// One handshake, from `initiate` through `respond`, with the initiator's
    /// entropy seeded by `seed` so that a second run with the same seed
    /// produces a byte-identical `SK`.
    fn handshake(&self, seed: u64) -> (Session, Session) {
        let mut entropy = TestEntropy::new(seed);
        let initiated = initiate(
            &self.alice.identity(),
            &self.bundle,
            self.bob.device_id,
            FIRST_SEQ,
            &mut entropy,
        )
        .expect("the handshake completes");
        let accepted = self.accept(&initiated.initial.to_wire());
        (initiated.session, accepted)
    }

    fn accept(&self, wire: &[u8]) -> Session {
        respond(&self.bob.identity(), &self.bob.prekeys(self.with_opk), wire)
            .expect("the responder accepts")
            .complete()
            .expect("one whole frame")
            .session
    }
}

fn seal<E: crate::Entropy>(session: &mut Session, entropy: &mut E, plaintext: &[u8]) -> Vec<u8> {
    session
        .send(plaintext, entropy)
        .expect("sealing succeeds")
        .to_wire()
}

/// `decode_frame` then `classify` — everything that happens before the single
/// mutation point (parent §8.1).
fn plan(session: &Session, wire: &[u8]) -> Result<Plan, ProtocolError> {
    let frame: Frame = session
        .decode_frame(wire)?
        .complete()
        .ok_or(ProtocolError::Malformed)?;
    session.classify(&frame)
}

fn open(session: Session, wire: &[u8]) -> (Session, Vec<Event>) {
    let plan = plan(&session, wire).expect("the frame is acceptable");
    session.apply(plan)
}

fn delivered(events: &[Event]) -> Option<&[u8]> {
    events.iter().find_map(|e| match e {
        Event::MessageReceived(pt) => Some(pt.as_bytes()),
        _ => None,
    })
}

fn open_failed(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::OpenFailed))
}

/// Seals `0 ..= max(wanted)` messages and returns only the wires named.
fn seal_indices(
    session: &mut Session,
    entropy: &mut TestEntropy,
    wanted: &[u64],
) -> Vec<(u64, Vec<u8>)> {
    let max = *wanted.iter().max().expect("at least one index");
    let mut out = Vec::new();
    for i in 0..=max {
        let wire = seal(session, entropy, b"filler");
        if wanted.contains(&i) {
            out.push((i, wire));
        }
    }
    out
}

fn wire_for(wires: &[(u64, Vec<u8>)], index: u64) -> &[u8] {
    &wires
        .iter()
        .find(|(i, _)| *i == index)
        .expect("that index was kept")
        .1
}

// ---------------------------------------------------------------------------
// C.1 — PQXDH
// ---------------------------------------------------------------------------

/// Both ends of one handshake derive the same `SK`.
///
/// `SK` never leaves `mlkb_crypto::RootKey`, deliberately — there is no
/// accessor and no `Clone` (parent §4.1). The observable consequence of
/// agreement is that both ends derive the same `session_id`, which is
/// `HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)`: equality there is equality of
/// `SK` short of a preimage on HKDF-SHA256. Message delivery in both
/// directions, below, is the other half of the same statement.
#[test]
fn c1_both_ends_derive_the_same_root_key_with_an_opk() {
    let world = world(true);
    let (alice, bob) = world.handshake(0x1111);
    assert_eq!(alice.session_id(), bob.session_id());
    assert_eq!(alice.role(), Role::Initiator);
    assert_eq!(bob.role(), Role::Responder);
    assert_eq!(alice.local(), bob.remote());
    assert_eq!(alice.remote(), bob.local());
}

/// The same, on the last-resort path where `DH4` is **omitted** from the `ikm`
/// rather than zero-filled (M1 §C.1).
#[test]
fn c1_both_ends_derive_the_same_root_key_without_an_opk() {
    let world = world(false);
    let (alice, bob) = world.handshake(0x2222);
    assert_eq!(alice.session_id(), bob.session_id());
}

/// The two arities are different key schedules, so the two runs are different
/// sessions even though every other input matches.
#[test]
fn c1_the_opk_and_no_opk_paths_are_different_sessions() {
    let (with, _) = world(true).handshake(0x3333);
    let (without, _) = world(false).handshake(0x3333);
    assert_ne!(with.session_id(), without.session_id());
}

/// Parent §4.3: every signature in a bundle verifies before any key in it is
/// used. A tampered signed prekey is refused, and `initiate` refuses it at the
/// same point.
#[test]
fn c1_a_bundle_with_a_broken_signature_is_refused_before_any_key_is_used() {
    let world = world(true);
    let mut tampered = world.bundle.clone();
    tampered.signed_prekey.public[0] ^= 1;

    assert_eq!(
        verify_bundle(&tampered),
        Err(ProtocolError::Unauthenticated)
    );
    assert_eq!(
        initiate(
            &world.alice.identity(),
            &tampered,
            world.bob.device_id,
            FIRST_SEQ,
            &mut TestEntropy::new(0x4444),
        )
        .err(),
        Some(ProtocolError::Unauthenticated)
    );

    // And the PQ prekey, under its own M1 §E.2 context.
    let mut tampered = world.bundle.clone();
    tampered.pq_prekey.id ^= 1;
    assert_eq!(
        verify_bundle(&tampered),
        Err(ProtocolError::Unauthenticated)
    );
}

/// M1 §C.3: a responder refuses a handshake naming a device, a prekey or a
/// one-time prekey it does not hold.
#[test]
fn c3_a_responder_refuses_selectors_it_does_not_hold() {
    let world = world(true);
    let mut entropy = TestEntropy::new(0x5555);
    let good = initiate(
        &world.alice.identity(),
        &world.bundle,
        world.bob.device_id,
        FIRST_SEQ,
        &mut entropy,
    )
    .expect("the handshake completes")
    .initial
    .to_wire();

    // The right device accepts it.
    assert!(respond(&world.bob.identity(), &world.bob.prekeys(true), &good).is_ok());

    // A responder that believes it is another device does not.
    let mut prekeys = world.bob.prekeys(true);
    prekeys.device_id = BOB_DEVICE + 1;
    assert_eq!(
        respond(&world.bob.identity(), &prekeys, &good).err(),
        Some(ProtocolError::Malformed)
    );

    // M1 §C.1: the arity of the `ikm` follows `opk_id` exactly, so a responder
    // holding a *different* one-time prekey id refuses rather than silently
    // dropping DH4.
    let mut prekeys = world.bob.prekeys(true);
    prekeys.opk = Some((OPK_ID + 1, prekeys.opk.expect("a fixture opk").1));
    assert_eq!(
        respond(&world.bob.identity(), &prekeys, &good).err(),
        Some(ProtocolError::Malformed)
    );
}

/// Parent §4.2 and M1 §A.1: a handshake frame whose payload has been altered
/// fails, and it fails on the frame MAC — the confirmation tag never gets a
/// chance to be an oracle.
#[test]
fn a1_a_tampered_handshake_frame_is_refused() {
    let world = world(true);
    let mut entropy = TestEntropy::new(0x6666);
    let mut wire = initiate(
        &world.alice.identity(),
        &world.bundle,
        world.bob.device_id,
        FIRST_SEQ,
        &mut entropy,
    )
    .expect("the handshake completes")
    .initial
    .to_wire();

    // A byte inside the `confirm` field, which the M1 §C.3 key ordering puts
    // first in the payload: the message still parses, `SK` is unchanged
    // because `confirm` is not one of its inputs, and the M1 §A.1 frame MAC is
    // what refuses it — before the parent §4.2 tag is ever compared.
    wire[25] ^= 0x40;
    assert_eq!(
        respond(&world.bob.identity(), &world.bob.prekeys(true), &wire).err(),
        Some(ProtocolError::Unauthenticated)
    );
}

/// A short buffer is `NeedMore`, not an error (parent §8.4, M1 §A.1 rule 3).
#[test]
fn a1_a_partial_handshake_frame_is_need_more_not_an_error() {
    let world = world(true);
    let mut entropy = TestEntropy::new(0x7777);
    let wire = initiate(
        &world.alice.identity(),
        &world.bundle,
        world.bob.device_id,
        FIRST_SEQ,
        &mut entropy,
    )
    .expect("the handshake completes")
    .initial
    .to_wire();

    for cut in [0usize, 1, 14, wire.len() - 1] {
        let partial = &wire[..cut];
        assert!(
            respond(&world.bob.identity(), &world.bob.prekeys(true), partial)
                .expect("incompleteness is not an error")
                .is_need_more(),
            "a {cut}-byte prefix must be NeedMore"
        );
    }
}

// ---------------------------------------------------------------------------
// D.2 / D.3 — the hybrid ratchet
// ---------------------------------------------------------------------------

/// A message in each direction, and the epoch bookkeeping of M1 §A.3.
#[test]
fn d2_a_message_round_trips_in_both_directions() {
    let world = world(true);
    let (mut alice, bob) = world.handshake(0x1001);
    let mut ea = TestEntropy::new(0xaaa1);
    let mut eb = TestEntropy::new(0xbbb1);

    // The initiator necessarily speaks first: `InitialMessageV2` carries no
    // ML-KEM encapsulation key for it, so the responder has nothing to
    // encapsulate to until it has received one message (M1 §C.3, §D.2).
    assert!(alice.ratchet_due());
    let wire = seal(&mut alice, &mut ea, b"hello from A");
    assert_eq!(alice.send_epoch(), 1);

    let (mut bob, events) = open(bob, &wire);
    assert_eq!(delivered(&events), Some(&b"hello from A"[..]));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::RatchetAdvanced { generation: 1 }))
    );
    assert_eq!(bob.recv_generation(), 1);

    let wire = seal(&mut bob, &mut eb, b"hello from B");
    assert_eq!(bob.send_epoch(), 1);
    let (alice, events) = open(alice, &wire);
    assert_eq!(delivered(&events), Some(&b"hello from B"[..]));
    assert_eq!(alice.recv_generation(), 1);
}

/// A conversation across several ratchet steps: every turn of the
/// back-and-forth performs a fresh root step, and every message decrypts.
#[test]
fn d2_a_conversation_crosses_several_ratchet_steps() {
    let world = world(true);
    let (mut alice, mut bob) = world.handshake(0x1002);
    let mut ea = TestEntropy::new(0xaaa2);
    let mut eb = TestEntropy::new(0xbbb2);

    for turn in 0..6u8 {
        // Two messages each way per turn: the first opens a chain, the second
        // continues it.
        for msg in 0..2u8 {
            let wire = seal(&mut alice, &mut ea, &[b'A', turn, msg]);
            let (next, events) = open(bob, &wire);
            bob = next;
            assert_eq!(delivered(&events), Some(&[b'A', turn, msg][..]));
        }
        for msg in 0..2u8 {
            let wire = seal(&mut bob, &mut eb, &[b'B', turn, msg]);
            let (next, events) = open(alice, &wire);
            alice = next;
            assert_eq!(delivered(&events), Some(&[b'B', turn, msg][..]));
        }
    }

    // Six turns, one sending root step each (M1 §A.3: the epoch is the sending
    // chain's DH-ratchet generation, constant within a chain).
    assert_eq!(alice.send_epoch(), 6);
    assert_eq!(bob.send_epoch(), 6);
    assert_eq!(alice.recv_generation(), 6);
    assert_eq!(bob.recv_generation(), 6);
    assert_eq!(alice.skipped_keys(), 0);
    assert_eq!(bob.skipped_keys(), 0);
}

/// Out-of-order delivery inside one chain: the keys for the gap are derived
/// and filed, and the late messages decrypt from the store (M1 §D.4).
#[test]
fn d4_out_of_order_delivery_inside_a_chain() {
    let world = world(true);
    let (mut alice, mut bob) = world.handshake(0x1003);
    let mut ea = TestEntropy::new(0xaaa3);

    let wires: Vec<Vec<u8>> = (0..5u8)
        .map(|i| seal(&mut alice, &mut ea, &[b'm', i]))
        .collect();

    // 0, then 4 — three keys filed.
    let (next, events) = open(bob, &wires[0]);
    bob = next;
    assert_eq!(delivered(&events), Some(&b"m\x00"[..]));
    let (next, events) = open(bob, &wires[4]);
    bob = next;
    assert_eq!(delivered(&events), Some(&b"m\x04"[..]));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::KeysSkipped { count: 3 }))
    );
    assert_eq!(bob.skipped_keys(), 3);

    // The three gap messages, in a third order again.
    for i in [2u8, 1, 3] {
        let (next, events) = open(bob, &wires[usize::from(i)]);
        bob = next;
        assert_eq!(delivered(&events), Some(&[b'm', i][..]));
    }
    assert_eq!(bob.skipped_keys(), 0);
}

/// Delivery across a ratchet boundary, and a genuinely delayed message that
/// still decrypts after the receiver has moved on (M1 §D.4,
/// `RETAINED_RECV_CHAINS`).
#[test]
fn d4_a_delayed_message_decrypts_after_the_receiver_has_moved_on() {
    let world = world(true);
    let (mut alice, mut bob) = world.handshake(0x1004);
    let mut ea = TestEntropy::new(0xaaa4);
    let mut eb = TestEntropy::new(0xbbb4);

    // Chain 1: three messages, of which the middle one is lost in flight.
    let first = seal(&mut alice, &mut ea, b"c1-0");
    let delayed = seal(&mut alice, &mut ea, b"c1-1");
    let third = seal(&mut alice, &mut ea, b"c1-2");

    let (next, _) = open(bob, &first);
    bob = next;
    let (next, events) = open(bob, &third);
    bob = next;
    assert_eq!(delivered(&events), Some(&b"c1-2"[..]));
    assert_eq!(bob.skipped_keys(), 1);

    // Bob answers, Alice answers, and Bob's receiving chain moves to
    // generation 2 — one whole DH ratchet past the delayed message.
    let wire = seal(&mut bob, &mut eb, b"b1-0");
    let (mut alice, _) = open(alice, &wire);
    let wire = seal(&mut alice, &mut ea, b"c2-0");
    let (bob, events) = open(bob, &wire);
    assert_eq!(delivered(&events), Some(&b"c2-0"[..]));
    assert_eq!(bob.recv_generation(), 2);
    assert_eq!(bob.skipped_keys(), 1, "the retained chain keeps its key");

    // The delayed message finally arrives.
    let (bob, events) = open(bob, &delayed);
    assert_eq!(delivered(&events), Some(&b"c1-1"[..]));
    assert_eq!(bob.skipped_keys(), 0);
}

/// The far side of the same rule: a chain older than `RETAINED_RECV_CHAINS`
/// generations is pruned, and a message from it is refused rather than
/// silently accepted under some other key.
#[test]
fn d4_a_chain_older_than_the_retention_window_is_pruned() {
    let world = world(true);
    let (mut alice, mut bob) = world.handshake(0x1005);
    let mut ea = TestEntropy::new(0xaaa5);
    let mut eb = TestEntropy::new(0xbbb5);

    let first = seal(&mut alice, &mut ea, b"c1-0");
    let delayed = seal(&mut alice, &mut ea, b"c1-1");
    let third = seal(&mut alice, &mut ea, b"c1-2");
    let (next, _) = open(bob, &first);
    bob = next;
    let (next, _) = open(bob, &third);
    bob = next;
    assert_eq!(bob.skipped_keys(), 1);

    // Two more full turns: Bob's receiving chain reaches generation 3.
    for _ in 0..2 {
        let wire = seal(&mut bob, &mut eb, b"b");
        let (next, _) = open(alice, &wire);
        alice = next;
        let wire = seal(&mut alice, &mut ea, b"a");
        let (next, _) = open(bob, &wire);
        bob = next;
    }
    assert_eq!(bob.recv_generation(), 3);
    assert_eq!(bob.skipped_keys(), 0, "generation 1 aged out");

    assert_eq!(
        plan(&bob, &delayed).err(),
        Some(ProtocolError::ReplayDetected)
    );
}

/// M1 §D.3 puts `"ek"`/`"kc"` on the `n == 0` message of each chain and
/// nowhere else, so a *later* message of a chain that has not been opened yet
/// cannot be processed. It is refused by `classify` — which cannot mutate — so
/// the caller may hold the frame and re-offer it once its `n == 0` sibling
/// arrives. This test does exactly that.
#[test]
fn a3_a_new_chain_cannot_be_entered_out_of_order() {
    let world = world(true);
    let (mut alice, bob) = world.handshake(0x1006);
    let mut ea = TestEntropy::new(0xaaa6);
    let mut eb = TestEntropy::new(0xbbb6);

    let wire = seal(&mut alice, &mut ea, b"c1-0");
    let (mut bob, _) = open(bob, &wire);

    // A full turn, so that Alice's next send opens generation 2.
    let reply = seal(&mut bob, &mut eb, b"b1-0");
    let (mut alice, _) = open(alice, &reply);
    let opener = seal(&mut alice, &mut ea, b"c2-0");
    let follower = seal(&mut alice, &mut ea, b"c2-1");

    // The follower arrives first. Nothing moves.
    let before = (bob.recv_generation(), bob.skipped_keys());
    assert_eq!(plan(&bob, &follower).err(), Some(ProtocolError::Malformed));
    assert_eq!((bob.recv_generation(), bob.skipped_keys()), before);

    // Re-offered after its sibling, the very same bytes are accepted.
    let (bob, events) = open(bob, &opener);
    assert_eq!(delivered(&events), Some(&b"c2-0"[..]));
    let (bob, events) = open(bob, &follower);
    assert_eq!(delivered(&events), Some(&b"c2-1"[..]));
    assert_eq!(bob.recv_generation(), 2);
}

// ---------------------------------------------------------------------------
// D.4 — the bounds
// ---------------------------------------------------------------------------

/// `MAX_SKIP_PER_CHAIN` refuses the **new** message and preserves every cached
/// key (M1 §D.4).
#[test]
fn d4_the_per_chain_bound_refuses_the_new_message_and_keeps_the_cache() {
    let world = world(true);
    let (mut alice, mut bob) = world.handshake(0x1007);
    let mut ea = TestEntropy::new(0xaaa7);

    // After index 3, `Nr == 4`, so this index needs `MAX_SKIP_PER_CHAIN + 1`
    // new keys — one past the bound, and not two, so that the test fails if
    // the comparison is off by one in either direction.
    let over = 4 + MAX_SKIP_PER_CHAIN + 1;
    let wires = seal_indices(&mut alice, &mut ea, &[0, 1, 3, over - 1, over]);

    let (next, _) = open(bob, wire_for(&wires, 0));
    bob = next;
    // Two keys filed: indices 1 and 2.
    let (next, _) = open(bob, wire_for(&wires, 3));
    bob = next;
    assert_eq!(bob.skipped_keys(), 2);

    // A message needing `MAX_SKIP_PER_CHAIN + 1` new keys is refused, and the
    // refusal happens in `classify` — before a single key is derived.
    assert_eq!(
        plan(&bob, wire_for(&wires, over)).err(),
        Some(ProtocolError::SkippedKeyLimit)
    );
    assert_eq!(bob.skipped_keys(), 2, "no cached key was evicted");
    // Exactly `MAX_SKIP_PER_CHAIN` is still inside the bound, so the rejection
    // above is the bound and not an arithmetic accident.
    assert!(plan(&bob, wire_for(&wires, over - 1)).is_ok());
    assert_eq!(bob.skipped_keys(), 2, "classify cannot mutate");

    // And the cache still works.
    let (bob, events) = open(bob, wire_for(&wires, 1));
    assert!(delivered(&events).is_some());
    assert_eq!(bob.skipped_keys(), 1);
}

/// `MAX_SKIPPED_KEYS_PER_SESSION` is the other bound, and it binds even when
/// each individual catch-up is inside the per-chain bound (M1 §D.4).
#[test]
fn d4_the_per_session_bound_refuses_the_new_message() {
    let world = world(true);
    let (mut alice, mut bob) = world.handshake(0x1008);
    let mut ea = TestEntropy::new(0xaaa8);

    // Three catch-ups of ~1000 each: the first two fit, the third would take
    // the store past 2000.
    let a = MAX_SKIP_PER_CHAIN - 1; // 999
    let b = a * 2; // 1998
    let c = b + 200; // a 200-key catch-up, well inside the per-chain bound
    let wires = seal_indices(&mut alice, &mut ea, &[0, a, b, c]);

    let (next, _) = open(bob, wire_for(&wires, 0));
    bob = next;
    let (next, _) = open(bob, wire_for(&wires, a));
    bob = next;
    let (next, _) = open(bob, wire_for(&wires, b));
    bob = next;

    let held = bob.skipped_keys();
    assert!(held > MAX_SKIPPED_KEYS_PER_SESSION - 300, "held {held}");
    assert!(held <= MAX_SKIPPED_KEYS_PER_SESSION);

    assert_eq!(
        plan(&bob, wire_for(&wires, c)).err(),
        Some(ProtocolError::SkippedKeyLimit)
    );
    assert_eq!(bob.skipped_keys(), held, "no cached key was evicted");
}

// ---------------------------------------------------------------------------
// D7 — a failed open must not spend a cached key
// ---------------------------------------------------------------------------

/// The Python audit's D7 defect, at the protocol layer (M1 §D.4).
///
/// The forgery is real: two `initiate` runs from the same seed produce the same
/// `SK`, hence the same directional frame keys, so the second session can emit
/// a frame whose M1 §A.1 MAC verifies. Its ratchet is different, so its
/// ciphertext at index `(1, 1)` is sealed under a chain key the receiver does
/// not have — exactly the shape of a forgery aimed at a cached skipped key.
///
/// The cached key must survive, and the authentic message must still decrypt.
#[test]
fn d7_a_forged_ciphertext_does_not_destroy_a_cached_skipped_key() {
    let world = world(true);
    let (mut honest, bob) = world.handshake(0x1009);
    let (mut forger, _) = world.handshake(0x1009);
    let mut honest_entropy = TestEntropy::new(0xaaa9);
    let mut forger_entropy = TestEntropy::new(0xffff);

    // Same handshake, so the same frame keys.
    assert_eq!(honest.session_id(), forger.session_id());

    let m0 = seal(&mut honest, &mut honest_entropy, b"m0");
    let m1 = seal(&mut honest, &mut honest_entropy, b"m1");
    let m2 = seal(&mut honest, &mut honest_entropy, b"m2");

    // The forger runs its own ratchet from the same root.
    let _f0 = seal(&mut forger, &mut forger_entropy, b"f0");
    let f1 = seal(&mut forger, &mut forger_entropy, b"f1");

    let (bob, _) = open(bob, &m0);
    let (mut bob, _) = open(bob, &m2);
    assert_eq!(bob.skipped_keys(), 1, "the key for index 1 is cached");

    // The forged frame authenticates as a frame and routes to the cached key.
    let plan = plan(&bob, &f1).expect("the frame MAC verifies");
    let (next, events) = bob.apply(plan);
    bob = next;
    assert!(open_failed(&events), "the AEAD must refuse it");
    assert!(delivered(&events).is_none());
    assert_eq!(
        bob.skipped_keys(),
        1,
        "a failed open must not spend the cached key"
    );

    // ...and the authentic message still decrypts.
    let (bob, events) = open(bob, &m1);
    assert_eq!(delivered(&events), Some(&b"m1"[..]));
    assert_eq!(bob.skipped_keys(), 0);
}

// ---------------------------------------------------------------------------
// A.1 / replay
// ---------------------------------------------------------------------------

/// A tampered frame never reaches `classify`, let alone `apply`: the M1 §A.1
/// MAC refuses it, and no state moves (parent §8.1).
#[test]
fn a1_a_tampered_frame_does_not_advance_any_state() {
    let world = world(true);
    let (mut alice, bob) = world.handshake(0x100a);
    let mut ea = TestEntropy::new(0xaaaa);

    let good = seal(&mut alice, &mut ea, b"payload");
    let before = (bob.recv_generation(), bob.skipped_keys());

    // M1 §A.1 rule 1 refuses a wrong `version` structurally, before the MAC is
    // computed; every other byte inside the MAC preimage — the epoch, the type
    // byte, the payload, the tag — collapses to the one payload-free
    // authentication outcome parent §8.4 allows.
    let cases: [(usize, ProtocolError); 6] = [
        (0, ProtocolError::Malformed),
        (1, ProtocolError::Malformed),
        (2, ProtocolError::Unauthenticated),
        (10, ProtocolError::Unauthenticated),
        (20, ProtocolError::Unauthenticated),
        (good.len() - 1, ProtocolError::Unauthenticated),
    ];
    for (at, expected) in cases {
        let mut bad = good.clone();
        bad[at] ^= 0x01;
        assert_eq!(
            bob.decode_frame(&bad).err(),
            Some(expected),
            "a flip at byte {at} must be refused"
        );
        assert_eq!((bob.recv_generation(), bob.skipped_keys()), before);
    }

    // Truncation is `NeedMore`, not an error (parent §8.4).
    assert!(
        bob.decode_frame(&good[..good.len() - 1])
            .expect("incompleteness is not an error")
            .is_need_more()
    );
    // A trailing byte is a hard reject (M1 §A.1 rule 4).
    let mut extended = good.clone();
    extended.push(0);
    assert_eq!(
        bob.decode_frame(&extended).err(),
        Some(ProtocolError::Malformed)
    );

    // The genuine frame still works, so nothing above was consumed.
    let (bob, events) = open(bob, &good);
    assert_eq!(delivered(&events), Some(&b"payload"[..]));
    assert_eq!(bob.recv_generation(), 1);
}

/// A replayed application message is rejected, in the current chain and in a
/// retained one, and the rejection happens in `classify`.
#[test]
fn c4_a_replayed_application_message_is_rejected() {
    let world = world(true);
    let (mut alice, bob) = world.handshake(0x100b);
    let mut ea = TestEntropy::new(0xaaab);

    let m0 = seal(&mut alice, &mut ea, b"m0");
    let m1 = seal(&mut alice, &mut ea, b"m1");

    let (bob, _) = open(bob, &m0);
    let (bob, _) = open(bob, &m1);

    // The chain-opening message: replaying it must not re-run the root step.
    assert_eq!(plan(&bob, &m0).err(), Some(ProtocolError::ReplayDetected));
    assert_eq!(plan(&bob, &m1).err(), Some(ProtocolError::ReplayDetected));
    assert_eq!(bob.recv_generation(), 1);
    assert_eq!(bob.skipped_keys(), 0);
}

/// An `INITIAL` frame is not a transition of an established session: accepting
/// one would let a peer reset a live ratchet.
#[test]
fn a2_an_initial_frame_is_refused_by_an_established_session() {
    let world = world(true);
    let mut entropy = TestEntropy::new(0x100c);
    let initiated = initiate(
        &world.alice.identity(),
        &world.bundle,
        world.bob.device_id,
        FIRST_SEQ,
        &mut entropy,
    )
    .expect("the handshake completes");
    let bob = world.accept(&initiated.initial.to_wire());

    let frame = bob
        .decode_frame(&initiated.initial.to_wire())
        .expect("the frame MAC verifies")
        .complete()
        .expect("one whole frame");
    assert_eq!(bob.classify(&frame).err(), Some(ProtocolError::Malformed));
}

/// A payload-free `ACK` is accepted and moves nothing (M1 §A.2).
#[test]
fn a2_an_ack_carries_no_key_material() {
    let world = world(true);
    let (mut alice, bob) = world.handshake(0x100d);
    let mut ea = TestEntropy::new(0xaaad);
    let wire = seal(&mut alice, &mut ea, b"m0");
    let (bob, _) = open(bob, &wire);

    let ack = alice.ack().expect("an ack seals").to_wire();
    let before = (bob.recv_generation(), bob.skipped_keys());
    let (bob, events) = open(bob, &ack);
    assert!(events.iter().any(|e| matches!(e, Event::AckReceived)));
    assert_eq!((bob.recv_generation(), bob.skipped_keys()), before);
}

// ---------------------------------------------------------------------------
// C.4 / parent §6.3 — handshake replay
// ---------------------------------------------------------------------------

/// A replayed `InitialMessage` is rejected (parent §6.3).
///
/// The replay is cryptographically perfect — it *is* the original frame — so
/// the handshake itself completes again and derives the identical
/// `session_id`. That identity is what the first-contact defence is: the
/// duplicate is refused by the `session_id` set even where the floor would
/// have let it through.
#[test]
fn s63_a_replayed_initial_message_is_rejected() {
    let world = world(true);
    let mut entropy = TestEntropy::new(0x100e);
    let initiated = initiate(
        &world.alice.identity(),
        &world.bundle,
        world.bob.device_id,
        FIRST_SEQ,
        &mut entropy,
    )
    .expect("the handshake completes");
    let wire = initiated.initial.to_wire();

    let mut guard = HandshakeGuard::new(16, 16);
    let first = world.accept(&wire);
    assert_eq!(
        guard.admit(first.remote(), FIRST_SEQ, first.session_id(), 10_000, 0),
        Ok(())
    );

    // The same bytes again: a new session value, the same `session_id`.
    let replay = world.accept(&wire);
    assert_eq!(replay.session_id(), first.session_id());
    assert_eq!(
        guard.admit(replay.remote(), FIRST_SEQ, replay.session_id(), 10_000, 0),
        Err(ProtocolError::ReplayDetected)
    );

    // And with a *fresh* sequence number, so the M1 §C.4 floor would accept
    // it: the first-contact set is what refuses it.
    assert_eq!(
        guard.admit(
            replay.remote(),
            FIRST_SEQ + 1000,
            replay.session_id(),
            10_000,
            0
        ),
        Err(ProtocolError::ReplayDetected)
    );
}

/// Parent §6.3, the hole a design review found: a re-handshake must **not**
/// evict the peer's earlier `session_id` record.
#[test]
fn s63_a_rehandshake_does_not_evict_an_earlier_session_id() {
    let mut guard = HandshakeGuard::new(16, 16);
    let peer = IdentityId::from_bytes([0x42; 32]);
    let first = [0xa1; 32];
    let second = [0xb2; 32];

    assert_eq!(guard.admit(&peer, 1, first, 10_000, 0), Ok(()));
    assert_eq!(guard.admit(&peer, 2, second, 10_000, 0), Ok(()));
    // The captured first handshake, replayed with a sequence number the floor
    // accepts. Without the retained record this would go through.
    assert_eq!(
        guard.admit(&peer, 3, first, 10_000, 0),
        Err(ProtocolError::ReplayDetected)
    );
    assert_eq!(guard.peers(), 1);
    assert_eq!(guard.sessions(), 2);
}

/// M1 §C.4's corrected predicate, through the guard: no underflow for a
/// freshly admitted peer, and reordering inside the window is accepted once.
#[test]
fn c4_the_floor_does_not_underflow_for_a_fresh_peer() {
    let mut guard = HandshakeGuard::new(16, 64);
    let peer = IdentityId::from_bytes([0x07; 32]);

    // First contact at a sequence number far below the 64-bit window width.
    assert_eq!(guard.admit(&peer, 3, [0x01; 32], 10_000, 0), Ok(()));
    // Under the parent's `seq <= last_seq - 64` this would have wrapped and
    // rejected everything.
    assert_eq!(guard.admit(&peer, 4, [0x02; 32], 10_000, 0), Ok(()));
    assert_eq!(guard.admit(&peer, 1, [0x03; 32], 10_000, 0), Ok(()));
    assert_eq!(
        guard.admit(&peer, 1, [0x04; 32], 10_000, 0),
        Err(ProtocolError::ReplayDetected)
    );
}

/// An expired record is refused rather than stored, so the uniqueness property
/// cannot be silently void.
#[test]
fn s63_a_record_born_expired_is_refused() {
    let mut guard = HandshakeGuard::new(16, 16);
    let peer = IdentityId::from_bytes([0x09; 32]);
    assert_eq!(
        guard.admit(&peer, 1, [0x01; 32], 500, 500),
        Err(ProtocolError::Malformed)
    );
    assert_eq!(guard.sessions(), 0);
    assert_eq!(guard.peers(), 0, "a refused handshake allocates nothing");
}

/// Both bounds fail closed and report their own resource (parent §8.4, §6.6).
#[test]
fn s63_the_guard_fails_closed_on_capacity() {
    let mut guard = HandshakeGuard::new(1, 8);
    let first = IdentityId::from_bytes([0x01; 32]);
    let second = IdentityId::from_bytes([0x02; 32]);
    assert_eq!(guard.admit(&first, 1, [0x11; 32], 10_000, 0), Ok(()));
    assert_eq!(
        guard.admit(&second, 1, [0x22; 32], 10_000, 0),
        Err(ProtocolError::FirstContactCapacity)
    );
    // The refused peer consumed neither resource.
    assert_eq!(guard.peers(), 1);
    assert_eq!(guard.sessions(), 1);
    // ...and the admitted peer is still served.
    assert_eq!(guard.admit(&first, 2, [0x33; 32], 10_000, 0), Ok(()));
}

// ---------------------------------------------------------------------------
// §8.1 — atomicity, on both sides
// ---------------------------------------------------------------------------

/// Two sessions are equal iff, driven by identical entropy, they emit identical
/// frames for identical plaintexts.
///
/// `Session` exposes only `role`, `session_id`, `send_epoch`, `recv_generation`
/// and `skipped_keys`, and none of those would notice a wrong root key or a
/// wrong chain key. A frame is the whole hidden state under one hash: it is
/// sealed under `CK_send` (hence under `RK`), its AAD binds `Ns`, `PN` and the
/// epoch, its `dh`/`ek` are the ratchet keypairs, and the frame MAC is over all
/// of it. So byte-equality here is state-equality for everything that matters,
/// and it is the assertion this file uses whenever the claim is "nothing moved".
fn emits(session: &mut Session, seed: u64) -> Vec<Vec<u8>> {
    let mut entropy = TestEntropy::new(seed);
    (0..3u8)
        .map(|i| seal(session, &mut entropy, &[b'p', i]))
        .collect()
}

/// A `send` that fails is a `send` that never happened — including its root
/// step (spec M1 §D.2, §D.3).
///
/// `Frame::seal` refuses a payload over `MAX_FRAME_PAYLOAD`, and that check is
/// the last thing in the send path. When the root step committed first, an
/// oversized plaintext consumed the step: `send_epoch` advanced, `ratchet_due`
/// cleared, and the `RatchetStep` carrying `ek`/`kc` was dropped with the
/// frame. Every later message of that chain then went out with `n >= 1` and no
/// step, and M1 §D.3 puts `ek`/`kc` only on the `n == 0` message — so the peer
/// could never enter the chain and refused all of them, permanently.
///
/// Reverting the fix fails this test at the first assertion.
#[test]
fn s81_a_refused_send_does_not_burn_the_ratchet_step() {
    let world = world(true);
    let (mut alice, bob) = world.handshake(0x100c);
    // A byte-identical sibling that is never offered the oversized plaintext.
    let (mut twin, _) = world.handshake(0x100c);

    assert!(alice.ratchet_due(), "the first send must step");
    let oversized = alloc::vec![0u8; MAX_FRAME_PAYLOAD];
    assert_eq!(
        alice.send(&oversized, &mut TestEntropy::new(0xaaac)).err(),
        Some(ProtocolError::Malformed),
        "M1 §A.1 rule 2 refuses it"
    );

    // Nothing moved: the step is still owed, and the epoch never advanced.
    assert_eq!(
        alice.send_epoch(),
        0,
        "the root step must not have happened"
    );
    assert!(alice.ratchet_due(), "and it must still be due");
    assert_eq!(
        emits(&mut alice, 0xbbbc),
        emits(&mut twin, 0xbbbc),
        "the refused send moved hidden state"
    );

    // And the peer can still enter the chain, which is the property the
    // burnt step destroyed.
    let (mut alice, bob) = (world.handshake(0x100c).0, bob);
    assert!(
        alice
            .send(&oversized, &mut TestEntropy::new(0xaaac))
            .is_err()
    );
    let good = seal(&mut alice, &mut TestEntropy::new(0xbbbc), b"hello");
    let (bob, events) = open(bob, &good);
    assert_eq!(delivered(&events), Some(&b"hello"[..]));
    assert_eq!(bob.recv_generation(), 1);
}

/// The bound is smaller on a chain-opening message, and the send is atomic
/// there too (spec M1 §D.3, §A.1 rule 2).
///
/// `ek` and `kc` are 1568 bytes each, and they ride the `n == 0` message. So a
/// plaintext can be under `MAX_FRAME_PAYLOAD` for the rest of a chain and over
/// it for the message that opens one — which is precisely the band in which a
/// non-atomic send breaks the session rather than merely refusing a message.
#[test]
fn s81_the_frame_bound_is_tighter_on_the_message_that_opens_a_chain() {
    let world = world(true);
    let (mut alice, bob) = world.handshake(0x100d);

    // Big enough that the 3136 bytes of `ek` + `kc` push it over the bound,
    // small enough that it fits without them.
    let payload = alloc::vec![0x5a_u8; MAX_FRAME_PAYLOAD - 2048];

    assert!(alice.ratchet_due());
    assert_eq!(
        alice.send(&payload, &mut TestEntropy::new(0xaaad)).err(),
        Some(ProtocolError::Malformed),
        "ek + kc take it over the bound"
    );
    assert!(alice.ratchet_due(), "the step is still owed");

    // Open the chain with a small message, then the same payload fits.
    let mut ea = TestEntropy::new(0xbbbd);
    let opener = seal(&mut alice, &mut ea, b"opener");
    let (bob, events) = open(bob, &opener);
    assert_eq!(delivered(&events), Some(&b"opener"[..]));

    let big = seal(&mut alice, &mut ea, &payload);
    let (bob, events) = open(bob, &big);
    assert_eq!(
        delivered(&events),
        Some(&payload[..]),
        "the same payload fits once the chain is open"
    );
    assert_eq!(bob.recv_generation(), 1);
}

/// **The §8.1 residue, closed.** A MAC-valid frame that opens a new receiving
/// chain but does not decrypt must leave the receiver exactly where it was.
///
/// The forgery is real. Two `initiate` runs from the same seed share `SK`,
/// hence the directional frame keys, so the forger's frames pass the M1 §A.1
/// MAC. `MisdirectedKemEntropy` then makes its `kc` encapsulate to a decoy, so
/// the receiver's decapsulation yields a different shared secret and the root
/// step it would take is not the one the sender took — a well-formed,
/// authenticated-as-a-frame, undecryptable chain opener.
///
/// Before the fix, `classify` could not derive the prospective chain key from
/// `&self` (`RootKey::ratchet` consumes, `RootKey` is not `Clone`), so the root
/// step ran in `apply` and this frame cost the receiver its session:
/// `RatchetAdvanced` + `OpenFailed`, `recv_generation` advanced, and every
/// later genuine message refused forever. `RootKey::ratchet_preview` moves the
/// AEAD ahead of the commit.
///
/// The assertion is the strong one: byte-identity against a twin that never
/// saw the forgery, *and* the genuine peer's next message still decrypts.
#[test]
fn s81_a_mac_valid_new_chain_forgery_leaves_the_receiver_byte_identical() {
    let world = world(true);
    let (mut alice, bob_target) = world.handshake(0x100e);
    let (mut alice_twin, bob_clean) = world.handshake(0x100e);
    // Same handshake seed => same `SK` => the same frame keys.
    let (mut forger, _) = world.handshake(0x100e);
    assert_eq!(alice.session_id(), forger.session_id());

    // A conversation, driven identically on all three copies so the two
    // receivers stay byte-identical to each other and the forger stays in step.
    let m0_target = seal(&mut alice, &mut TestEntropy::new(0xaaae), b"m0");
    let m0_clean = seal(&mut alice_twin, &mut TestEntropy::new(0xaaae), b"m0");
    let m0_forger = seal(&mut forger, &mut TestEntropy::new(0xaaae), b"m0");
    assert_eq!(m0_target, m0_clean, "the two runs start identical");
    assert_eq!(m0_target, m0_forger);
    let (mut bob_target, _) = open(bob_target, &m0_target);
    let (mut bob_clean, _) = open(bob_clean, &m0_clean);

    // Bob answers on both copies; Alice takes the reply and is now owed a step.
    let r0_target = seal(&mut bob_target, &mut TestEntropy::new(0xbbbe), b"r0");
    let r0_clean = seal(&mut bob_clean, &mut TestEntropy::new(0xbbbe), b"r0");
    assert_eq!(r0_target, r0_clean);
    let (alice, _) = open(alice, &r0_target);
    let (alice_twin, _) = open(alice_twin, &r0_clean);
    let (forger, _) = open(forger, &r0_target);
    let (mut alice, mut alice_twin, mut forger) = (alice, alice_twin, forger);

    // The forger is owed a step exactly as Alice is, so it emits at the epoch
    // Bob is expecting next. It diverges in one place: its `kc` encapsulates to
    // a decoy, so Bob's decapsulation — and therefore Bob's root step — is not
    // the one the forger took, and the AEAD must refuse. The frame MAC still
    // verifies, because `K_frame_dir` comes from `SK` and never ratchets.
    let forgery = seal(
        &mut forger,
        &mut MisdirectedKemEntropy::new(0xffff),
        b"forged-chain-opener",
    );

    // It is a valid *frame*, and `classify` gets as far as the root step — and
    // then refuses it, without a `Plan` ever existing.
    assert!(
        bob_target.decode_frame(&forgery).is_ok(),
        "the frame MAC verifies; that is the whole point"
    );
    assert_eq!(
        plan(&bob_target, &forgery).err(),
        Some(ProtocolError::Unauthenticated),
        "a chain opener that does not decrypt must be refused in classify"
    );
    assert_eq!(
        bob_target.recv_generation(),
        1,
        "the root step must not have happened"
    );

    // Byte-identical to a twin that never saw the forgery...
    assert_eq!(
        emits(&mut bob_target, 0xccce),
        emits(&mut bob_clean, 0xccce),
        "the forgery moved hidden state"
    );

    // ...and — the property the desync destroyed — the real peer's next
    // message still opens. Both receivers have since sent, so drive the two
    // senders identically and check both.
    let g_target = seal(&mut alice, &mut TestEntropy::new(0xddde), b"genuine");
    let g_clean = seal(&mut alice_twin, &mut TestEntropy::new(0xddde), b"genuine");
    assert_eq!(g_target, g_clean);
    let (bob_target, events_target) = open(bob_target, &g_target);
    let (bob_clean, events_clean) = open(bob_clean, &g_clean);
    assert_eq!(delivered(&events_target), Some(&b"genuine"[..]));
    assert_eq!(delivered(&events_clean), Some(&b"genuine"[..]));
    assert_eq!(
        bob_target.recv_generation(),
        bob_clean.recv_generation(),
        "the two receivers ended in the same generation"
    );
}
