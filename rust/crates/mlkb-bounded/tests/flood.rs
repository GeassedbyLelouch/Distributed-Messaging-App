//! Parent spec §11 gate 5 — flood tests, mandatory for every bounded resource.
//!
//! Each test has the same three-part shape the gate demands, and each part is
//! labelled, because the missing halves are precisely why the Python rounds
//! oscillated between fail-open and fail-closed (parent spec §6):
//!
//! - **(a)** fill / overflow the resource;
//! - **(b)** assert the ORIGINAL attack is STILL rejected — the fail-open
//!   failure mode, where a flood evicts the victim's record and reinstates the
//!   replay the record existed to stop;
//! - **(c)** assert an honest peer is STILL served — the fail-closed failure
//!   mode, where a flood locks the victim out.
//!
//! For [`PartitionedPool`] the gate's assertion is parent §6.6's containment
//! property: flooding Unknown to capacity leaves an Established entry fully
//! functional.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use mlkb_bounded::{
    BoundedMap, ExpiringSet, PartitionedPool, PeerClass, Promotion, ProtocolError, ReplayWindow,
    UNKNOWN_ENTRY_TTL_MS, UNKNOWN_POOL_CAPACITY,
};

/// The volume of attacker traffic every flood test uses. Far past every bound
/// in this crate, so "overflow" is never in question.
const FLOOD: u64 = 100_000;

/// What a serverless caller names its own Established bound. Parent §8.4 makes
/// the overflow error the owner's choice; the only way this pool grows is the
/// local user accepting a first contact.
const EST_FULL: ProtocolError = ProtocolError::FirstContactCapacity;

// ---------------------------------------------------------------------------
// §6.4 row 1 — handshake replay floor (tier 1, unforgeable-small state).
// ---------------------------------------------------------------------------

/// A flood cannot make the window forget: its state is two `u64`s, so there is
/// nothing for an attacker to grow and no eviction policy to trigger.
#[test]
fn replay_window_flood() {
    let captured_seq = 5u64; // what the attacker recorded off the wire
    let mut w = ReplayWindow::new(0);
    assert_eq!(w.check_and_update(captured_seq), Ok(()));

    // (a) FLOOD: the admitted peer's counter is driven as far as it will go.
    for seq in 6..=FLOOD {
        assert_eq!(w.check_and_update(seq), Ok(()), "seq {seq}");
    }
    assert_eq!(
        core::mem::size_of::<ReplayWindow>(),
        16,
        "state must not grow with input: O(1) per peer, not per message"
    );

    // (b) The ORIGINAL attack — replaying the captured handshake — is STILL
    //     rejected. Under an evicting design the flood would have aged the
    //     record out and this would now succeed.
    assert_eq!(
        w.check_and_update(captured_seq),
        Err(ProtocolError::ReplayDetected)
    );

    // (c) The HONEST peer is STILL served. Its next messages arrive out of
    //     order: FLOOD+41 first, then the delayed FLOOD+20 from inside the
    //     window. Both go through, and each exactly once.
    assert_eq!(w.check_and_update(FLOOD + 41), Ok(()));
    let delayed = FLOOD + 20;
    assert_eq!(w.check_and_update(delayed), Ok(()), "in-window reorder");
    assert_eq!(
        w.check_and_update(delayed),
        Err(ProtocolError::ReplayDetected),
        "and it is single-use"
    );
}

/// The same, for a peer flooded with *far-future* sequence numbers rather than
/// contiguous ones: the window resets, but never to a state that accepts a
/// replay from below the new floor.
#[test]
fn replay_window_flood_with_far_future_jumps() {
    let mut w = ReplayWindow::new(0);
    let captured_seq = 3u64;
    assert_eq!(w.check_and_update(captured_seq), Ok(()));

    // (a) FLOOD with sparse, far-apart values.
    for i in 1..=FLOOD {
        assert_eq!(w.check_and_update(i * 1_000), Ok(()));
    }

    // (b) ORIGINAL attack still rejected.
    assert_eq!(
        w.check_and_update(captured_seq),
        Err(ProtocolError::ReplayDetected)
    );
    // (c) Honest peer still served.
    assert_eq!(w.check_and_update(FLOOD * 1_000 + 1), Ok(()));
}

// ---------------------------------------------------------------------------
// §6.4 row 3 / M1 §D.4 — skipped message keys (fail closed, never evict).
// ---------------------------------------------------------------------------

/// The bound is per authenticated session, so the "attacker" here is traffic
/// inside one session. Overflow must refuse the NEW entry and leave every
/// cached key intact — evicting one silently destroys an authentic delayed
/// message (spec M1 §D.4).
#[test]
fn bounded_map_flood() {
    const CAP: usize = 2_000; // MAX_SKIPPED_KEYS_PER_SESSION shape
    let mut m: BoundedMap<u64, u64> = BoundedMap::new(CAP, ProtocolError::SkippedKeyLimit);

    // An honest, delayed message key is cached first — this is the record a
    // fail-open design would lose.
    let honest_index = 0u64;
    let honest_key = 0xA5A5_A5A5u64;
    assert_eq!(m.insert(honest_index, honest_key), Ok(None));

    // (a) FLOOD to and past capacity.
    for i in 1..CAP as u64 {
        assert_eq!(m.insert(i, i), Ok(None));
    }
    assert!(m.is_full());
    for i in CAP as u64..FLOOD {
        assert_eq!(
            m.insert(i, i),
            Err(ProtocolError::SkippedKeyLimit),
            "index {i} must be refused, not admitted by eviction"
        );
    }
    assert_eq!(m.len(), CAP, "the flood cannot grow the store");

    // (b) The ORIGINAL attack: none of the flood's entries got in, so a
    //     forged index is still unknown and the honest cached key was not
    //     displaced by one.
    assert_eq!(m.get(&(FLOOD - 1)), None);
    assert_eq!(
        m.insert_if_absent(honest_index, 0xDEAD_BEEF),
        Err(ProtocolError::ReplayDetected),
        "an existing cached key is never silently replaced"
    );

    // (c) The HONEST peer is STILL served: the delayed message arrives and its
    //     key is exactly the one that was cached before the flood.
    assert_eq!(m.get(&honest_index), Some(&honest_key));
    assert_eq!(m.remove(&honest_index), Some(honest_key));

    // ... and the owner-directed prune (M1 §D.4 chain retirement) reopens the
    // store, so the fail-closed state is recoverable rather than terminal.
    m.prune(|k, _| *k < 1_000);
    assert!(!m.is_full());
    assert_eq!(m.insert(FLOOD, FLOOD), Ok(None));
}

// ---------------------------------------------------------------------------
// §6.3 / §6.4 row 2 — session_id uniqueness (expiry-pruned, never key-evicted).
// ---------------------------------------------------------------------------

/// The attack this set exists to stop is a replayed `InitialMessage`, which
/// derives the identical `session_id`. A flood must not age that record out,
/// and re-handshakes must not evict it (parent §6.3).
#[test]
fn expiring_set_flood() {
    const CAP: usize = 256;
    // §6.3's set sits on the serverless first-contact path, so its owner names
    // the §6.6 item 4 error rather than translating a generic one.
    const FULL: ProtocolError = ProtocolError::FirstContactCapacity;
    let mut s: ExpiringSet<u64> = ExpiringSet::new(CAP, FULL);

    // The victim's first contact is recorded at t=0.
    let victim_sid = 0u64;
    assert_eq!(
        s.insert_if_absent(victim_sid, UNKNOWN_ENTRY_TTL_MS, 0),
        Ok(())
    );

    // (a) FLOOD with distinct session_ids, all still live.
    for sid in 1..CAP as u64 {
        assert_eq!(s.insert_if_absent(sid, UNKNOWN_ENTRY_TTL_MS, 0), Ok(()));
    }
    for sid in CAP as u64..FLOOD {
        assert_eq!(
            s.insert_if_absent(sid, UNKNOWN_ENTRY_TTL_MS, 0),
            Err(FULL),
            "sid {sid}"
        );
    }
    assert_eq!(s.len(), CAP);

    // (a') And a re-handshake from the victim's own peer, which parent §6.3
    //      records as the hole one design track shipped.
    assert_eq!(
        s.insert_if_absent(victim_sid + 1_000_000, UNKNOWN_ENTRY_TTL_MS, 1),
        Err(FULL),
        "a full set refuses the new record; it does not replace an old one"
    );

    // (b) The ORIGINAL attack — replaying the captured InitialMessage, which
    //     re-derives `victim_sid` — is STILL rejected.
    assert!(s.contains(&victim_sid, 1));
    assert_eq!(
        s.insert_if_absent(victim_sid, UNKNOWN_ENTRY_TTL_MS, 1),
        Err(ProtocolError::ReplayDetected)
    );

    // (c) The HONEST peer is STILL served. Expiry is the only removal path, so
    //     once the flood's entries age out the set serves new first contacts
    //     again — the lockout is bounded by the TTL, not permanent.
    let after = UNKNOWN_ENTRY_TTL_MS + 1;
    assert_eq!(s.prune(after), CAP);
    assert!(s.is_empty());
    assert_eq!(
        s.insert_if_absent(FLOOD + 1, after + UNKNOWN_ENTRY_TTL_MS, after),
        Ok(())
    );
}

/// Parent §6.3 in isolation: the uniqueness record survives a re-handshake even
/// when there is ample room, i.e. replacement is not merely unlikely, it is
/// unrepresentable — the type has no key-directed removal.
#[test]
fn expiring_set_rehandshake_does_not_evict() {
    let mut s: ExpiringSet<(u32, u32)> = ExpiringSet::new(64, ProtocolError::FirstContactCapacity);
    let peer = 7u32;
    let captured = (peer, 1u32);
    assert_eq!(s.insert_if_absent(captured, 10_000, 0), Ok(()));

    // (a) The same peer re-handshakes many times.
    for n in 2..1_000u32 {
        assert_eq!(s.prune(0), 0);
        if s.insert_if_absent((peer, n), 10_000, 0).is_err() {
            // Fail closed once full — but never by displacing `captured`.
        }
        // (b) The captured no-OPK InitialMessage still replays into a
        //     rejection, after every single re-handshake.
        assert!(s.contains(&captured, 0), "evicted after re-handshake {n}");
        assert_eq!(
            s.insert_if_absent(captured, 10_000, 0),
            Err(ProtocolError::ReplayDetected)
        );
    }

    // (c) Honest service resumes as soon as the records expire.
    assert!(s.prune(10_000) > 0);
    assert_eq!(s.insert_if_absent((peer, 9_999), 20_000, 10_000), Ok(()));
}

// ---------------------------------------------------------------------------
// §6.6 — serverless containment.
// ---------------------------------------------------------------------------

/// The parent §6.6 containment property, stated as the gate 5 assertion:
///
/// > Flooding the Unknown pool must never evict, degrade, or deny service to
/// > any Established peer.
#[test]
fn partitioned_pool_flood_containment() {
    let mut p: PartitionedPool<u64, ReplayWindow> =
        PartitionedPool::new(32, EST_FULL, UNKNOWN_POOL_CAPACITY, UNKNOWN_ENTRY_TTL_MS);

    // An Established peer with live replay state (parent §6.4 rows 1-3 sit in
    // the Established budget).
    let established = 1u64;
    assert_eq!(
        p.insert_established(established, ReplayWindow::new(0)),
        Ok(None)
    );
    let captured_seq = 4u64;
    match p.get_established_mut(&established) {
        Some(w) => assert_eq!(w.check_and_update(captured_seq), Ok(())),
        None => panic!("Established peer missing"),
    }

    // (a) FLOOD the Unknown pool far past capacity.
    for k in 0..UNKNOWN_POOL_CAPACITY as u64 {
        assert_eq!(p.insert_unknown(1_000 + k, ReplayWindow::new(0), 0), Ok(()));
    }
    for k in UNKNOWN_POOL_CAPACITY as u64..FLOOD {
        assert_eq!(
            p.insert_unknown(1_000 + k, ReplayWindow::new(0), 0),
            Err(ProtocolError::FirstContactCapacity),
            "must be the distinct, user-actionable error, never a silent drop"
        );
    }
    assert_eq!(p.unknown_len(), UNKNOWN_POOL_CAPACITY);

    // CONTAINMENT: the Established side is untouched in every observable way.
    assert_eq!(p.established_len(), 1);
    assert_eq!(p.classify(&established, 0), Some(PeerClass::Established));
    assert_eq!(p.established_capacity(), 32);

    // (b) The ORIGINAL attack against the Established peer — replaying its
    //     captured handshake — is STILL rejected. A pool that borrowed from or
    //     evicted Established state would have dropped this floor.
    match p.get_established_mut(&established) {
        Some(w) => {
            assert_eq!(
                w.check_and_update(captured_seq),
                Err(ProtocolError::ReplayDetected)
            );
            // (c) ... and the HONEST Established peer is STILL served: a full
            //     send/receive round trip's worth of fresh sequence numbers.
            for seq in 100..200u64 {
                assert_eq!(w.check_and_update(seq), Ok(()), "seq {seq}");
            }
        }
        None => panic!("Established peer evicted by an Unknown-pool flood"),
    }

    // (c') A NEW peer the user explicitly accepts is still admitted, because
    //      the Established budget was never spent by the flood.
    assert_eq!(p.insert_established(2, ReplayWindow::new(0)), Ok(None));
    assert_eq!(p.established_len(), 2);

    // The accepted degradation, and only it: inbound first contact from a new
    // peer is denied for the duration of the flood (parent §6.6).
    assert_eq!(
        p.insert_unknown(9_999_999, ReplayWindow::new(0), 0),
        Err(ProtocolError::FirstContactCapacity)
    );

    // And it is genuinely for the duration only: once the pending entries age
    // out, first contact works again.
    let after = UNKNOWN_ENTRY_TTL_MS;
    assert_eq!(p.prune_unknown(after), UNKNOWN_POOL_CAPACITY);
    assert_eq!(
        p.insert_unknown(9_999_999, ReplayWindow::new(0), after),
        Ok(())
    );
    assert_eq!(p.promote(9_999_999, after), Ok(Promotion::Promoted));
    assert_eq!(p.established_len(), 3);
}

/// The complementary direction: a flood cannot deny the *promotion* of a peer
/// the user accepts, and cannot corrupt an Established entry through
/// `promote`.
#[test]
fn partitioned_pool_flood_cannot_hijack_promotion() {
    let mut p: PartitionedPool<u64, u64> =
        PartitionedPool::new(4, EST_FULL, 8, UNKNOWN_ENTRY_TTL_MS);
    assert_eq!(p.insert_established(1, 0xC0DE), Ok(None));

    // (a) FLOOD Unknown, including with the Established peer's own key.
    assert_eq!(p.insert_unknown(1, 0xBAD, 0), Ok(()));
    for k in 100..107u64 {
        assert_eq!(p.insert_unknown(k, k, 0), Ok(()));
    }
    assert_eq!(
        p.insert_unknown(200, 200, 0),
        Err(ProtocolError::FirstContactCapacity)
    );

    // (b) The ORIGINAL attack: a pending Unknown value must not become the
    //     Established peer's state via promotion.
    assert_eq!(p.promote(1, 0), Ok(Promotion::AlreadyEstablished));
    assert_eq!(p.get_established(&1), Some(&0xC0DE));

    // (c) An honest pending peer the user accepts is still promoted.
    assert_eq!(p.promote(100, 0), Ok(Promotion::Promoted));
    assert_eq!(p.get_established(&100), Some(&100));
    assert_eq!(p.classify(&100, 0), Some(PeerClass::Established));
}

// ---------------------------------------------------------------------------
// §6.3 — the first-contact defence must not be voidable by the record's own
// declared expiry, which is attacker-influenced data.
// ---------------------------------------------------------------------------

/// The flood-shaped version of the born-expired hole: `not_after_ms` is supplied
/// per insert, so an attacker who can steer it toward the past would otherwise
/// get a uniqueness set that silently accepts every replay while still
/// consuming capacity. Neither may happen.
#[test]
fn expiring_set_cannot_be_voided_by_a_past_expiry() {
    let mut s: ExpiringSet<u64> = ExpiringSet::new(64, ProtocolError::FirstContactCapacity);
    let now = 1_000_000u64;
    let victim_sid = 0x00C0_FFEE_u64;

    // (a) FLOOD with records that declare themselves already expired.
    for sid in 0..FLOOD {
        assert_eq!(
            s.insert_if_absent(sid, now.saturating_sub(1), now),
            Err(ProtocolError::Malformed),
            "sid {sid}: a record born expired must be refused outright"
        );
    }
    assert!(s.is_empty(), "and must consume no capacity at all");

    // (b) The ORIGINAL attack: replaying one InitialMessage whose derived
    //     session_id is recorded. Under the old behaviour the past expiry made
    //     every one of these `Ok(())`.
    assert_eq!(s.insert_if_absent(victim_sid, now + 60_000, now), Ok(()));
    for attempt in 0..8u32 {
        assert_eq!(
            s.insert_if_absent(victim_sid, now + 60_000, now),
            Err(ProtocolError::ReplayDetected),
            "replay {attempt} must stay rejected"
        );
        // ... including when the replay tries to smuggle a past expiry in.
        assert_eq!(
            s.insert_if_absent(victim_sid, now.saturating_sub(1), now),
            Err(ProtocolError::Malformed),
            "replay {attempt} must not be laundered by a dead expiry"
        );
    }

    // (c) The HONEST peer is STILL served: the flood consumed no slots, so a
    //     well-formed first contact goes straight through.
    assert_eq!(s.len(), 1);
    assert_eq!(s.insert_if_absent(777, now + 60_000, now), Ok(()));
}
