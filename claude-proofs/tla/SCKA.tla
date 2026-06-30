-------------------------------- MODULE SCKA --------------------------------
(*****************************************************************************)
(* TLA+ specification of the ML-KEM Braid SCKA *state machine* -- the        *)
(* distributed-systems correctness layer of the protocol (agreement,        *)
(* one-key-per-epoch, monotone-gapless epochs, no-deadlock, progress).      *)
(*                                                                          *)
(* THIS FILE HAS BEEN RUN under TLC (tla2tools 2.19, Java).  See            *)
(* claude-proofs/results/tlc.txt for the captured output and                *)
(* claude-proofs/README.md for what each property means and does NOT mean.  *)
(*                                                                          *)
(* Authoritative sources (behaviour read byte-exact from these):            *)
(*   ml_kem_braid/protocol/states.py   -- the 11 states + transitions 1..13 *)
(*   ml_kem_braid/protocol/braid.py    -- _handle_epoch_advancement_receive *)
(*                                        (epoch += 1 on exactly two events) *)
(*   ml_kem_braid/protocol/messages.py -- Message {epoch, type, data?}      *)
(*                                                                          *)
(* SCOPE / ABSTRACTION (honest about what is and is NOT modelled):          *)
(*  * All 11 states of states.py are named.  The per-chunk Send/Receive of   *)
(*    the erasure-coded stream is collapsed to ONE logical message per       *)
(*    object (header / ek_vector / ct1 / ct2): Reed-Solomon, GF(2^8), and    *)
(*    the k-of-(k+p) threshold are abstracted -- they affect WHEN an object  *)
(*    completes, never WHICH object or its content, so they are irrelevant   *)
(*    to the state-machine safety properties checked here.                   *)
(*  * NO cryptography.  The per-epoch key is the abstract proxy              *)
(*        KeyOf(e) == <<e, SharedNonce>>                                     *)
(*    which is equal for both parties at the same epoch BY CONSTRUCTION.     *)
(*    This bakes in the cryptographic fact (proven elsewhere: kdf_ok over    *)
(*    the same decaps/encaps ss, plus the EasyCrypt split==reference lemma)  *)
(*    that an honest epoch yields the same ss on both sides.  This model     *)
(*    therefore proves the *state-machine discipline* -- that the two        *)
(*    parties only emit a key while agreeing on the epoch index e, and never *)
(*    emit two different keys for the same e -- NOT cryptographic agreement. *)
(*  * Channel = Dolev-Yao-LITE: drops, reorders, duplicates honest messages, *)
(*    but cannot forge/inject (forgery is defeated by the authenticator MAC, *)
(*    modelled in the Tamarin theory, not here).                            *)
(*****************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxEpoch,       \* highest epoch index the model is bounded to (cfg: 3)
    MaxCopies       \* cap on in-flight copies of any one message (cfg: 2)

Parties == {"Alice", "Bob"}

(*--- the 11 states of states.py, names identical -------------------------*)
(* EK-side: party transmits the encapsulation key, receives the ciphertext. *)
EKStates == { "KeysUnsampled", "KeysSampled", "HeaderSent",
              "Ct1Received", "EkSentCt1Received" }
(* CT-side: party transmits the ciphertext, receives the encapsulation key.  *)
CTStates == { "NoHeaderReceived", "HeaderReceived", "Ct1Sampled",
              "EkReceivedCt1Sampled", "Ct1Acknowledged", "Ct2Sampled" }
AllStates == EKStates \cup CTStates

(* The reachable subset used by the collapsed transitions below.  Four pure   *)
(* chunk-pumping states (KeysSampled, EkSentCt1Received, EkReceivedCt1Sampled, *)
(* Ct1Acknowledged) are folded into their neighbours: they neither emit a key  *)
(* nor change the epoch, so they are invisible to the safety/liveness          *)
(* properties.  The 7 states below keep the real names and carry every         *)
(* key-emission and epoch-advance transition exactly.  Each transmitting state *)
(* RETRANSMITS its object (self-loop send) -- this models the erasure-coded     *)
(* chunk stream re-sending until the object is reconstructed, which is what     *)
(* makes the protocol robust to the lossy channel (no spurious deadlock).      *)
(*   KeysUnsampled   (EK) : ready to send header                               *)
(*   HeaderSent      (EK) : header transmitting, awaiting ct1                   *)
(*   Ct1Received     (EK) : ct1 in, ek_vector transmitting, awaiting ct2        *)
(*   NoHeaderReceived(CT) : awaiting header                                     *)
(*   HeaderReceived  (CT) : header in, about to encaps1 (emit) + send ct1       *)
(*   Ct1Sampled      (CT) : ct1 transmitting, awaiting ek_vector                *)
(*   Ct2Sampled      (CT) : ct2 transmitting, awaiting peer epoch advance       *)

(* Logical message objects (per-chunk granularity abstracted to one each).    *)
MsgTypes == { "None", "Hdr", "Ek", "EkCt1Ack", "Ct1", "Ct2" }

(* A network message: recipient + epoch + logical type.  Epoch is bounded to  *)
(* 1..MaxEpoch so Msg (hence the channel) is a FINITE set for TLC.           *)
Msg == [ to : Parties, epoch : 1..MaxEpoch, type : MsgTypes ]

SharedNonce == "N0"
KeyOf(e) == << e, SharedNonce >>           \* abstract per-epoch key proxy
KeySpace == { KeyOf(e) : e \in 1..MaxEpoch }

VARIABLES
    pstate,     \* pstate[p] \in AllStates
    epoch,      \* epoch[p]  \in 1..(MaxEpoch+1)
    keys,       \* keys[p]   : set of <<e, KeyOf(e)>> this party has EMITTED
    net         \* net \in [Msg -> 0..MaxCopies] : in-flight message bag

vars == << pstate, epoch, keys, net >>

(*--- the in-flight message bag -------------------------------------------*)
EmptyNet == [ m \in Msg |-> 0 ]
InFlight(m) == net[m] > 0
CanPut(m)   == net[m] < MaxCopies                \* guard keeps the bag finite
Put(m)  == [ net EXCEPT ![m] = @ + 1 ]
Take(m) == [ net EXCEPT ![m] = @ - 1 ]

(*===========================================================================*)
(* TYPE INVARIANT                                                            *)
(*===========================================================================*)
TypeOK ==
    /\ pstate \in [ Parties -> AllStates ]
    /\ epoch  \in [ Parties -> 1..(MaxEpoch + 1) ]
    /\ keys   \in [ Parties -> SUBSET ((1..MaxEpoch) \X KeySpace) ]
    /\ net    \in [ Msg -> 0..MaxCopies ]

(*===========================================================================*)
(* INIT  -- Alice = init_alice_state() = KeysUnsampled (EK side, epoch 1);    *)
(*          Bob   = init_bob_state()   = NoHeaderReceived (CT side, epoch 1). *)
(*===========================================================================*)
Init ==
    /\ pstate = [ p \in Parties |-> IF p = "Alice" THEN "KeysUnsampled"
                                                   ELSE "NoHeaderReceived" ]
    /\ epoch  = [ p \in Parties |-> 1 ]
    /\ keys   = [ p \in Parties |-> {} ]
    /\ net    = EmptyNet

(*===========================================================================*)
(* HELPERS                                                                   *)
(*===========================================================================*)
Other(p)        == IF p = "Alice" THEN "Bob" ELSE "Alice"
HasKeyFor(p, e) == \E k \in keys[p] : k[1] = e

(*===========================================================================*)
(* TRANSITIONS  (per-object; intermediate pure-chunk states collapsed).      *)
(*                                                                          *)
(* Every transmitting state RETRANSMITS its object (a self-loop SendX that    *)
(* puts another copy, up to MaxCopies) -- this is the erasure-coded stream     *)
(* re-sending chunks until the receiver reconstructs the object.  A receiver   *)
(* TAKES one copy to "complete" the object.  Combined with the fair-channel    *)
(* SF (below), this makes the protocol robust to drop/dup/reorder.            *)
(*                                                                          *)
(* The two KEY-EMITTING / EPOCH-ADVANCING transitions are kept exact         *)
(* (verified against states.py + braid.py):                                 *)
(*   T7  CT-side HeaderReceived (encaps1) : EMITS KeyOf(e), epoch UNCHANGED.  *)
(*   T5  EK-side recv(Ct2) (decaps)       : EMITS KeyOf(e) AND epoch += 1.    *)
(*   T13 CT-side advance once peer reached e+1 : epoch += 1 (no key here).    *)
(*===========================================================================*)

(* Each protocol action carries `epoch[p] <= MaxEpoch` as its FIRST conjunct.  *)
(* This bounds the model (finiteness) AND -- crucially -- keeps every action    *)
(* DISABLED past the bound, so the per-action fairness below never evaluates a   *)
(* message term whose epoch is out of the Msg domain.  The LET binding of `m`    *)
(* sits AFTER the guard so it is never evaluated when the guard is false.        *)

(*--- EK-side pipeline ------------------------------------------------------*)
SendHeader(p) ==                              \* KeysUnsampled/HeaderSent: (re)send hdr
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] \in { "KeysUnsampled", "HeaderSent" }
    /\ LET m == [ to |-> Other(p), epoch |-> epoch[p], type |-> "Hdr" ]
       IN /\ CanPut(m)
          /\ net' = Put(m)
          /\ pstate' = [ pstate EXCEPT ![p] = "HeaderSent" ]   \* idempotent past first send
          /\ UNCHANGED << epoch, keys >>

RecvCt1_EK(p) ==                              \* HeaderSent -> Ct1Received
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "HeaderSent"
    /\ LET m == [ to |-> p, epoch |-> epoch[p], type |-> "Ct1" ]
       IN /\ InFlight(m)
          /\ net' = Take(m)
          /\ pstate' = [ pstate EXCEPT ![p] = "Ct1Received" ]
          /\ UNCHANGED << epoch, keys >>

SendEk_EK(p) ==                               \* Ct1Received: (re)send ek_vector
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "Ct1Received"
    /\ LET m == [ to |-> Other(p), epoch |-> epoch[p], type |-> "EkCt1Ack" ]
       IN /\ CanPut(m)
          /\ net' = Put(m)
          /\ UNCHANGED << pstate, epoch, keys >>

RecvCt2_EK(p) ==                              \* T5: emit key + epoch++ ; flip to CT side
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "Ct1Received"
    /\ LET m == [ to |-> p, epoch |-> epoch[p], type |-> "Ct2" ]
       IN /\ InFlight(m)
          /\ net' = Take(m)
          /\ keys' = [ keys EXCEPT ![p] = @ \cup { << epoch[p], KeyOf(epoch[p]) >> } ]
          /\ epoch' = [ epoch EXCEPT ![p] = @ + 1 ]
          /\ pstate' = [ pstate EXCEPT ![p] = "NoHeaderReceived" ]

(*--- CT-side pipeline ------------------------------------------------------*)
RecvHeader_CT(p) ==                           \* NoHeaderReceived -> HeaderReceived
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "NoHeaderReceived"
    /\ LET m == [ to |-> p, epoch |-> epoch[p], type |-> "Hdr" ]
       IN /\ InFlight(m)
          /\ net' = Take(m)
          /\ pstate' = [ pstate EXCEPT ![p] = "HeaderReceived" ]
          /\ UNCHANGED << epoch, keys >>

SendCt1_emit(p) ==                            \* T7: encaps1 emits key; send ct1; epoch UNCHANGED
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "HeaderReceived"
    /\ LET m == [ to |-> Other(p), epoch |-> epoch[p], type |-> "Ct1" ]
       IN /\ CanPut(m)
          /\ net' = Put(m)
          /\ keys' = [ keys EXCEPT ![p] = @ \cup { << epoch[p], KeyOf(epoch[p]) >> } ]
          /\ pstate' = [ pstate EXCEPT ![p] = "Ct1Sampled" ]
          /\ UNCHANGED epoch

SendCt1_retx(p) ==                            \* Ct1Sampled: retransmit ct1 (no re-emit)
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "Ct1Sampled"
    /\ LET m == [ to |-> Other(p), epoch |-> epoch[p], type |-> "Ct1" ]
       IN /\ CanPut(m)
          /\ net' = Put(m)
          /\ UNCHANGED << pstate, epoch, keys >>

RecvEk_CT(p) ==                               \* Ct1Sampled -> Ct2Sampled
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "Ct1Sampled"
    /\ LET m == [ to |-> p, epoch |-> epoch[p], type |-> "EkCt1Ack" ]
       IN /\ InFlight(m)
          /\ net' = Take(m)
          /\ pstate' = [ pstate EXCEPT ![p] = "Ct2Sampled" ]
          /\ UNCHANGED << epoch, keys >>

SendCt2(p) ==                                 \* Ct2Sampled: (re)send ct2
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "Ct2Sampled"
    /\ LET m == [ to |-> Other(p), epoch |-> epoch[p], type |-> "Ct2" ]
       IN /\ CanPut(m)
          /\ net' = Put(m)
          /\ UNCHANGED << pstate, epoch, keys >>

AdvanceCT(p) ==                               \* T13: epoch++ once peer reached e+1 ; flip to EK side
    /\ epoch[p] <= MaxEpoch
    /\ pstate[p] = "Ct2Sampled"
    /\ epoch[Other(p)] = epoch[p] + 1
    /\ epoch' = [ epoch EXCEPT ![p] = @ + 1 ]
    /\ pstate' = [ pstate EXCEPT ![p] = "KeysUnsampled" ]
    /\ UNCHANGED << keys, net >>

(*--- adversarial lossy channel --------------------------------------------*)
DropMsg ==
    \E m \in Msg : InFlight(m) /\ net' = Take(m)
                   /\ UNCHANGED << pstate, epoch, keys >>
DupMsg ==
    \E m \in Msg : InFlight(m) /\ CanPut(m) /\ net' = Put(m)
                   /\ UNCHANGED << pstate, epoch, keys >>

(*===========================================================================*)
(* NEXT  (each protocol action self-bounds via epoch[p] <= MaxEpoch).         *)
(*===========================================================================*)
Protocol(p) ==
    \/ SendHeader(p)    \/ RecvCt1_EK(p)   \/ SendEk_EK(p)    \/ RecvCt2_EK(p)
    \/ RecvHeader_CT(p) \/ SendCt1_emit(p) \/ SendCt1_retx(p)
    \/ RecvEk_CT(p)     \/ SendCt2(p)      \/ AdvanceCT(p)

Next ==
    \/ \E p \in Parties : Protocol(p)
    \/ DropMsg
    \/ DupMsg

(*===========================================================================*)
(* FAIRNESS + SPEC                                                            *)
(*   WF on each party's sends (parties keep driving the pipeline);            *)
(*   SF on each party's deliveries (a usable copy that stays available is     *)
(*   eventually consumed -- the "fair channel" that forbids starving every    *)
(*   copy forever).  Progress is conditional on this fairness.                *)
(*===========================================================================*)
(* Weak fairness on every sender action (a continuously-enabled (re)send         *)
(* eventually fires) and STRONG fairness on every receiver/advance action (a     *)
(* delivery that is available infinitely often -- the fair channel -- eventually  *)
(* fires).  Progress and NoDeadlock are conditional on this fairness.            *)
Fairness ==
    /\ \A p \in Parties :
         /\ WF_vars(SendHeader(p))  /\ WF_vars(SendEk_EK(p))
         /\ WF_vars(SendCt1_emit(p)) /\ WF_vars(SendCt1_retx(p)) /\ WF_vars(SendCt2(p))
    /\ \A p \in Parties :
         /\ SF_vars(RecvCt1_EK(p))   /\ SF_vars(RecvCt2_EK(p))
         /\ SF_vars(RecvHeader_CT(p)) /\ SF_vars(RecvEk_CT(p)) /\ SF_vars(AdvanceCT(p))

Spec == Init /\ [][Next]_vars /\ Fairness

(* State constraint (cfg CONSTRAINT) keeping the bag finite. *)
BoundedNet == \A m \in Msg : net[m] <= MaxCopies

(*===========================================================================*)
(* SAFETY INVARIANTS                                                          *)
(*===========================================================================*)

(* AGREEMENT: if BOTH parties have emitted a key for the SAME epoch e, those  *)
(* keys are equal (KeyOf is the abstract proxy -- see header).               *)
Agreement ==
    \A e \in 1..MaxEpoch :
        (HasKeyFor("Alice", e) /\ HasKeyFor("Bob", e)) =>
            ( { k \in keys["Alice"] : k[1] = e } = { k \in keys["Bob"] : k[1] = e } )

(* UNIQUENESS: each party emits AT MOST ONE key per epoch.                   *)
Uniqueness ==
    \A p \in Parties : \A e \in 1..MaxEpoch :
        Cardinality({ k \in keys[p] : k[1] = e }) <= 1

(* MONOTONE + GAPLESS: a party's emitted-key epochs form a prefix 1..n.       *)
MonotoneGapless ==
    \A p \in Parties : \A e \in 2..MaxEpoch :
        HasKeyFor(p, e) => HasKeyFor(p, e - 1)

(* NO KEY AHEAD: a party never emits a key for an epoch beyond what it has    *)
(* negotiated (its key epochs are all < its current epoch counter, or ==     *)
(* current only transiently on the CT side at the emit step).               *)
NoKeyAhead ==
    \A p \in Parties : \A k \in keys[p] : k[1] <= epoch[p]

Inv == TypeOK /\ Agreement /\ Uniqueness /\ MonotoneGapless /\ NoKeyAhead

(*===========================================================================*)
(* LIVENESS / TEMPORAL PROPERTIES (TLC only; rely on Fairness in Spec).       *)
(*===========================================================================*)

(* PROGRESS: every bounded epoch is eventually agreed by BOTH parties.        *)
Progress ==
    \A e \in 1..MaxEpoch : <> ( HasKeyFor("Alice", e) /\ HasKeyFor("Bob", e) )

(* NO DEADLOCK: always either we are "done" (both ran past MaxEpoch having    *)
(* keyed it) or some step is enabled.                                        *)
Done == \A p \in Parties : epoch[p] > MaxEpoch \/ HasKeyFor(p, MaxEpoch)
NoDeadlock == [] ( Done \/ ENABLED Next )

=============================================================================
