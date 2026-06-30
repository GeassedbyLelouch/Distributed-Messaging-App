-------------------------------- MODULE SCKA --------------------------------
(*****************************************************************************)
(* TLA+ specification of the ML-KEM Braid SCKA *state machine* (the         *)
(* distributed-systems correctness layer of the protocol).                  *)
(*                                                                          *)
(* This is a SCAFFOLD / PLAN intended for human review and completion. It   *)
(* has NOT been run through TLC or Apalache by its author; the invariants   *)
(* and temporal properties below are CLAIMS to be model-checked, not proven *)
(* facts. Several modelling choices are deliberate abstractions (documented  *)
(* inline) and at least one liveness obligation is left as an explicit TODO. *)
(*                                                                          *)
(* Authoritative sources (byte-exact behaviour was read from these):        *)
(*   - docs/PROTOCOL_SPEC.md          (section 2: ML-KEM Braid SCKA)         *)
(*   - ml_kem_braid/protocol/states.py    (the 11 states + transitions 1-13)*)
(*   - ml_kem_braid/protocol/braid.py     (epoch-advance + key emission)    *)
(*   - ml_kem_braid/protocol/messages.py  (message {epoch,type,data?})      *)
(*                                                                          *)
(*===========================================================================*)
(* WHAT IS MODELLED                                                          *)
(*===========================================================================*)
(* * The 11 concrete states of states.py for each party, plus a START marker *)
(*   that is folded into the two role-specific initial states (Alice begins  *)
(*   in KeysUnsampled, Bob in NoHeaderReceived -- see init_alice_state /      *)
(*   init_bob_state).                                                        *)
(* * BOTH parties (Alice, Bob) running the same state machine with swapped    *)
(*   roles. Roles ALTERNATE every epoch: the EK-sender of epoch e becomes the *)
(*   CT-sender of epoch e+1 and vice-versa (this is exactly what the Python   *)
(*   epoch-advance logic produces -- see braid.py                            *)
(*   _handle_epoch_advancement_receive).                                     *)
(* * A per-party epoch counter, started at 1, advanced on exactly the two     *)
(*   receive transitions that the code advances it on:                       *)
(*     (a) EkSentCt1Received --CT2--> NoHeaderReceived  (transition 5), and   *)
(*     (b) Ct2Sampled        --(epoch+1 msg)--> KeysUnsampled (transition 13).*)
(* * The erasure-coded chunk stream as an ABSTRACT lossy/reordering/          *)
(*   duplicating channel. We do NOT model Reed-Solomon, GF(2^8), chunk        *)
(*   indices, or the k-of-(k+p) reconstruction threshold. Instead each large  *)
(*   object (header, ek_vector, ct1, ct2) is modelled as ONE logical message  *)
(*   that the channel may drop, reorder, or duplicate. The "needs N chunks to *)
(*   reconstruct" detail is abstracted to "needs the one logical message to   *)
(*   arrive at least once"; loss/reorder/dup of that logical message is the    *)
(*   adversary's power. This is sound for the state-machine properties we      *)
(*   check (agreement / uniqueness / monotonicity / progress) because the     *)
(*   erasure layer only affects WHEN an object completes, never WHICH object   *)
(*   or its content.  TODO(human): if you want to model partial reconstruction *)
(*   explicitly, replace the boolean "delivered" with a chunk-count counter.  *)
(* * The per-epoch output key, modelled ABSTRACTLY as KeyOf(e) -- a           *)
(*   deterministic function of the epoch and a single shared nonce. See       *)
(*   "WHAT IS ABSTRACTED" for why this is the right abstraction for AGREEMENT. *)
(*                                                                          *)
(*===========================================================================*)
(* WHAT IS ABSTRACTED AWAY (NOT modelled -- belongs to other tools)          *)
(*===========================================================================*)
(* * ALL cryptography. There is no ML-KEM, no HKDF, no HMAC, no MAC           *)
(*   verification, no authenticator ratchet. Secrecy, forward secrecy, PCS,   *)
(*   and authentication are OUT OF SCOPE here -- they are Tamarin / EasyCrypt  *)
(*   territory (see docs/PROTOCOL_SPEC.md section A, the target matrix).      *)
(* * Keys are abstract. We model the per-epoch key as KeyOf(e) where          *)
(*       KeyOf(e) == <<e, SharedNonce>>                                       *)
(*   i.e. a value that is, by construction, equal for both parties whenever   *)
(*   they refer to the same epoch e. THIS BAKES IN the cryptographic fact     *)
(*   (proven elsewhere: states.py uses kdf_ok(decaps/encaps ss, epoch) and    *)
(*   the EasyCrypt "split == reference ciphertext" lemma) that, given an       *)
(*   honest run, encaps and decaps of the SAME epoch yield the SAME ss, hence  *)
(*   the same kdf_ok output. The TLA+ model therefore CANNOT and DOES NOT      *)
(*   prove key agreement cryptographically; it proves the *state-machine*      *)
(*   discipline that ensures the two parties only ever emit a key while        *)
(*   agreeing on the epoch number e, and never emit two different keys for the *)
(*   same epoch.  Equality of KeyOf(e) is thus the decidable proxy the task    *)
(*   asks for.                                                                *)
(*   ==> A human reviewer MUST keep this caveat: AGREEMENT here means          *)
(*       "agree on epoch index, and each emits KeyOf(thatEpoch)". The          *)
(*       cryptographic step KeyOf is a stand-in for the real KDF/KEM equality. *)
(* * The channel adversary is a Dolev-Yao-LITE network: it may drop, reorder, *)
(*   and duplicate honest messages, but it CANNOT forge or inject new          *)
(*   messages (injection/forgery is defeated by the authenticator MAC, which   *)
(*   is modelled elsewhere). Modelling forgery here would be meaningless        *)
(*   because we have no MAC in the model -- a forged message would simply be    *)
(*   indistinguishable from an honest one. TODO(human): if desired, add a       *)
(*   "forge" action gated by a flag to confirm the state machine *halts*        *)
(*   (does not advance epochs) on unexpected messages, mirroring the Python     *)
(*   "verification failure => session halts" behaviour.                        *)
(*                                                                          *)
(*===========================================================================*)
(* HOW TO RUN                                                                *)
(*===========================================================================*)
(* TLC (explicit-state, exhaustive up to the .cfg bounds):                   *)
(*   1. Install the TLA+ Toolbox or the standalone tla2tools.jar             *)
(*      (https://github.com/tlaplus/tlaplus/releases). Needs a JRE >= 11.    *)
(*   2. From this directory:                                                  *)
(*        java -cp /path/to/tla2tools.jar tlc2.TLC -config SCKA.cfg SCKA.tla  *)
(*      or, with the `tlc` wrapper script from the toolbox:                   *)
(*        tlc -config SCKA.cfg SCKA.tla                                       *)
(*   3. EXPECTED RESULT (if the model and properties are correct): TLC        *)
(*      reports "Model checking completed. No error has been found." for all  *)
(*      INVARIANTS, and for the PROPERTIES it will need the FAIRNESS in Spec  *)
(*      (already included) to discharge the liveness checks. Because the       *)
(*      channel is fair (see FairChannel below) the liveness props should      *)
(*      hold; if you remove fairness, expect TLC to report a stuttering/       *)
(*      lasso counterexample for Progress (that is the POINT of the fairness   *)
(*      hypothesis -- liveness is conditional on it).                          *)
(*                                                                          *)
(* Apalache (symbolic, bounded; good for the inductive invariants):          *)
(*   1. Install Apalache (https://github.com/informalsystems/apalache,        *)
(*      `apalache-mc` on PATH; needs a JRE).                                  *)
(*   2. Check the safety invariants (bounded model checking, default length): *)
(*        apalache-mc check --config=SCKA.cfg --inv=Inv SCKA.tla              *)
(*      where Inv is the conjunction TypeOK /\ Agreement /\ Uniqueness /\     *)
(*      MonotoneGapless (defined as `Inv` below for convenience).            *)
(*   3. Apalache needs type annotations for full symbolic checking. This       *)
(*      scaffold uses simple types (Int, records, sets, sequences) that        *)
(*      Apalache's type-checker can mostly infer, but you WILL likely need to  *)
(*      add `\* @type:` annotations to CONSTANTS and a few operators for a      *)
(*      clean `apalache-mc typecheck`. That is marked TODO(human) below.       *)
(*      EXPECTED RESULT once annotated: "The outcome is: NoError".            *)
(*      NOTE: Apalache does not check liveness/temporal `[]<>`/`<>[]`          *)
(*      properties -- use TLC for Progress and NoDeadlock.                     *)
(*****************************************************************************)

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxEpoch        \* highest epoch index we bound the model to (e.g. 3)

(* Parties. Alice is the epoch-1 EK-sender, Bob the epoch-1 CT-sender. *)
Parties == {"Alice", "Bob"}

(*---------------------------------------------------------------------------*)
(* The 11 concrete states from states.py, named identically (plus the role    *)
(* split is captured by which state a party is currently in -- the "EK side"   *)
(* states vs the "CT side" states).                                           *)
(*                                                                            *)
(* EK-side states (party is transmitting the encapsulation key, receiving CT): *)
(*   KeysUnsampled, KeysSampled, HeaderSent, Ct1Received, EkSentCt1Received    *)
(* CT-side states (party is transmitting the ciphertext, receiving the EK):    *)
(*   NoHeaderReceived, HeaderReceived, Ct1Sampled, EkReceivedCt1Sampled,       *)
(*   Ct1Acknowledged, Ct2Sampled                                              *)
(*---------------------------------------------------------------------------*)
EKStates == { "KeysUnsampled", "KeysSampled", "HeaderSent",
              "Ct1Received", "EkSentCt1Received" }
CTStates == { "NoHeaderReceived", "HeaderReceived", "Ct1Sampled",
              "EkReceivedCt1Sampled", "Ct1Acknowledged", "Ct2Sampled" }
AllStates == EKStates \cup CTStates

(*---------------------------------------------------------------------------*)
(* Message types from messages.py (MessageType IntEnum). We model the          *)
(* *logical* object carried, abstracting the per-chunk granularity: one logical*)
(* message per object. "Hdr"=header, "Ek"=ek_vector, "EkCt1Ack"=ek_vector +    *)
(* ct1-ack, "Ct1"=ct1, "Ct2"=ct2, "None"=no-op keepalive.                      *)
(*                                                                            *)
(* NOTE on the abstraction of EK vs EK_CT1_ACK: in the code these differ only  *)
(* in whether the CT-sender has already seen ct1. Because we collapse the      *)
(* chunk stream into a single logical delivery, we represent the EK delivery   *)
(* to the CT-sender as a single "Ek" object, and the ek-with-ack path that     *)
(* triggers ct2 generation as "EkCt1Ack". A human refining this can split them *)
(* back out per the four Ct1Sampled transitions (8/9/10/12).                   *)
(*---------------------------------------------------------------------------*)
MsgTypes == { "None", "Hdr", "Ek", "EkCt1Ack", "Ct1", "Ct2" }

(* A network message: which epoch it belongs to + its logical type.            *)
(* `data` from the real message is abstracted away (content is irrelevant to   *)
(* the state-machine properties). `to` records the intended recipient so the    *)
(* fair-channel reasoning is per-recipient.                                     *)
Msg == [ to : Parties, epoch : Nat, type : MsgTypes ]

(*===========================================================================*)
(* VARIABLES                                                                  *)
(*===========================================================================*)
VARIABLES
    state,      \* state[p] \in AllStates : current state-machine state of p
    epoch,      \* epoch[p] \in Nat       : current epoch p is negotiating
    keys,       \* keys[p]  : set of <<e, KeyOf(e)>> p has OUTPUT (emitted)
    net         \* net : multiset (we use a *sequence* / bag-as-seq) of in-flight Msgs

vars == << state, epoch, keys, net >>

(*---------------------------------------------------------------------------*)
(* Abstract per-epoch key. By construction equal for both parties at the same  *)
(* epoch -- this is the decidable proxy for cryptographic key agreement        *)
(* (see the long comment in the header). SharedNonce is an arbitrary fixed      *)
(* token; its only role is to make KeyOf injective in e and "shared".          *)
(*---------------------------------------------------------------------------*)
SharedNonce == "N0"
KeyOf(e) == << e, SharedNonce >>

(*---------------------------------------------------------------------------*)
(* The channel is modelled as a BAG of in-flight messages, encoded as a        *)
(* function from Msg to a Nat count (how many copies are in flight). This       *)
(* lets us express drop (decrement without delivery), duplicate (a delivered    *)
(* message stays in the bag), and reorder (delivery picks any present msg).     *)
(* We use an explicit function `net \in [Msg -> Nat]` restricted to a finite    *)
(* support by the MaxEpoch bound.                                              *)
(*---------------------------------------------------------------------------*)
EmptyNet == [ m \in Msg |-> 0 ]

InFlight(m) == net[m] > 0

(* add one copy of m *)
Put(m)  == [ net EXCEPT ![m] = @ + 1 ]
(* remove one copy of m (used by drop and by non-duplicating delivery) *)
Take(m) == [ net EXCEPT ![m] = @ - 1 ]

(* State constraint (referenced by SCKA.cfg's CONSTRAINT directive): cap the    *)
(* number of copies of any single in-flight message so TLC's state space is      *)
(* finite despite DupMsg. TODO(human): tune the bound 2 (see SCKA.cfg).          *)
BoundedNet == \A m \in Msg : net[m] <= 2

(*===========================================================================*)
(* TYPE INVARIANT                                                             *)
(*===========================================================================*)
TypeOK ==
    /\ state \in [ Parties -> AllStates ]
    /\ epoch \in [ Parties -> Nat ]
    /\ \A p \in Parties : epoch[p] >= 1
    /\ keys  \in [ Parties -> SUBSET (Nat \X {<<n, SharedNonce>> : n \in Nat}) ]
       \* keys[p] is a set of <<epoch, KeyOf(epoch)>> pairs; we keep it loose so
       \* Apalache can infer a sequence/record-free type.
    /\ net   \in [ Msg -> Nat ]

(*===========================================================================*)
(* INITIAL STATE                                                              *)
(*===========================================================================*)
(* Alice = init_alice_state() = KeysUnsampled (EK sender).                     *)
(* Bob   = init_bob_state()   = NoHeaderReceived (CT sender).                  *)
(* Both at epoch 1, no keys emitted, empty channel.                            *)
Init ==
    /\ state = [ p \in Parties |-> IF p = "Alice" THEN "KeysUnsampled"
                                                  ELSE "NoHeaderReceived" ]
    /\ epoch = [ p \in Parties |-> 1 ]
    /\ keys  = [ p \in Parties |-> {} ]
    /\ net   = EmptyNet

(*===========================================================================*)
(* HELPERS                                                                    *)
(*===========================================================================*)
Other(p) == IF p = "Alice" THEN "Bob" ELSE "Alice"

HasKeyFor(p, e) == \E k \in keys[p] : k[1] = e

(*===========================================================================*)
(* TRANSITIONS                                                                *)
(*===========================================================================*)
(* The transitions below abstract the per-chunk Send/Receive of states.py     *)
(* into per-object steps. Each "object" (header, ek_vector, ct1, ct2) is sent  *)
(* by a single SendObj_* action that PUTS one logical message into the bag,    *)
(* and consumed by a single Recv_* action that TAKES it (or, to model          *)
(* duplication, may leave a copy). For brevity and because the SAFETY          *)
(* properties only care about the epoch/key bookkeeping at the transition       *)
(* boundaries, we fast-forward through the intermediate chunk-pumping states    *)
(* (KeysSampled, HeaderSent, Ct1Received, Ct1Sampled, EkReceivedCt1Sampled,    *)
(* Ct1Acknowledged) where no key is emitted and the epoch does not change.     *)
(*                                                                            *)
(* The KEY-EMITTING / EPOCH-ADVANCING transitions kept explicit are exactly    *)
(* the ones that matter (verified against states.py + braid.py):              *)
(*   T7  : CT-sender HeaderReceived.send  -> Ct1Sampled : EMITS KeyOf(e)       *)
(*         (encaps1 + kdf_ok); epoch does NOT advance here.                    *)
(*   T5  : EK-sender EkSentCt1Received.recv(Ct2) -> NoHeaderReceived :         *)
(*         EMITS KeyOf(e) (decaps + kdf_ok) AND epoch += 1; party flips to     *)
(*         CT side for the next epoch.                                         *)
(*   T13 : CT-sender Ct2Sampled.recv(epoch+1 msg) -> KeysUnsampled :           *)
(*         epoch += 1 (no key emitted here; its key was emitted at T7);        *)
(*         party flips to EK side.                                            *)
(*---------------------------------------------------------------------------*)

(*--- EK-sender pipeline (party p is on the EK side) ------------------------*)

(* p sends its header (KeysUnsampled/KeysSampled -> ... ). We collapse the     *)
(* header+ek_vector chunk pumping into: emit a Hdr object then later an Ek     *)
(* object. State advances KeysUnsampled -> HeaderSent (header fully "sent").   *)
SendHeader(p) ==
    /\ state[p] = "KeysUnsampled"
    /\ net' = Put([ to |-> Other(p), epoch |-> epoch[p], type |-> "Hdr" ])
    /\ state' = [ state EXCEPT ![p] = "HeaderSent" ]
    /\ UNCHANGED << epoch, keys >>

(* p (EK side, HeaderSent) receives ct1 from the CT side -> Ct1Received,       *)
(* then we let it send ek + receive ct2. We model the receipt of ct1 as the    *)
(* transition HeaderSent -> Ct1Received (transitions 2 & 3 collapsed).         *)
RecvCt1_EK(p) ==
    LET m == [ to |-> p, epoch |-> epoch[p], type |-> "Ct1" ] IN
    /\ state[p] = "HeaderSent"
    /\ InFlight(m)
    /\ net' = Take(m)
    /\ state' = [ state EXCEPT ![p] = "Ct1Received" ]
    /\ UNCHANGED << epoch, keys >>

(* p (EK side, Ct1Received) sends its ek_vector (with ct1-ack) -> still        *)
(* Ct1Received until it has emitted the Ek object; then it awaits ct2.         *)
(* We move to EkSentCt1Received to denote "ek fully sent, waiting for ct2".    *)
SendEk_EK(p) ==
    /\ state[p] = "Ct1Received"
    /\ net' = Put([ to |-> Other(p), epoch |-> epoch[p], type |-> "EkCt1Ack" ])
    /\ state' = [ state EXCEPT ![p] = "EkSentCt1Received" ]
    /\ UNCHANGED << epoch, keys >>

(* T5: p (EK side, EkSentCt1Received) receives Ct2 -> NoHeaderReceived.         *)
(* This is the EK-sender's key-emission + epoch advance. After this p is a       *)
(* CT-sender for epoch+1.                                                       *)
RecvCt2_EK(p) ==
    LET m == [ to |-> p, epoch |-> epoch[p], type |-> "Ct2" ] IN
    /\ state[p] = "EkSentCt1Received"
    /\ InFlight(m)
    /\ net' = Take(m)
    /\ keys' = [ keys EXCEPT ![p] = @ \cup { << epoch[p], KeyOf(epoch[p]) >> } ]
    /\ epoch' = [ epoch EXCEPT ![p] = @ + 1 ]
    /\ state' = [ state EXCEPT ![p] = "NoHeaderReceived" ]

(*--- CT-sender pipeline (party p is on the CT side) ------------------------*)

(* p (CT side, NoHeaderReceived) receives the peer's Hdr -> HeaderReceived.     *)
RecvHeader_CT(p) ==
    LET m == [ to |-> p, epoch |-> epoch[p], type |-> "Hdr" ] IN
    /\ state[p] = "NoHeaderReceived"
    /\ InFlight(m)
    /\ net' = Take(m)
    /\ state' = [ state EXCEPT ![p] = "HeaderReceived" ]
    /\ UNCHANGED << epoch, keys >>

(* T7: p (CT side, HeaderReceived) sends ct1 and EMITS its key (encaps1).       *)
(* Epoch does NOT advance here (matches braid.py: send-side never increments).  *)
(* p moves to Ct1Sampled and will then receive ek and send ct2.                 *)
SendCt1_emit(p) ==
    /\ state[p] = "HeaderReceived"
    /\ net' = Put([ to |-> Other(p), epoch |-> epoch[p], type |-> "Ct1" ])
    /\ keys' = [ keys EXCEPT ![p] = @ \cup { << epoch[p], KeyOf(epoch[p]) >> } ]
    /\ state' = [ state EXCEPT ![p] = "Ct1Sampled" ]
    /\ UNCHANGED epoch

(* p (CT side, Ct1Sampled) receives the ek_vector (EkCt1Ack) -> Ct2Sampled.     *)
(* (Collapses transitions 8/9/10/11/12 -> the ek arrives, ct2 is generated.)    *)
RecvEk_CT(p) ==
    LET m == [ to |-> p, epoch |-> epoch[p], type |-> "EkCt1Ack" ] IN
    /\ state[p] = "Ct1Sampled"
    /\ InFlight(m)
    /\ net' = Take(m)
    /\ state' = [ state EXCEPT ![p] = "Ct2Sampled" ]
    /\ UNCHANGED << epoch, keys >>

(* p (CT side, Ct2Sampled) sends ct2 chunks. We model the ct2 emission as       *)
(* a Put that does NOT change state (it can send many ct2 objects; the bag      *)
(* may carry duplicates -- exactly the duplication the channel is allowed).     *)
SendCt2(p) ==
    /\ state[p] = "Ct2Sampled"
    /\ net' = Put([ to |-> Other(p), epoch |-> epoch[p], type |-> "Ct2" ])
    /\ UNCHANGED << state, epoch, keys >>

(* T13: p (CT side, Ct2Sampled) sees a message for epoch+1 -> KeysUnsampled,     *)
(* epoch += 1. In the real code the trigger is "received a message whose epoch  *)
(* is epoch+1". We model that as: the OTHER party has already advanced to        *)
(* epoch[p]+1 (i.e. it started the next epoch). p flips to the EK side.          *)
(* No key emitted here (p's key for this epoch was emitted at SendCt1_emit).     *)
AdvanceCT(p) ==
    /\ state[p] = "Ct2Sampled"
    /\ epoch[Other(p)] = epoch[p] + 1
    /\ epoch' = [ epoch EXCEPT ![p] = @ + 1 ]
    /\ state' = [ state EXCEPT ![p] = "KeysUnsampled" ]
    /\ UNCHANGED << keys, net >>

(*--- The adversarial / lossy channel ---------------------------------------*)

(* Drop: the network silently discards one in-flight message.                  *)
DropMsg ==
    \E m \in Msg :
        /\ InFlight(m)
        /\ net' = Take(m)
        /\ UNCHANGED << state, epoch, keys >>

(* Duplicate: the network re-injects an extra copy of an in-flight message.     *)
(* (Reorder is automatic: every Recv_* picks ANY present message of the right   *)
(*  type, so there is no FIFO assumption.)                                      *)
DupMsg ==
    \E m \in Msg :
        /\ InFlight(m)
        /\ net' = Put(m)
        /\ UNCHANGED << state, epoch, keys >>

(*===========================================================================*)
(* NEXT                                                                       *)
(*===========================================================================*)
(* Bound the model: stop generating new protocol steps once a party would      *)
(* exceed MaxEpoch. The guards `epoch[p] <= MaxEpoch` keep the state space      *)
(* finite for TLC / Apalache.                                                  *)
Protocol(p) ==
    /\ epoch[p] <= MaxEpoch
    /\ \/ SendHeader(p)
       \/ RecvCt1_EK(p)
       \/ SendEk_EK(p)
       \/ RecvCt2_EK(p)
       \/ RecvHeader_CT(p)
       \/ SendCt1_emit(p)
       \/ RecvEk_CT(p)
       \/ SendCt2(p)
       \/ AdvanceCT(p)

Next ==
    \/ \E p \in Parties : Protocol(p)
    \/ DropMsg
    \/ DupMsg

(*===========================================================================*)
(* FAIRNESS + SPEC                                                            *)
(*===========================================================================*)
(* For LIVENESS we need two things:                                            *)
(*  (1) Weak fairness on each party's protocol steps -- a continuously-enabled  *)
(*      Send/Recv eventually happens (the parties keep running).               *)
(*  (2) A FAIR-CHANNEL assumption: the adversary cannot drop EVERY copy of a    *)
(*      needed message forever. We encode the fair channel as STRONG FAIRNESS   *)
(*      of the *delivery* (Recv_*) actions: if a delivering action is enabled   *)
(*      infinitely often (i.e. a usable copy keeps being available), it         *)
(*      eventually fires. Combined with WF on the senders (which keep re-sending *)
(*      ct2 / re-driving the pipeline) this gives PROGRESS.                     *)
(*                                                                            *)
(*  IMPORTANT MODELLING CAVEAT (TODO(human) to validate): a purely adversarial  *)
(*  Drop action can starve delivery (drop each copy before it is consumed).     *)
(*  Strong fairness on the Recv_* actions is what rules that out -- it says      *)
(*  "delivery wins infinitely often". A human should confirm with TLC that this *)
(*  fairness is (a) strong enough to prove Progress and (b) not so strong that   *)
(*  it trivialises the channel (it should still ALLOW finite loss/reorder/dup).  *)
(*---------------------------------------------------------------------------*)

PartyDeliver(p) ==
    \/ RecvCt1_EK(p) \/ RecvCt2_EK(p)
    \/ RecvHeader_CT(p) \/ RecvEk_CT(p) \/ AdvanceCT(p)

PartySend(p) ==
    \/ SendHeader(p) \/ SendEk_EK(p) \/ SendCt1_emit(p) \/ SendCt2(p)

Fairness ==
    /\ \A p \in Parties : WF_vars(PartySend(p))
    /\ \A p \in Parties : SF_vars(PartyDeliver(p))

Spec == Init /\ [][Next]_vars /\ Fairness

(*===========================================================================*)
(* SAFETY INVARIANTS                                                          *)
(*===========================================================================*)

(* AGREEMENT: whenever BOTH parties have output a key for the SAME epoch e,    *)
(* those keys are equal. Because each party stores <<e, KeyOf(e)>> and KeyOf    *)
(* is a function of e only, this holds iff the state machine never lets the     *)
(* two parties emit keys for the same e under disagreeing epoch bookkeeping.    *)
(* (KeyOf is the abstract proxy for the real KDF/KEM equality -- see header.)   *)
Agreement ==
    \A e \in 1..MaxEpoch :
        (HasKeyFor("Alice", e) /\ HasKeyFor("Bob", e)) =>
            ( { k \in keys["Alice"] : k[1] = e }
              = { k \in keys["Bob"] : k[1] = e } )

(* UNIQUENESS: each party outputs AT MOST ONE key per epoch. With the abstract  *)
(* KeyOf this reduces to "at most one stored pair has first component e".       *)
Uniqueness ==
    \A p \in Parties :
        \A e \in 1..MaxEpoch :
            Cardinality({ k \in keys[p] : k[1] = e }) <= 1

(* MONOTONE + GAPLESS epochs: a party's emitted-key epochs form a prefix         *)
(* 1..n with no gaps. Equivalently: if a party has a key for epoch e>1 then it    *)
(* also has one for e-1.                                                          *)
MonotoneGapless ==
    \A p \in Parties :
        \A e \in 2..MaxEpoch :
            HasKeyFor(p, e) => HasKeyFor(p, e - 1)

(* Convenience conjunction for `apalache-mc check --inv=Inv`. *)
Inv == TypeOK /\ Agreement /\ Uniqueness /\ MonotoneGapless

(*===========================================================================*)
(* LIVENESS / TEMPORAL PROPERTIES (check with TLC, NOT Apalache)              *)
(*===========================================================================*)

(* PROGRESS: for every bounded epoch e, EVENTUALLY both parties agree on        *)
(* (emit a key for) epoch e. This is the "both parties eventually agree on       *)
(* epoch e for increasing e" liveness goal, instantiated up to MaxEpoch.        *)
Progress ==
    \A e \in 1..MaxEpoch :
        <> ( HasKeyFor("Alice", e) /\ HasKeyFor("Bob", e) )

(* NO DEADLOCK: the system never reaches a state from which no protocol step     *)
(* is possible *before* both parties have finished all bounded epochs. We state  *)
(* it as: it is always the case that either we are "done" (both reached the       *)
(* bound) or some Protocol(p)/channel step is enabled.                           *)
Done ==
    \A p \in Parties : epoch[p] > MaxEpoch \/ HasKeyFor(p, MaxEpoch)

NoDeadlock ==
    [] ( Done \/ ENABLED Next )

(*****************************************************************************)
(* OPEN TODOs FOR A HUMAN (do not treat any property above as verified):     *)
(*  1. RUN IT. Neither TLC nor Apalache has been executed on this file. Run    *)
(*     TLC with SCKA.cfg and fix any genuine counterexamples (they may reveal   *)
(*     real modelling bugs in the collapsed transitions).                       *)
(*  2. VALIDATE THE FAIRNESS. Confirm SF on PartyDeliver is exactly the          *)
(*     "fair channel" assumption you want, and that Progress fails WITHOUT it    *)
(*     (sanity check that the hypothesis is load-bearing, not vacuous).         *)
(*  3. APALACHE TYPES. Add `\* @type:` annotations (CONSTANT MaxEpoch : Int;     *)
(*     the Msg record; the keys-set element type) for a clean `apalache-mc       *)
(*     typecheck`, then `apalache-mc check --inv=Inv`.                           *)
(*  4. CHANNEL FINITENESS. `net \in [Msg -> Nat]` has unbounded counts;          *)
(*     constrain copies (e.g. net[m] <= MaxCopies in the .cfg via a state         *)
(*     constraint) so TLC's state space stays finite -- see SCKA.cfg.            *)
(*  5. REFINE THE COLLAPSED STATES if you want the full 11-state granularity    *)
(*     and the per-chunk erasure threshold (replace booleans with chunk          *)
(*     counters; split EK vs EK_CT1_ACK per transitions 8/9/10/11/12).          *)
(*  6. OPTIONAL: add a `Forge` action (guarded, off by default) to confirm the   *)
(*     machine HALTS rather than advances on unexpected messages, mirroring the  *)
(*     Python "MAC verification failure => session halts" behaviour.            *)
(*  7. AGREEMENT CAVEAT. Remember KeyOf(e) is an ABSTRACT stand-in; this model   *)
(*     proves the state-machine discipline, NOT cryptographic key equality.     *)
(*     The cryptographic equality is the job of Tamarin/EasyCrypt (spec §A).     *)
(*****************************************************************************)

=============================================================================
