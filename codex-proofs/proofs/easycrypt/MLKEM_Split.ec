(* ==========================================================================
   MLKEM_Split.ec  --  EasyCrypt SKELETON (SCAFFOLD, NOT MACHINE-CHECKED)

   Goal: state, in EasyCrypt, that the ML-KEM Braid "incremental split" KEM
   (encaps1 producing ct1 from the header, encaps2 producing ct2 from
   ek_vector) is IND-CCA-secure by a tight, advantage-preserving reduction to
   standard FIPS-203 ML-KEM.  The accompanying prose is in PROOF_SKETCH.md.

   ----------------------------------------------------------------------------
   STATUS / HEALTH WARNING
     * This file was authored WITHOUT a local EasyCrypt toolchain. It is NOT
       guaranteed to typecheck or parse.  Treat every `admit` / `axiom` as an
       OPEN proof obligation, not a discharged fact.
     * The central obligation is `split_eq` (Lemma 1 in PROOF_SKETCH.md): the
       split produces the SAME (K, ct1||ct2) bytes as standard ML-KEM for the
       same FO message m.  It is currently an `axiom` whose ONLY evidence is the
       empirical unit test tests/test_kem.py::test_split_equals_reference_monolithic.
       A human MUST discharge it against the FIPS-203 K-PKE.Encrypt equations
       (Algorithm 14), ideally by reusing the verified K-PKE spec from
       formosa-mlkem (github.com/formosa-crypto/formosa-mlkem) or libcrux/hax.

   HOW TO CHECK
     opam pin add -n easycrypt https://github.com/EasyCrypt/easycrypt.git
     opam install easycrypt
     easycrypt why3config
     easycrypt -I . MLKEM_Split.ec
   Expect: every `admit`/`axiom` remains an open hole; the main theorem is
   `admit`ted.  A clean *load* is NOT a proof.

   SOURCE MAP (normative, byte-exact):
     docs/PROTOCOL_SPEC.md                       -- protocol abstraction, sec.2
     ml_kem_braid/core/ml_kem.py:178-247         -- encaps1 / encaps2 / decaps
     kyber_py/ml_kem/ml_kem.py:215-265,341-365   -- _k_pke_encrypt, _encaps_internal
     tests/test_kem.py:40-60                      -- the empirical byte-equality test
   ========================================================================== *)

require import AllCore Distr DInterval List FSet SmtMap.
(* `Bool` etc. come in via AllCore; adjust requires to your EC stdlib version. *)

(* --------------------------------------------------------------------------
   0. Abstract byte/value types.

   We deliberately model the data as ABSTRACT types, not as the concrete
   lattice objects, EXCEPT where the split-vs-standard equality lives.  What is
   MODELED: the KEM interface, the IND-CCA game, the reduction, the equality
   obligation.  What is ABSTRACTED AWAY: the lattice algebra of K-PKE itself
   (Module-LWE, NTT, CBD sampling, compression) -- that lives in the FIPS-203
   theory we reduce TO (assumption A1, see PROOF_SKETCH.md sec.7).
   -------------------------------------------------------------------------- *)

type ek_t.        (* encapsulation key  = ek_vector || ek_seed  (384k+32 bytes) *)
type dk_t.        (* decapsulation key  (768k+96 bytes), private                *)
type ekseed_t.    (* ek_seed = rho      (32 bytes, public header field)         *)
type ekvec_t.     (* ek_vector = Encode_12(t_hat)  (384k bytes)                 *)
type hek_t.       (* hek = SHA3-256(ek) (32 bytes, public header field)         *)
type ct_t.        (* full ciphertext bytes  ct1 || ct2                          *)
type ct1_t.       (* u-component ciphertext (32*du*k bytes)                     *)
type ct2_t.       (* v-component ciphertext (32*dv bytes)                       *)
type key_t.       (* shared secret K    (32 bytes)                              *)
type msg_t.       (* FO message m       (32 bytes); challenge randomness        *)
type es_t.        (* EncapsulationSecret: in-memory (m, y_hat, e2, K); NEVER on wire *)

(* The uniform distribution on shared secrets (for the "random key" world of
   the IND-CCA real-or-random game) and on FO messages m. *)
op [lossless full uniform] dkey : key_t distr.
op [lossless full uniform] dmsg : msg_t distr.

(* Concatenation of the two ciphertext halves into the canonical ML-KEM
   ciphertext.  This is the byte concatenation ct1 || ct2 from the code
   (ml_kem.py:247 `ct1 + ct2`).  Modeled as an abstract, INJECTIVE pairing. *)
op cat : ct1_t -> ct2_t -> ct_t.
axiom cat_inj c1 c1' c2 c2' : cat c1 c2 = cat c1' c2' => c1 = c1' /\ c2 = c2'.

(* Splitting an ek into its header seed and vector (ek[-32:], ek[:-32]) and the
   header hash hek = H(ek).  Pure public functions of ek. *)
op ek_seed_of : ek_t -> ekseed_t.       (* ek[-32:]            *)
op ek_vec_of  : ek_t -> ekvec_t.        (* ek[:-32]            *)
op hek_of     : ek_t -> hek_t.          (* SHA3-256(ek)        *)

(* ==========================================================================
   1. KEM module types.
   ========================================================================== *)

(* 1a. Standard FIPS-203 ML-KEM interface (this is `Pi` in PROOF_SKETCH.md). *)
module type KEM = {
  proc keygen() : ek_t * dk_t
  proc encaps(ek : ek_t) : key_t * ct_t          (* = _encaps_internal w/ random m *)
  proc decaps(dk : dk_t, c : ct_t) : key_t       (* = _decaps_internal, implicit rej *)
}.

(* 1b. The Braid incremental SPLIT interface (this is `Sigma`).
   encaps1 yields (es, ct1, K) from the header (ek_seed, hek) and FO msg m;
   encaps2 yields ct2 from es + ek_vector.  decaps is identical to standard. *)
module type SplitKEM = {
  proc keygen() : ek_t * dk_t
  proc encaps1(ek_seed : ekseed_t, hek : hek_t, m : msg_t) : es_t * ct1_t * key_t
  proc encaps2(es : es_t, ek_seed : ekseed_t, ek_vec : ekvec_t) : ct2_t
  proc decaps(dk : dk_t, c : ct_t) : key_t
}.

(* ==========================================================================
   2. Concrete (abstract-bodied) modules tying the two interfaces together.

   We do NOT implement the lattice math.  We declare the split's procedures as
   `op`-backed deterministic functions of their inputs (encaps1 is randomized
   only via its explicit m argument; the protocol samples m externally), and we
   pin down their relationship to the standard KEM via the `split_eq` axiom.
   ========================================================================== *)

(* Deterministic cores of the split (m is an explicit input; matches the code
   where encaps1(..., m=...) is deterministic given m, ek_seed, hek). *)
op encaps1_core : ekseed_t -> hek_t -> msg_t -> (es_t * ct1_t * key_t).
op encaps2_core : es_t -> ekseed_t -> ekvec_t -> ct2_t.

(* Deterministic core of standard ML-KEM encapsulation given m
   (= _encaps_internal(ek, m), kyber_py/ml_kem.py:341-365): returns (K, ct). *)
op encaps_core : ek_t -> msg_t -> (key_t * ct_t).

(* Shared decapsulation (both Pi and Sigma call _decaps_internal). *)
op decaps_core : dk_t -> ct_t -> key_t.

(* Shared key generation distribution (honest ek,dk pairs). *)
op [lossless] dkeygen : (ek_t * dk_t) distr.

(* ----- the standard KEM instance Pi ------------------------------------- *)
module MLKEM : KEM = {
  proc keygen() : ek_t * dk_t = { var kp; kp <$ dkeygen; return kp; }

  proc encaps(ek : ek_t) : key_t * ct_t = {
    var m, K, c;
    m <$ dmsg;                       (* m <- random_bytes(32)             *)
    (K, c) <- encaps_core ek m;      (* = _encaps_internal(ek, m)         *)
    return (K, c);
  }

  proc decaps(dk : dk_t, c : ct_t) : key_t = {
    return decaps_core dk c;         (* = _decaps_internal(dk, c)         *)
  }
}.

(* ----- the split KEM instance Sigma ------------------------------------- *)
module MLKEMSplit : SplitKEM = {
  proc keygen() : ek_t * dk_t = { var kp; kp <$ dkeygen; return kp; }

  proc encaps1(ek_seed : ekseed_t, hek : hek_t, m : msg_t)
      : es_t * ct1_t * key_t = {
    return encaps1_core ek_seed hek m;
  }

  proc encaps2(es : es_t, ek_seed : ekseed_t, ek_vec : ekvec_t) : ct2_t = {
    return encaps2_core es ek_seed ek_vec;
  }

  proc decaps(dk : dk_t, c : ct_t) : key_t = {
    return decaps_core dk c;         (* IDENTICAL op to MLKEM.decaps      *)
  }
}.

(* A whole-ciphertext "EncapsSplit" wrapper so Sigma fits the same (K, c) shape
   as Pi.  This is the `EncapsSplit` of PROOF_SKETCH.md sec.2: run encaps1 then
   encaps2 and concatenate.  Note m is sampled here, exactly as in MLKEM.encaps. *)
module SplitEncaps = {
  proc encaps(ek : ek_t) : key_t * ct_t = {
    var m, es, ct1, ct2, K;
    m <$ dmsg;
    (es, ct1, K) <- encaps1_core (ek_seed_of ek) (hek_of ek) m;
    ct2          <- encaps2_core es (ek_seed_of ek) (ek_vec_of ek);
    return (K, cat ct1 ct2);
  }
}.

(* ==========================================================================
   3. THE CENTRAL OBLIGATION -- Lemma 1, byte-for-byte equality.

   For every ek and every m, the split's (K, ct1||ct2) equals standard
   ML-KEM's (K, c).  This is the ONLY split-specific cryptographic content; the
   reduction in sec.5 is otherwise an identity.

   >>> THIS IS AN AXIOM = AN OPEN PROOF OBLIGATION ("admit"). <<<
   It must be discharged from the FIPS-203 K-PKE.Encrypt equations.  See the
   term-by-term table in PROOF_SKETCH.md sec.4 and TODO-LEMMA1 / TODO-VALIDATION
   in sec.8.  Current evidence = ONE unit test, which is NOT a proof.

   SIDE CONDITION (TODO-VALIDATION, A6): as stated this quantifies over ALL ek.
   The split's encaps2 does not re-run the FIPS-203 modulus check
   (t_hat.encode(12) == t_hat_bytes) that _k_pke_encrypt does
   (kyber_py/ml_kem.py:242). For the IND-CCA reduction this is harmless because
   the challenger's ek is honestly generated (canonical), but a faithful proof
   must EITHER restrict ek to `is_canonical ek` OR prove identical rejection.
   We expose the predicate and keep the axiom guarded by it. *)

op is_canonical : ek_t -> bool.   (* ek = Encode_12(Decode_12(ek_vec)) || ek_seed *)

(* Honest keygen only ever outputs canonical ek (true for FIPS-203 KeyGen). *)
axiom dkeygen_canonical :
  forall ek dk, (ek, dk) \in dkeygen => is_canonical ek.

(* Lemma 1 (split_eq) -- ADMITTED.  TODO-LEMMA1 / TODO-VALIDATION. *)
axiom split_eq (ek : ek_t) (m : msg_t) :
  is_canonical ek =>
  let (es, ct1, K) = encaps1_core (ek_seed_of ek) (hek_of ek) m in
  let ct2          = encaps2_core es (ek_seed_of ek) (ek_vec_of ek) in
  (K, cat ct1 ct2) = encaps_core ek m.

(* Lemma (decaps_eq) -- TRIVIAL/SYNTACTIC but still ADMITTED (TODO-DECAPS, A3).
   Both MLKEM.decaps and MLKEMSplit.decaps call the SAME op decaps_core, which
   models _decaps_internal (ml_kem.py:247). This is here so the reduction may
   forward decaps queries verbatim. Discharge by `reflexivity`/code identity. *)
lemma decaps_eq (dk : dk_t) (c : ct_t) :
  decaps_core dk c = decaps_core dk c.
proof. trivial. qed.   (* the *interesting* content is that BOTH modules use it *)

(* ==========================================================================
   4. IND-CCA game (real-or-random key), parametric in the encaps procedure.

   Standard one-bit IND-CCA: challenger encapsulates honestly to get (K0, c*),
   draws K1 uniform, gives the adversary (ek, c*, K_b), answers decaps on any
   c <> c*. The adversary's two oracles are modeled by the ADV module type.
   ========================================================================== *)

module type CCA_Oracles = {
  proc decaps(c : ct_t) : key_t          (* refuses the challenge c*         *)
}.

module type CCA_Adv (O : CCA_Oracles) = {
  proc guess(ek : ek_t, c_star : ct_t, k : key_t) : bool
}.

(* Generic IND-CCA experiment for an arbitrary "Encaps" procedure E with the
   shape  proc encaps(ek) : key_t * ct_t.  We instantiate E with MLKEM.encaps
   (the standard game G_Pi) and with SplitEncaps.encaps (the split game G_Sigma).
   The decaps oracle and the keygen are shared (decaps_core / dkeygen). *)
module CCA_Game
  (E : KEM)              (* uses E.keygen and E.encaps; E.decaps ignored here *)
  (A : CCA_Adv) = {

  var dk_g  : dk_t
  var cstar : ct_t

  module O : CCA_Oracles = {
    proc decaps(c : ct_t) : key_t = {
      var r;
      r <- witness;
      if (c <> CCA_Game.cstar) {       (* refuse the challenge ciphertext   *)
        r <- decaps_core CCA_Game.dk_g c;
      }
      return r;
    }
  }

  proc main() : bool = {
    var ek, dk, K0, K1, b, b', kb;
    (ek, dk)      <@ E.keygen();
    CCA_Game.dk_g <- dk;
    (K0, CCA_Game.cstar) <@ E.encaps(ek);
    K1 <$ dkey;
    b  <$ {0,1};
    kb <- (b ? K1 : K0);
    b' <@ A(O).guess(ek, CCA_Game.cstar, kb);
    return (b' = b);
  }
}.

(* To slot SplitEncaps (which is not a full KEM module) into CCA_Game, wrap it
   as a KEM whose keygen/decaps reuse the shared cores and whose encaps is the
   split wrapper.  This is `Sigma` as a KEM. *)
module SigmaKEM : KEM = {
  proc keygen() : ek_t * dk_t      = { var kp; kp <$ dkeygen; return kp; }
  proc encaps(ek : ek_t) : key_t * ct_t = { var r; r <@ SplitEncaps.encaps(ek); return r; }
  proc decaps(dk : dk_t, c : ct_t) : key_t = { return decaps_core dk c; }
}.

(* ==========================================================================
   5. The reduction B: turns a split-adversary A into a standard-KEM adversary.

   B is the IDENTITY forwarder (PROOF_SKETCH.md sec.5): it relays ek, c*, k_b
   to A and relays A's decaps queries to its own oracle.  Because of split_eq
   the challenge it receives from the standard challenger is distributed exactly
   as the one A expects from the split challenger; because decaps is the same
   op, the oracle is identical.
   ========================================================================== *)

module B (A : CCA_Adv) (O : CCA_Oracles) = {
  proc guess(ek : ek_t, c_star : ct_t, k : key_t) : bool = {
    var b';
    (* No transformation whatsoever: forward inputs and the oracle to A. *)
    b' <@ A(O).guess(ek, c_star, k);
    return b';
  }
}.

(* ==========================================================================
   6. MAIN THEOREM (advantage equality) -- ADMITTED.

   For every A:  Adv^{INDCCA}_{Sigma}(A) = Adv^{INDCCA}_{Pi}(B(A)).
   We state it as equality of the two `main` success probabilities (the 1/2
   subtraction cancels), then the advantage statement is a corollary.

   PROOF PLAN (the game hops; each `byequiv`/`rewrite` step below is currently
   an `admit`):
     Hop 0->1 : replace SigmaKEM.encaps (=SplitEncaps) by MLKEM.encaps using
                `split_eq` + `dkeygen_canonical`.  Perfect: same (K, c) for the
                same sampled m, so the two `main` programs are observationally
                equivalent.  ==> CCA_Game(SigmaKEM, A) ~ CCA_Game(MLKEM, B(A)).
     Hop 1->2 : the decaps oracle is already identical (shared decaps_core), and
                B forwards A verbatim, so CCA_Game(MLKEM, B(A)) IS the standard
                game.  Conclude equality of probabilities.
   ========================================================================== *)

(* Pr-equality form (what `byequiv` would establish): *)
lemma split_indcca_eq (A <: CCA_Adv{-CCA_Game}) &m :
    Pr[CCA_Game(SigmaKEM, A).main() @ &m : res]
  = Pr[CCA_Game(MLKEM, B(A)).main() @ &m : res].
proof.
  (* TODO-MAIN: discharge by two byequiv hops.
     Step 1: byequiv on CCA_Game(SigmaKEM,A).main ~ CCA_Game(MLKEM, B(A)).main.
       - keygen: same (dkeygen). align ek,dk.
       - challenge: rewrite the split encaps body to the standard one using
         `split_eq (ek) (m)` under `dkeygen_canonical` (canonical ek), giving
         equal (K0, cstar) for the same m. The K1, b, kb draws are identical.
       - oracle: both call decaps_core on the same dk_g, refusing the same
         cstar; B forwards A's calls unchanged, so the oracles are equal.
       - guess: B(A).guess just calls A(O).guess with identical arguments.
     This requires aligning the `m <$ dmsg` sampling on both sides (single
     coupling) so the cores receive the same m. *)
  admit. (* sorry -- see PROOF_SKETCH.md sec.5 and TODO-MAIN *)
qed.

(* Advantage corollary.  With Adv = |Pr[main]-1/2|, equality of Pr[main] gives
   equality of advantages immediately. *)
lemma split_indcca_adv (A <: CCA_Adv{-CCA_Game}) &m :
    `| Pr[CCA_Game(SigmaKEM, A).main() @ &m : res] - 1%r/2%r |
  = `| Pr[CCA_Game(MLKEM, B(A)).main() @ &m : res] - 1%r/2%r |.
proof.
  by rewrite (split_indcca_eq A &m).
qed.

(* ==========================================================================
   7. (Optional) Tie to the FIPS-203 IND-CCA assumption A1.

   If you import a machine-checked ML-KEM IND-CCA result (formosa-mlkem /
   libcrux-via-hax), replace this axiom with that theorem's conclusion to obtain
   a CONCRETE bound on the split's advantage rather than a relative one.
   Until then this is ASSUMED (TODO-INDCCA-A1, assumption A1). *)
axiom mlkem_indcca (D <: CCA_Adv{-CCA_Game}) &m :
  `| Pr[CCA_Game(MLKEM, D).main() @ &m : res] - 1%r/2%r | <= eps_mlkem.
  (* where `op eps_mlkem : real` is the FIPS-203 ML-KEM-P IND-CCA bound;
     declare it as `op eps_mlkem : real.` and instantiate from the imported
     theory.  Left abstract here. *)

(* Corollary: the split inherits the same concrete bound (tight, no loss). *)
lemma split_indcca_bound (A <: CCA_Adv{-CCA_Game}) &m :
  `| Pr[CCA_Game(SigmaKEM, A).main() @ &m : res] - 1%r/2%r | <= eps_mlkem.
proof.
  rewrite (split_indcca_adv A &m).
  by apply (mlkem_indcca (B(A)) &m).
qed.

(* ==========================================================================
   8. Early-ct1-leak (Lemma 2) -- OUT OF THIS GAME, recorded as a TODO.

   The IND-CCA game above already hands A the whole c* = cat ct1 ct2, so it
   covers "A sees ct1".  The PROTOCOL emits ct1 before ct2 exists; that ORDERING
   argument (Lemma 2, PROOF_SKETCH.md sec.6) belongs in the SCKA protocol model
   with explicit message scheduling (Tamarin / a stateful EasyCrypt module), NOT
   in this pure-KEM file.  Stated here only as documentation. *)

(* ct1 is a deterministic public function of (ek_seed, hek, m): A could compute
   it itself.  Hence releasing it early adds no advantage over the atomic c*. *)
axiom ct1_is_public_fn (ek_seed : ekseed_t) (hek : hek_t) (m : msg_t) :
  exists (f : ekseed_t -> hek_t -> msg_t -> ct1_t),
    let (es, ct1, K) = encaps1_core ek_seed hek m in ct1 = f ek_seed hek m.
(* Trivially true (encaps1_core is a function); kept as a reminder that ct1
   carries no secret-key-dependent information beyond c*.  The real ordering
   argument is TODO-EARLYLEAK in PROOF_SKETCH.md sec.8, to be done in the SCKA
   model. *)

(* ==========================================================================
   END.  Open holes:  split_eq (A2, the real one), decaps identity usage (A3),
   split_indcca_eq main hops (TODO-MAIN), mlkem_indcca instantiation (A1),
   canonical-ek side condition (A6), early-leak ordering (A5, other model).
   ========================================================================== *)
