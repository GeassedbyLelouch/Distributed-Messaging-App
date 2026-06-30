(* ==========================================================================
   MLKEM_Split.ec  --  EasyCrypt model: the ML-KEM Braid incremental split
   (Encaps1 producing ct1 from the 64-byte header, Encaps2 producing ct2 from
   the ek_vector) is IND-CCA-EQUIVALENT to standard FIPS-203 ML-KEM, via a
   TIGHT, advantage-preserving (identity) reduction.

   Companion prose: claude-proofs/easycrypt/PROOF_SKETCH.md
   Empirical backbone of Lemma 1: claude-proofs/kem_split/verify_split_indcca.py
     (1800/1800 byte-for-byte matches: ct1||ct2 == _encaps_internal(ek,m), all
      three parameter sets, 200 random m * 3 keypairs each).

   STATUS / HEALTH WARNING
     * Authored WITHOUT a local EasyCrypt toolchain (opam/why3/SMT were not
       installed in the build environment), so this file is NOT guaranteed to
       typecheck. Every `axiom`/`admit` is an OPEN obligation, not a fact.
     * The one real obligation is `split_eq` (Lemma 1): the split yields the
       SAME (K, ct1||ct2) bytes as standard ML-KEM for the same FO message m.
       It is currently an `axiom` whose evidence is the kem_split harness; a
       human must discharge it against the FIPS-203 K-PKE.Encrypt equations
       (Algorithm 14), ideally by reusing the verified K-PKE spec from
       formosa-mlkem (github.com/formosa-crypto/formosa-mlkem).

   HOW TO CHECK
     opam pin add -n easycrypt https://github.com/EasyCrypt/easycrypt.git
     opam install easycrypt && easycrypt why3config
     easycrypt -I . MLKEM_Split.ec
   Expect: every axiom/admit remains an open hole; a clean *load* is NOT a proof.

   SOURCE MAP (byte-exact):
     ml_kem_braid/core/ml_kem.py:178-247       encaps1 / encaps2 / decaps
     kyber_py/ml_kem/ml_kem.py                  _k_pke_encrypt, _encaps_internal
     tests/test_kem.py:test_split_equals_reference_monolithic   empirical Lemma 1
   ========================================================================== *)

require import AllCore Distr.

(* ----- abstract byte/value types (the lattice algebra lives in the FIPS-203
   theory we reduce TO; here only the KEM interface + reduction are modelled) - *)
type ek_t.        (* encapsulation key = ek_vector || ek_seed *)
type dk_t.        (* decapsulation key, private *)
type ekseed_t.    (* ek_seed = rho   (ek[-32:]) *)
type ekvec_t.     (* ek_vector = Encode_12(t_hat)  (ek[:-32]) *)
type hek_t.       (* hek = SHA3-256(ek) *)
type ct_t.        (* full ciphertext ct1 || ct2 *)
type ct1_t.       (* u-component *)
type ct2_t.       (* v-component *)
type key_t.       (* shared secret K (32 bytes) *)
type msg_t.       (* FO message m (32 bytes) *)
type es_t.        (* EncapsulationSecret (m, y_hat, e2, K) -- NEVER on the wire *)

(* uniform distributions on the shared-secret space and on FO messages *)
op [lossless full uniform] dkey : key_t distr.
op [lossless full uniform] dmsg : msg_t distr.
op [lossless] dkeygen : (ek_t * dk_t) distr.

(* public, pure functions of ek (ek[-32:], ek[:-32], SHA3-256(ek)) *)
op ek_seed_of : ek_t -> ekseed_t.
op ek_vec_of  : ek_t -> ekvec_t.
op hek_of     : ek_t -> hek_t.

(* injective byte concatenation ct1 || ct2 = the canonical ML-KEM ciphertext *)
op cat : ct1_t -> ct2_t -> ct_t.
axiom cat_inj c1 c1' c2 c2' : cat c1 c2 = cat c1' c2' => c1 = c1' /\ c2 = c2'.

(* deterministic cores (m an explicit input -- encaps1(...,m) is deterministic) *)
op encaps1_core : ekseed_t -> hek_t -> msg_t -> (es_t * ct1_t * key_t).
op encaps2_core : es_t -> ekseed_t -> ekvec_t -> ct2_t.
op encaps_core  : ek_t -> msg_t -> (key_t * ct_t).   (* = _encaps_internal(ek,m) *)
op decaps_core  : dk_t -> ct_t -> key_t.             (* = _decaps_internal       *)

(* honest FIPS-203 KeyGen only ever outputs canonical encapsulation keys *)
op is_canonical : ek_t -> bool.
axiom dkeygen_canonical ek dk : (ek, dk) \in dkeygen => is_canonical ek.

(* ==========================================================================
   LEMMA 1 (split_eq) -- THE ONLY SPLIT-SPECIFIC OBLIGATION.  ADMITTED.
   For canonical ek and every m, the split's (K, ct1||ct2) equals standard
   ML-KEM's (K, c).  Evidence: kem_split harness (1800/1800 exact matches).
   To discharge: prove from FIPS-203 K-PKE.Encrypt that encaps1 then encaps2
   compute the SAME (u, v) polynomials as _k_pke_encrypt (term-by-term table in
   PROOF_SKETCH.md sec.4).  The canonical-ek guard handles the input-validation
   delta (encaps2 omits the t_hat re-encode check); harmless for IND-CCA since
   the challenger's ek is honestly generated.
   ========================================================================== *)
axiom split_eq (ek : ek_t) (m : msg_t) :
  is_canonical ek =>
  let (es, ct1, k) = encaps1_core (ek_seed_of ek) (hek_of ek) m in
  let ct2 = encaps2_core es (ek_seed_of ek) (ek_vec_of ek) in
  (k, cat ct1 ct2) = encaps_core ek m.

(* ----- KEM interface ----- *)
module type KEM = {
  proc keygen() : ek_t * dk_t
  proc encaps(ek : ek_t) : key_t * ct_t
  proc decaps(dk : dk_t, c : ct_t) : key_t
}.

(* standard FIPS-203 ML-KEM (Pi) *)
module MLKEM : KEM = {
  proc keygen() : ek_t * dk_t = { var kp; kp <$ dkeygen; return kp; }
  proc encaps(ek : ek_t) : key_t * ct_t = {
    var m, k, c; m <$ dmsg; (k, c) <- encaps_core ek m; return (k, c);
  }
  proc decaps(dk : dk_t, c : ct_t) : key_t = { return decaps_core dk c; }
}.

(* the Braid split as a KEM (Sigma): encaps = run encaps1 then encaps2, cat *)
module SigmaKEM : KEM = {
  proc keygen() : ek_t * dk_t = { var kp; kp <$ dkeygen; return kp; }
  proc encaps(ek : ek_t) : key_t * ct_t = {
    var m, es, ct1, ct2, k;
    m <$ dmsg;
    (es, ct1, k) <- encaps1_core (ek_seed_of ek) (hek_of ek) m;
    ct2          <- encaps2_core es (ek_seed_of ek) (ek_vec_of ek);
    return (k, cat ct1 ct2);
  }
  proc decaps(dk : dk_t, c : ct_t) : key_t = { return decaps_core dk c; }
}.

(* ----- IND-CCA (real-or-random key) ----- *)
module type CCA_Oracles = { proc decaps(c : ct_t) : key_t }.
module type CCA_Adv (O : CCA_Oracles) = {
  proc guess(ek : ek_t, c_star : ct_t, k : key_t) : bool
}.

module CCA_Game (E : KEM) (A : CCA_Adv) = {
  var dk_g  : dk_t
  var cstar : ct_t
  module O : CCA_Oracles = {
    proc decaps(c : ct_t) : key_t = {
      var r; r <- witness;
      if (c <> CCA_Game.cstar) { r <- decaps_core CCA_Game.dk_g c; }
      return r;
    }
  }
  proc main() : bool = {
    var ek, dk, k0, k1, b, b', kb;
    (ek, dk)             <@ E.keygen();
    CCA_Game.dk_g        <- dk;
    (k0, CCA_Game.cstar) <@ E.encaps(ek);
    k1 <$ dkey; b <$ {0,1}; kb <- (b ? k1 : k0);
    b' <@ A(O).guess(ek, CCA_Game.cstar, kb);
    return (b' = b);
  }
}.

(* ----- the reduction B: identity forwarder (PROOF_SKETCH.md sec.5) ----- *)
module B (A : CCA_Adv) (O : CCA_Oracles) = {
  proc guess(ek : ek_t, c_star : ct_t, k : key_t) : bool = {
    var b'; b' <@ A(O).guess(ek, c_star, k); return b';
  }
}.

(* ==========================================================================
   MAIN THEOREM (advantage equality) -- ADMITTED.
   Pr[CCA_Game(SigmaKEM, A)] = Pr[CCA_Game(MLKEM, B(A))].
   PROOF PLAN (two byequiv hops):
     Hop 1: rewrite SigmaKEM.encaps to MLKEM.encaps using split_eq under the
            canonical-ek guard (dkeygen_canonical): for the SAME sampled m the
            two produce equal (K, c).  Perfect coupling on m.
     Hop 2: decaps is the same op (decaps_core), B forwards A verbatim, so the
            game IS the standard one.  Probabilities equal.
   ========================================================================== *)
lemma split_indcca_eq (A <: CCA_Adv{-CCA_Game}) &m :
    Pr[CCA_Game(SigmaKEM, A).main() @ &m : res]
  = Pr[CCA_Game(MLKEM,    B(A)).main() @ &m : res].
proof.
  (* TODO-MAIN: two byequiv hops; couple the m<$dmsg sampling on both sides and
     apply split_eq (canonical ek from dkeygen_canonical) for the challenge,
     then forward decaps + guess unchanged. *)
  admit.
qed.

lemma split_indcca_adv (A <: CCA_Adv{-CCA_Game}) &m :
    `| Pr[CCA_Game(SigmaKEM, A).main() @ &m : res] - 1%r/2%r |
  = `| Pr[CCA_Game(MLKEM,    B(A)).main() @ &m : res] - 1%r/2%r |.
proof. by rewrite (split_indcca_eq A &m). qed.

(* assume / import the FIPS-203 ML-KEM IND-CCA bound (formosa-mlkem) *)
op eps_mlkem : real.
axiom mlkem_indcca (D <: CCA_Adv{-CCA_Game}) &m :
  `| Pr[CCA_Game(MLKEM, D).main() @ &m : res] - 1%r/2%r | <= eps_mlkem.

(* the split inherits the SAME concrete bound (tight, no loss) *)
lemma split_indcca_bound (A <: CCA_Adv{-CCA_Game}) &m :
  `| Pr[CCA_Game(SigmaKEM, A).main() @ &m : res] - 1%r/2%r | <= eps_mlkem.
proof. rewrite (split_indcca_adv A &m). by apply (mlkem_indcca (B(A)) &m). qed.

(* ==========================================================================
   LEMMA 2 (early-ct1 leak is benign) -- protocol-level, recorded as a TODO.
   The IND-CCA game already hands A the whole c* = cat ct1 ct2, covering "A
   sees ct1".  The protocol emits ct1 BEFORE ct2 exists; that ORDERING argument
   belongs in the SCKA model (Tamarin/Verifpal), not this pure-KEM file.  The
   premise -- ct1 is a deterministic public function of (ek_seed,hek,m), and K
   is fixed by phase 1, independent of ct2 -- is exactly what the kem_split
   harness checks empirically (Lemma2 checks: ct1=f(ek_seed,hek,m) and
   K independent of ct2, 1800/1800).
   ========================================================================== *)
axiom ct1_is_public_fn (ek_seed : ekseed_t) (hek : hek_t) (m : msg_t) :
  exists (f : ekseed_t -> hek_t -> msg_t -> ct1_t),
    let (es, ct1, k) = encaps1_core ek_seed hek m in ct1 = f ek_seed hek m.
