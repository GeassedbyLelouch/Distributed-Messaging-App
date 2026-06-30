---- MODULE OPKLease ----
EXTENDS Naturals, Sequences

CONSTANTS OPKS

VARIABLES state

Init == state = [opk \in OPKS |-> "available"]

Lease(opk) ==
  /\ state[opk] = "available"
  /\ state' = [state EXCEPT ![opk] = "leased"]

Consume(opk) ==
  /\ state[opk] = "leased"
  /\ state' = [state EXCEPT ![opk] = "consumed"]

Expire(opk) ==
  /\ state[opk] = "leased"
  /\ state' = [state EXCEPT ![opk] = "expired"]

Next == \E opk \in OPKS: Lease(opk) \/ Consume(opk) \/ Expire(opk)

NoConsumedReplay == \A opk \in OPKS: state[opk] = "consumed" => state[opk] # "available"

Spec == Init /\ [][Next]_state

====
