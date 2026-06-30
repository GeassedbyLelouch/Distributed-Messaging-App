"""Anonymous client transport wrapper for fixed three-hop circuit frames.

Task 11 intentionally validates and stores route roles only. It still uses
private fixed development keys for frame construction; production key
negotiation is outside this wrapper's current scope.
"""

from __future__ import annotations

from secrets import token_bytes
from typing import Protocol

from ml_kem_braid.decentralized.circuits import (
    CircuitFrame,
    LayerKeys,
    build_three_hop_frame,
    pad_payload,
)


_REQUIRED_ROUTE = ("entry", "middle", "exit")


class CircuitGateway(Protocol):
    def send_frame(self, frame: CircuitFrame) -> dict:
        """Send an already-built anonymous circuit frame."""


# Private Task 11 development keys. Tests may use these to peel frames, but
# these are not negotiated route keys and must not be treated as production
# circuit key material.
_DEV_LAYER_KEYS = (
    LayerKeys(hop_id="entry", key=b"dev-entry-layer-key-32-bytes!!!!"),
    LayerKeys(hop_id="middle", key=b"dev-middle-layer-key-32-bytes!!!"),
    LayerKeys(hop_id="exit", key=b"dev-exit-layer-key-32-bytes!!!!!"),
)


class AnonymousTransport:
    """Client wrapper that sends requests as padded encrypted 3-hop frames.

    The route must currently be the explicit role order
    ``("entry", "middle", "exit")``. The roles are validated and stored for
    now; frame encryption uses the module's private development-only keys.
    """

    def __init__(
        self,
        gateway: CircuitGateway,
        route: list[str] | tuple[str, str, str],
        direct_peer_endpoint: str | None = None,
    ):
        if direct_peer_endpoint is not None:
            raise ValueError("direct peer-to-peer is disabled in anonymity mode")

        route_roles = tuple(route)
        if route_roles != _REQUIRED_ROUTE:
            raise ValueError(
                "anonymous transport requires exactly three hops: entry, middle, exit"
            )

        self.gateway = gateway
        self.route = route_roles
        self.circuit_id = token_bytes(16)
        self._sequence = 0

    def send_request(self, payload: bytes) -> dict:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")

        self._sequence += 1
        padded_payload = pad_payload(payload, 1024)
        frame = build_three_hop_frame(
            circuit_id=self.circuit_id,
            payload=padded_payload,
            keys=_DEV_LAYER_KEYS,
            sequence=self._sequence,
        )
        return self.gateway.send_frame(frame)
