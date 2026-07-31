"""Trusted-proxy-aware client identification.

Audit M11 introduced a ``trusted_proxies`` allow-list for ``X-Forwarded-Proto``.
The rate limiters added by H1/M12/M13/M14 kept keying on ``request.client.host``
alone, so behind exactly the reverse proxy M11 was written to support **every
request shares one key**: all limiters collapse into a single global bucket and
one flooder starves every legitimate user.

This module is the *single* implementation of "which client is this request
from" used by both :mod:`ml_kem_braid.server.app` and
:mod:`ml_kem_braid.server.decentralized_routes`, so the two can never diverge.

Trust rules
-----------
* ``X-Forwarded-For`` is attacker-controlled.  It is consulted **only** when the
  immediate peer (the socket address) is in the trusted-proxy allow-list.  With
  the default empty allow-list the header is ignored entirely, so a direct
  client cannot mint a fresh rate-limit bucket per request by rotating a header.
* Within the chain the **right-most hop that is not itself a trusted proxy** is
  used.  The left-most entry is whatever the client claimed and can be forged;
  walking from the right stops at the last hop a trusted proxy actually
  observed.
* The number of hops parsed is bounded so a huge header cannot cost the server
  meaningful work.
"""

from __future__ import annotations

from typing import Iterable

from starlette.requests import Request

__all__ = ["client_key", "normalize_host", "normalize_trusted_proxies"]

#: Only the right-most hops can matter; parsing is bounded regardless of header size.
MAX_FORWARDED_HOPS = 32

#: Returned when the request has no usable peer address (e.g. ASGI test doubles).
UNKNOWN_CLIENT = "unknown"


def normalize_host(raw: str) -> str:
    """Normalize a host token from a socket address or forwarded chain.

    Strips whitespace, an optional ``:port`` suffix and case, and keeps
    bracketed IPv6 literals intact (``[::1]:443`` → ``[::1]``).
    """
    host = raw.strip()
    if not host:
        return ""
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            return host[: end + 1].lower()
        return host.lower()
    # A single colon is host:port; several colons means a bare IPv6 literal.
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.lower()


def normalize_trusted_proxies(values: Iterable[str]) -> frozenset[str]:
    """Normalize an allow-list so comparisons are apples-to-apples."""
    return frozenset(h for h in (normalize_host(v) for v in values) if h)


def client_key(
    request: Request, trusted_proxies: frozenset[str] = frozenset()
) -> str:
    """Rate-limit identity for ``request``.

    Returns the socket peer unless that peer is a trusted proxy, in which case
    the right-most non-proxy hop of ``X-Forwarded-For`` is returned.
    """
    client = request.client
    peer = normalize_host(client.host) if client is not None and client.host else ""
    if not peer:
        return UNKNOWN_CLIENT
    if peer not in trusted_proxies:
        # Untrusted (or direct) peer: the forwarded chain is not evidence.
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return peer
    hops = [
        host
        for host in (
            normalize_host(part)
            for part in forwarded.split(",")[-MAX_FORWARDED_HOPS:]
        )
        if host
    ]
    for hop in reversed(hops):
        if hop not in trusted_proxies:
            return hop
    # Every hop is a trusted proxy (or the header was empty after parsing):
    # fall back to the peer rather than trusting a forgeable value.
    return peer
