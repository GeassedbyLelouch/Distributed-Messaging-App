"""
HTTP/S Transport for ML-KEM Braid Protocol

Provides network transport for exchanging Braid protocol messages
over HTTP/S connections.

Features:
- Synchronous and asynchronous HTTP clients
- Message serialization/deserialization
- Connection management and retries
- TLS/SSL support for secure transport

The transport layer is separate from the protocol logic, allowing
the Braid protocol to be used with different network transports.

Usage:
    # Async client
    >>> async with BraidHttpClient("https://peer.example.com/braid") as client:
    ...     response = await client.exchange(msg)
    
    # Sync client
    >>> client = BraidHttpClient("https://peer.example.com/braid", async_mode=False)
    >>> response = client.exchange_sync(msg)
    
    # In-memory transport for testing
    >>> transport = InMemoryTransport()
    >>> transport.send(alice_msg)
    >>> bob_msg = transport.receive()
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from queue import Queue
from typing import AsyncIterator, Iterator, List, Optional, Tuple, TYPE_CHECKING

from ml_kem_braid.protocol.messages import Message

# HTTP client imports (optional dependencies)
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False


class TransportError(Exception):
    """Raised when transport operations fail."""
    pass


@dataclass
class BraidHttpClient:
    """
    HTTP/S client for Braid protocol message exchange.
    
    Provides both synchronous and asynchronous interfaces for sending
    and receiving Braid protocol messages over HTTP/S.
    
    Message Format (JSON):
        {
            "epoch": 1,
            "type": "HDR",
            "data": "base64-encoded-bytes"
        }
    
    Usage:
        >>> client = BraidHttpClient("https://peer.example.com/braid")
        >>> 
        >>> # Async usage
        >>> async with client:
        ...     response = await client.exchange(msg)
        >>> 
        >>> # Sync usage
        >>> response = client.exchange_sync(msg)
    
    Attributes:
        endpoint: URL of the peer's Braid endpoint
        timeout: Request timeout in seconds
        retries: Number of retry attempts
        headers: Custom HTTP headers
    """
    
    endpoint: str
    timeout: float = 30.0
    retries: int = 3
    headers: dict = field(default_factory=dict)
    
    # Internal state
    _httpx_client: Optional["httpx.AsyncClient"] = field(
        init=False, default=None, repr=False
    )
    _httpx_sync_client: Optional["httpx.Client"] = field(
        init=False, default=None, repr=False
    )
    
    def __post_init__(self):
        """Validate configuration."""
        if not self.endpoint.startswith(("http://", "https://")):
            raise ValueError(f"Invalid endpoint URL: {self.endpoint}")
    
    async def __aenter__(self) -> "BraidHttpClient":
        """Async context manager entry."""
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx is required for async HTTP client")
        
        self._httpx_client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=self._get_headers()
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._httpx_client:
            await self._httpx_client.aclose()
            self._httpx_client = None
    
    def __enter__(self) -> "BraidHttpClient":
        """Sync context manager entry."""
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx is required for HTTP client")
        
        self._httpx_sync_client = httpx.Client(
            timeout=self.timeout,
            headers=self._get_headers()
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Sync context manager exit."""
        if self._httpx_sync_client:
            self._httpx_sync_client.close()
            self._httpx_sync_client = None
    
    def _get_headers(self) -> dict:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "MLKEMBraid/0.1.0",
        }
        headers.update(self.headers)
        return headers
    
    def _serialize_message(self, msg: Message) -> dict:
        """Serialize message to JSON-compatible dict."""
        result = {
            "epoch": msg.epoch,
            "type": msg.type.name,
        }
        if msg.data is not None:
            result["data"] = base64.b64encode(msg.data).decode("ascii")
        return result
    
    def _deserialize_message(self, data: dict) -> Message:
        """Deserialize message from JSON dict."""
        from ml_kem_braid.protocol.messages import MessageType
        
        msg_type = MessageType[data["type"]]
        msg_data = None
        if "data" in data and data["data"]:
            msg_data = base64.b64decode(data["data"])
        
        return Message(
            epoch=data["epoch"],
            type=msg_type,
            data=msg_data
        )
    
    async def exchange(self, msg: Message) -> Message:
        """
        Exchange a message with the peer (async).
        
        Sends the message and waits for a response.
        
        Args:
            msg: Message to send
        
        Returns:
            Response message from peer
        
        Raises:
            TransportError: If exchange fails after retries
        """
        if self._httpx_client is None:
            raise RuntimeError("Client not initialized - use 'async with' context")
        
        payload = self._serialize_message(msg)
        
        for attempt in range(self.retries):
            try:
                response = await self._httpx_client.post(
                    self.endpoint,
                    json=payload
                )
                response.raise_for_status()
                
                return self._deserialize_message(response.json())
                
            except httpx.HTTPError as e:
                if attempt == self.retries - 1:
                    raise TransportError(f"Exchange failed after {self.retries} attempts: {e}")
                await asyncio.sleep(0.5 * (2 ** attempt))  # Exponential backoff
    
    def exchange_sync(self, msg: Message) -> Message:
        """
        Exchange a message with the peer (synchronous).
        
        Args:
            msg: Message to send
        
        Returns:
            Response message from peer
        
        Raises:
            TransportError: If exchange fails after retries
        """
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx is required for HTTP client")
        
        with httpx.Client(timeout=self.timeout, headers=self._get_headers()) as client:
            payload = self._serialize_message(msg)
            
            for attempt in range(self.retries):
                try:
                    response = client.post(self.endpoint, json=payload)
                    response.raise_for_status()
                    
                    return self._deserialize_message(response.json())
                    
                except httpx.HTTPError as e:
                    if attempt == self.retries - 1:
                        raise TransportError(
                            f"Exchange failed after {self.retries} attempts: {e}"
                        )
                    time.sleep(0.5 * (2 ** attempt))
    
    async def send(self, msg: Message) -> None:
        """
        Send a message without waiting for response (async).
        
        Useful for one-way message sending.
        
        Args:
            msg: Message to send
        """
        if self._httpx_client is None:
            raise RuntimeError("Client not initialized - use 'async with' context")
        
        payload = self._serialize_message(msg)
        await self._httpx_client.post(self.endpoint, json=payload)
    
    def send_sync(self, msg: Message) -> None:
        """Send a message without waiting for response (sync)."""
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx is required for HTTP client")
        
        with httpx.Client(timeout=self.timeout, headers=self._get_headers()) as client:
            payload = self._serialize_message(msg)
            client.post(self.endpoint, json=payload)


@dataclass
class BraidServer:
    """
    Simple HTTP server for receiving Braid messages.
    
    This is a minimal implementation for testing. Production deployments
    should use a proper web framework.
    
    Usage:
        >>> server = BraidServer(port=8080)
        >>> server.on_message = lambda msg: process(msg)
        >>> await server.start()
    
    Attributes:
        host: Server bind address
        port: Server port
        on_message: Callback for received messages
    """
    
    host: str = "0.0.0.0"
    port: int = 8080
    
    # Message handler callback
    on_message: Optional[callable] = None
    
    # Internal state
    _messages: Queue = field(init=False, default_factory=Queue)
    
    async def handle_request(self, data: dict) -> dict:
        """
        Handle incoming request.
        
        Args:
            data: JSON request body
        
        Returns:
            JSON response body
        """
        from ml_kem_braid.protocol.messages import MessageType
        
        # Deserialize incoming message
        msg_type = MessageType[data["type"]]
        msg_data = None
        if "data" in data and data["data"]:
            msg_data = base64.b64decode(data["data"])
        
        msg = Message(
            epoch=data["epoch"],
            type=msg_type,
            data=msg_data
        )
        
        # Store message
        self._messages.put(msg)
        
        # Call handler if set
        response_msg = None
        if self.on_message:
            response_msg = self.on_message(msg)
        
        # Return response
        if response_msg:
            result = {
                "epoch": response_msg.epoch,
                "type": response_msg.type.name,
            }
            if response_msg.data:
                result["data"] = base64.b64encode(response_msg.data).decode("ascii")
            return result
        else:
            return {"status": "received"}
    
    def get_messages(self) -> List[Message]:
        """Get all received messages (clears queue)."""
        messages = []
        while not self._messages.empty():
            messages.append(self._messages.get())
        return messages


@dataclass
class InMemoryTransport:
    """
    In-memory transport for testing Braid protocol.
    
    Provides two queues (Alice -> Bob, Bob -> Alice) for testing
    protocol exchanges without network overhead.
    
    Usage:
        >>> transport = InMemoryTransport()
        >>> 
        >>> # Alice sends
        >>> transport.alice_to_bob.put(alice_msg)
        >>> 
        >>> # Bob receives
        >>> msg = transport.alice_to_bob.get()
        >>> 
        >>> # Bob responds
        >>> transport.bob_to_alice.put(response)
    
    Attributes:
        alice_to_bob: Queue for Alice -> Bob messages
        bob_to_alice: Queue for Bob -> Alice messages
    """
    
    alice_to_bob: Queue = field(default_factory=Queue)
    bob_to_alice: Queue = field(default_factory=Queue)
    
    def alice_send(self, msg: Message) -> None:
        """Alice sends a message to Bob."""
        self.alice_to_bob.put(msg)
    
    def bob_send(self, msg: Message) -> None:
        """Bob sends a message to Alice."""
        self.bob_to_alice.put(msg)
    
    def alice_receive(self, timeout: float = 1.0) -> Optional[Message]:
        """Alice receives a message from Bob."""
        try:
            return self.bob_to_alice.get(timeout=timeout)
        except:
            return None
    
    def bob_receive(self, timeout: float = 1.0) -> Optional[Message]:
        """Bob receives a message from Alice."""
        try:
            return self.alice_to_bob.get(timeout=timeout)
        except:
            return None
    
    def clear(self) -> None:
        """Clear all queues."""
        while not self.alice_to_bob.empty():
            self.alice_to_bob.get()
        while not self.bob_to_alice.empty():
            self.bob_to_alice.get()
    
    def pending_alice_to_bob(self) -> int:
        """Number of pending messages for Bob."""
        return self.alice_to_bob.qsize()
    
    def pending_bob_to_alice(self) -> int:
        """Number of pending messages for Alice."""
        return self.bob_to_alice.qsize()


def serialize_for_wire(msg: Message) -> bytes:
    """
    Serialize message to compact wire format.
    
    Alternative to JSON for bandwidth-constrained environments.
    Uses the Message.to_bytes() method directly.
    
    Args:
        msg: Message to serialize
    
    Returns:
        Compact byte representation
    """
    return msg.to_bytes()


def deserialize_from_wire(data: bytes) -> Message:
    """
    Deserialize message from compact wire format.
    
    Args:
        data: Wire bytes
    
    Returns:
        Deserialized Message
    """
    return Message.from_bytes(data)


# Self-test
if __name__ == "__main__":
    import os
    
    print("Testing Transport Module...")
    
    # Test InMemoryTransport
    print("\n1. Testing InMemoryTransport...")
    transport = InMemoryTransport()
    
    from ml_kem_braid.protocol.messages import msg_header
    
    test_msg = msg_header(epoch=1, chunk_data=os.urandom(34))
    
    transport.alice_send(test_msg)
    received = transport.bob_receive()
    
    assert received is not None
    assert received.epoch == test_msg.epoch
    assert received.type == test_msg.type
    assert received.data == test_msg.data
    print("  InMemoryTransport ✓")
    
    # Test wire serialization
    print("\n2. Testing wire serialization...")
    wire_bytes = serialize_for_wire(test_msg)
    recovered = deserialize_from_wire(wire_bytes)
    
    assert recovered.epoch == test_msg.epoch
    assert recovered.type == test_msg.type
    assert recovered.data == test_msg.data
    print(f"  Serialized: {len(wire_bytes)} bytes ✓")
    
    # Test JSON serialization (used by HTTP client)
    print("\n3. Testing JSON serialization...")
    client = BraidHttpClient("http://localhost:8080/braid")
    
    json_dict = client._serialize_message(test_msg)
    recovered = client._deserialize_message(json_dict)
    
    assert recovered.epoch == test_msg.epoch
    assert recovered.type == test_msg.type
    assert recovered.data == test_msg.data
    print(f"  JSON fields: {list(json_dict.keys())} ✓")
    
    print("\nTransport tests passed!")
