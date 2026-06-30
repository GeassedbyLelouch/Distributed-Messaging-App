from __future__ import annotations

import copy
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from ml_kem_braid.decentralized.records import SignedRecord
from ml_kem_braid.decentralized.services import DecentralizedServices


_USERNAME_RECORD_TYPE = "identity.username_record"
_FORBIDDEN_CIRCUIT_FRAME_FIELDS = {
    "username",
    "auth_token",
    "sender_username",
    "recipient_username",
}


def _contains_identity_metadata(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if isinstance(key, str) and key.lower() in _FORBIDDEN_CIRCUIT_FRAME_FIELDS:
                return True
            if _contains_identity_metadata(nested_value):
                return True
        return False

    if isinstance(value, list):
        return any(_contains_identity_metadata(item) for item in value)

    return False


def build_decentralized_router(services: DecentralizedServices) -> APIRouter:
    router = APIRouter()
    circuit_frames: dict[str, list[dict[str, Any]]] = {}

    @router.post("/v1/records")
    async def publish_record(request: Request) -> dict[str, str]:
        try:
            payload: Any = await request.json()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="malformed JSON") from exc

        try:
            record = SignedRecord.from_dict(payload)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        try:
            services.publish_record(record)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            status_code = 409 if "already registered" in str(exc) else 422
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc

        return {"status": "published"}

    @router.get("/v1/records/{record_type}/{lookup}")
    def lookup_record(record_type: str, lookup: str) -> dict[str, Any]:
        if record_type != _USERNAME_RECORD_TYPE:
            raise HTTPException(status_code=404, detail="unknown record type")

        record = services.lookup_username(lookup)
        if record is None:
            raise HTTPException(status_code=404, detail="record not found")
        return record.to_dict()

    @router.post("/v1/circuits/{circuit_id}/frames")
    async def queue_circuit_frame(circuit_id: str, request: Request) -> dict[str, str]:
        try:
            payload: Any = await request.json()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="malformed JSON") from exc

        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="frame must be a JSON object")

        if _contains_identity_metadata(payload):
            raise HTTPException(status_code=422, detail="identity metadata is not allowed")

        circuit_frames.setdefault(circuit_id, []).append(copy.deepcopy(payload))
        return {"status": "queued"}

    @router.get("/v1/circuits/{circuit_id}/frames")
    def drain_circuit_frames(circuit_id: str) -> dict[str, list[dict[str, Any]]]:
        frames = circuit_frames.pop(circuit_id, [])
        return {"frames": copy.deepcopy(frames)}

    return router
