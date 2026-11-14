"""securechat.protocol — newline-delimited JSON wire frames + validation.

Every frame is one line of compact JSON terminated by '\n', max 8 KiB.
The relay validates the envelope only (types, sizes, formats, rate limits);
the "data" it forwards is opaque base64 ciphertext.

Client -> Server : join, msg, ping, leave
Server -> Client : joined, member_join, member_leave, msg, err, pong
"""

from __future__ import annotations

import base64
import binascii
import json
import re

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 8192
MAX_CIPHER_BLOB = 12 + 4096     # GCM nonce + largest padded bucket

_STREAM_LIMIT = MAX_FRAME_BYTES * 2   # asyncio stream read limit


class ProtocolError(Exception):
    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code
        self.msg = msg


_ROOM_RE = re.compile(r"^[0-9a-f]{32}$")
_TAG_RE = re.compile(r"^[0-9a-f]{16}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def stream_limit() -> int:
    """Read limit to pass to asyncio.start_server / open_connection."""
    return _STREAM_LIMIT


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def encode_frame(obj: dict) -> bytes:
    try:
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("bad_frame", f"unserializable frame: {exc}") from exc
    data = line.encode("ascii") + b"\n"
    if len(data) > MAX_FRAME_BYTES:
        raise ProtocolError("too_big", "frame exceeds size limit")
    return data


def parse_frame(line: bytes) -> dict:
    if len(line) > MAX_FRAME_BYTES:
        raise ProtocolError("too_big", "frame exceeds size limit")
    if line.endswith(b"\n"):
        line = line[:-1]
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("bad_frame", "frame is not valid JSON") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
        raise ProtocolError("bad_frame", "frame must be an object with a string 'type'")
    return obj


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------

def _field(obj: dict, key: str, types, code: str = "bad_frame"):
    val = obj.get(key)
    if isinstance(val, bool) or not isinstance(val, types):
        raise ProtocolError(code, f"invalid or missing '{key}' field")
    return val


# ---------------------------------------------------------------------------
# Client -> Server
# ---------------------------------------------------------------------------

def validate_join(obj: dict) -> tuple[str, str]:
    """Returns (room_id, tag)."""
    if _field(obj, "v", int) != PROTOCOL_VERSION:
        raise ProtocolError("bad_version", f"unsupported protocol version {obj.get('v')!r}")
    room = _field(obj, "room", str)
    tag = _field(obj, "tag", str)
    if not _ROOM_RE.match(room):
        raise ProtocolError("bad_room", "room id must be 32 lowercase hex chars")
    if not _TAG_RE.match(tag):
        raise ProtocolError("bad_tag", "tag must be 16 lowercase hex chars")
    return room, tag


def validate_client_msg(obj: dict) -> str:
    """Returns the (validated) base64 ciphertext string, pass-through."""
    data = _field(obj, "data", str, code="bad_data")
    if len(data) > MAX_CIPHER_BLOB * 4 // 3 + 4:
        raise ProtocolError("bad_data", "data too large")
    if not _B64_RE.match(data):
        raise ProtocolError("bad_data", "data must be standard base64")
    try:
        blob = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError("bad_data", "invalid base64") from exc
    if not 16 <= len(blob) <= MAX_CIPHER_BLOB:
        raise ProtocolError("bad_data", f"data must be 16..{MAX_CIPHER_BLOB} bytes")
    return data


# ---------------------------------------------------------------------------
# Server -> Client
# ---------------------------------------------------------------------------

def frame_joined(room: str, tag: str, members) -> dict:
    return {"type": "joined", "v": PROTOCOL_VERSION, "room": room,
            "tag": tag, "members": sorted(members)}


def frame_member_join(tag: str) -> dict:
    return {"type": "member_join", "tag": tag}


def frame_member_leave(tag: str, reason: str) -> dict:
    return {"type": "member_leave", "tag": tag, "reason": reason}


def frame_relay_msg(from_tag: str, data: str) -> dict:
    return {"type": "msg", "from": from_tag, "data": data}


def frame_err(code: str, msg: str) -> dict:
    return {"type": "err", "code": code, "msg": str(msg)[:200]}


def frame_pong() -> dict:
    return {"type": "pong"}


def validate_joined(obj: dict) -> tuple[str, str, list]:
    if _field(obj, "v", int) != PROTOCOL_VERSION:
        raise ProtocolError("bad_version", "unsupported protocol version")
    room = _field(obj, "room", str)
    tag = _field(obj, "tag", str)
    members = _field(obj, "members", list)
    if not _ROOM_RE.match(room) or not _TAG_RE.match(tag):
        raise ProtocolError("bad_frame", "malformed 'joined' frame")
    for m in members:
        if not isinstance(m, str) or not _TAG_RE.match(m):
            raise ProtocolError("bad_frame", "malformed member list")
    return room, tag, members


def validate_server_msg(obj: dict) -> tuple[str, str]:
    from_tag = _field(obj, "from", str)
    if not _TAG_RE.match(from_tag):
        raise ProtocolError("bad_frame", "malformed 'from' tag")
    data = _field(obj, "data", str)
    return from_tag, data


def validate_member_event(obj: dict) -> tuple[str, str]:
    tag = _field(obj, "tag", str)
    if not _TAG_RE.match(tag):
        raise ProtocolError("bad_frame", "malformed member event")
    reason = obj.get("reason", "left")
    if reason not in ("left", "timeout"):
        reason = "left"
    return tag, reason
