"""securechat.crypto — end-to-end encryption primitives.

Trust model
-----------
The room code (16 Crockford-base32 chars, ~80 bits, generated locally) is the
ONLY secret. Everything else is derived from it:

    master   = Argon2id(code, salt=PROTOCOL_SALT)            (scrypt fallback)
    room_id  = HKDF(master, info="securechat/v1/room-id")    -> sent on the wire
    enc_key  = HKDF(master, info="securechat/v1/enc")        -> AES-256-GCM key

The relay server only ever sees room_id (an opaque 128-bit handle), never the
code, so its logs cannot be brute-forced against room keys.

Message framing inside AES-256-GCM:

    ciphertext_blob = nonce(12) || ciphertext_and_tag
    nonce           = sender_tag(8, random per session) || counter(4, big-endian)
    plaintext       = length(4, big-endian) || payload || zero padding -> size bucket

Length-bucket padding hides exact message size from the server. Per-sender
counters give nonce uniqueness without random-nonce collision risk, and let
receivers reject replays (strictly increasing counters per sender tag).
"""

from __future__ import annotations

import hashlib
import base64
import json
import secrets
from dataclasses import dataclass

PROTOCOL_VERSION = 1

# Crockford base32: no I, L, O, U (avoids transcription ambiguity).
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CODE_LEN = 16
_CODE_GROUP = 4

# Fixed protocol salt. Acceptable here: codes are 80-bit random values, so
# generic precomputation is infeasible; hand-picked codes are warned about.
PROTOCOL_SALT = bytes.fromhex("9d6f0a3e5c1b8742f4e6d2a8b0c3e517")

_ROOM_ID_BYTES = 16          # -> 32 hex chars on the wire
_TAG_BYTES = 8               # -> 16 hex chars on the wire
_NONCE_LEN = 12
_KEY_LEN = 32

MAX_MESSAGE_BYTES = 2000     # max utf-8 payload per chat message
PAD_BUCKETS = (256, 512, 1024, 2048, 4096)
_LEN_PREFIX = 4

# Argon2id: ~64 MiB, 3 passes — sub-second on a laptop, expensive to brute force.
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4
ARGON2_MEMORY_KIB = 65536

_SCRYPT_N = 2 ** 15          # scrypt fallback (same ballpark cost)
_SCRYPT_R = 8
_SCRYPT_P = 1


class CryptoError(Exception):
    """Base class for crypto-layer failures."""


class MessageTooLong(CryptoError):
    pass


class PaddingError(CryptoError):
    pass


class ReplayError(CryptoError):
    pass


class DecryptionError(CryptoError):
    pass


# ---------------------------------------------------------------------------
# Room codes
# ---------------------------------------------------------------------------

def format_code(compact: str) -> str:
    """XXXX-XXXX-XXXX-XXXX display form."""
    return "-".join(compact[i:i + _CODE_GROUP] for i in range(0, len(compact), _CODE_GROUP))


def generate_room_code() -> str:
    """Fresh 80-bit code, generated locally. Never sent to the server."""
    raw = "".join(secrets.choice(CROCKFORD_ALPHABET) for _ in range(_CODE_LEN))
    return format_code(raw)


def normalize_code(raw: str) -> str:
    """Accepts case-insensitive, dash/space-separated input; returns compact code."""
    compact = (raw or "").strip().upper().replace("-", "").replace(" ", "")
    compact = compact.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))
    if len(compact) != _CODE_LEN or any(c not in CROCKFORD_ALPHABET for c in compact):
        raise ValueError(
            "room code must be 16 characters of Crockford base32 "
            "(digits + A-Z, excluding I, L, O, U) — e.g. ABCD-EFGH-JKMN-PQRS"
        )
    return compact


@dataclass(frozen=True)
class Invitation:
    """A shareable relay endpoint and the secret room code."""

    host: str
    port: int
    code: str
    tls: bool = False


def format_invitation(host: str, port: int, code: str, *, tls: bool = False) -> str:
    """Encode relay connection details and a room code for sharing."""
    host = (host or "").strip()
    if not host or len(host) > 253 or any(ord(ch) < 32 for ch in host):
        raise ValueError("invitation host is invalid")
    if not 1 <= port <= 65535:
        raise ValueError("invitation port must be between 1 and 65535")
    compact = normalize_code(code)
    payload = json.dumps(
        {"h": host, "p": port, "t": bool(tls)}, separators=(",", ":")
    ).encode()
    endpoint = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"SC1.{endpoint}.{format_code(compact)}"


def parse_invitation(raw: str) -> Invitation:
    """Decode an invitation, rejecting malformed endpoint data."""
    parts = (raw or "").strip().split(".")
    if len(parts) != 3 or parts[0].upper() != "SC1":
        raise ValueError("not a SecureChat invitation")
    try:
        padding = "=" * (-len(parts[1]) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(parts[1] + padding).decode("utf-8")
        )
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invitation endpoint is malformed") from exc
    if not isinstance(payload, dict):
        raise ValueError("invitation endpoint is malformed")
    host = payload.get("h")
    port = payload.get("p")
    tls = payload.get("t", False)
    if (not isinstance(host, str) or not host.strip() or len(host) > 253
            or any(ord(ch) < 32 for ch in host)
            or isinstance(port, bool) or not isinstance(port, int)
            or not 1 <= port <= 65535 or not isinstance(tls, bool)):
        raise ValueError("invitation endpoint is invalid")
    return Invitation(host.strip(), port, normalize_code(parts[2]), tls)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _master_key(code: str) -> bytes:
    password = code.encode("ascii")
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:
        # Older `cryptography` without the Argon2 binding: scrypt from stdlib.
        return hashlib.scrypt(
            password, salt=PROTOCOL_SALT, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
            dklen=_KEY_LEN, maxmem=64 * 1024 * 1024,
        )
    kdf = Argon2id(
        salt=PROTOCOL_SALT,
        length=_KEY_LEN,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_KIB,
    )
    return kdf.derive(password)


def _hkdf(master: bytes, purpose: str, length: int = _KEY_LEN) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b"securechat/v1/" + purpose.encode("ascii"),
    ).derive(master)


@dataclass(frozen=True)
class RoomKeys:
    room_id: str      # 32 lowercase hex chars — the ONLY room identifier on the wire
    enc_key: bytes    # AES-256-GCM key


def derive_keys(code: str) -> RoomKeys:
    """Derive room id + AES-256 key from a normalized code."""
    master = _master_key(code)
    room_id = _hkdf(master, "room-id", _ROOM_ID_BYTES).hex()
    enc_key = _hkdf(master, "enc", _KEY_LEN)
    return RoomKeys(room_id=room_id, enc_key=enc_key)


def new_tag() -> bytes:
    """Random per-session sender tag (also the GCM nonce prefix)."""
    return secrets.token_bytes(_TAG_BYTES)


def make_aad(room_id: str) -> bytes:
    """Bind every ciphertext to its room — frames can't be moved between rooms."""
    return room_id.encode("ascii") + b"|v1"


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------

def pad_payload(payload: bytes) -> bytes:
    total = _LEN_PREFIX + len(payload)
    if total > PAD_BUCKETS[-1]:
        raise MessageTooLong(
            f"message too long ({len(payload)} bytes; max {MAX_MESSAGE_BYTES})"
        )
    bucket = next(b for b in PAD_BUCKETS if total <= b)
    return len(payload).to_bytes(_LEN_PREFIX, "big") + payload + b"\x00" * (bucket - total)


def unpad_payload(blob: bytes) -> bytes:
    if len(blob) < _LEN_PREFIX:
        raise PaddingError("truncated payload")
    n = int.from_bytes(blob[:_LEN_PREFIX], "big")
    rest = blob[_LEN_PREFIX:]
    if n > len(rest) or any(rest[n:]):
        raise PaddingError("bad padding")
    return rest[:n]


# ---------------------------------------------------------------------------
# Encrypt / decrypt sessions
# ---------------------------------------------------------------------------

class Sender:
    """Encrypts outbound messages; owns the per-session tag + counter."""

    def __init__(self, enc_key: bytes, tag: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self._aes = AESGCM(enc_key)
        self._tag = tag
        self._counter = 0

    @property
    def counter(self) -> int:
        return self._counter

    def seal(self, payload: bytes, aad: bytes) -> bytes:
        if len(payload) > MAX_MESSAGE_BYTES:
            raise MessageTooLong(
                f"message too long ({len(payload)} bytes; max {MAX_MESSAGE_BYTES})"
            )
        if self._counter >= 1 << 32:
            raise CryptoError("nonce space exhausted — leave and rejoin the room")
        blob = pad_payload(payload)
        nonce = self._tag + self._counter.to_bytes(4, "big")
        self._counter += 1
        return nonce + self._aes.encrypt(nonce, blob, aad)


class Receiver:
    """Decrypts inbound messages; enforces per-tag replay protection."""

    def __init__(self, enc_key: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self._aes = AESGCM(enc_key)
        self._high_water: dict[str, int] = {}

    def open(self, blob: bytes, aad: bytes, tag: bytes) -> bytes:
        if len(blob) < _NONCE_LEN + 16:
            raise DecryptionError("ciphertext too short")
        nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
        if not secrets.compare_digest(nonce[:_TAG_BYTES], tag):
            raise DecryptionError("nonce/tag mismatch")
        try:
            padded = self._aes.decrypt(nonce, ct, aad)
        except Exception as exc:  # InvalidTag and friends
            raise DecryptionError(
                "authentication failed (tampered, replayed under wrong tag, or wrong key)"
            ) from exc
        counter = int.from_bytes(nonce[_TAG_BYTES:], "big")
        key = tag.hex()
        if counter <= self._high_water.get(key, -1):
            raise ReplayError("replayed message rejected")
        self._high_water[key] = counter
        return unpad_payload(padded)
