"""securechat.phrases — join announcement templates.

The joiner picks a random template index and broadcasts it *inside* the
encrypted presence message, so every member renders the same fun line and the
relay learns nothing. If the index is missing or out of range (malformed or
older client), every member falls back to the same deterministic pick derived
from the sender's tag — still consistent for everyone.
"""

from __future__ import annotations

import secrets

JOIN_TEMPLATES = [
    "{user} joined!",
    "Welcome to the party, {user}! Glad you made it.",
    "Look who just dropped in: {user}! Make yourself at home.",
    "A wild {user} appeared! Welcome to the crew.",
    "{user} has spawned into the server.",
    "Brace yourselves, {user} just slid into the room.",
    "Hide the snacks! {user} just walked in.",
]


def random_join_line_index() -> int:
    return secrets.randbelow(len(JOIN_TEMPLATES))


def join_message(index, user: str, tag_hex: str) -> str:
    """Render the announcement; bad indexes fall back deterministically."""
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(JOIN_TEMPLATES):
        seed = int.from_bytes(bytes.fromhex(tag_hex)[:8], "big")
        index = seed % len(JOIN_TEMPLATES)
    return JOIN_TEMPLATES[index].format(user=user)
