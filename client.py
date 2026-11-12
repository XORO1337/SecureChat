"""securechat.client — E2E-encrypted terminal chat client.

Flow: choose username -> create/join room -> connect (plain/TLS/Tor) ->
E2E join handshake -> prompt_toolkit TUI (ui.py).

The username and all chat traffic live inside AES-256-GCM payloads; the relay
only sees opaque room ids, random tags and ciphertext. Nothing is written to
disk: input history is in-memory only, and /burn wipes the transcript buffer.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
import unicodedata
from dataclasses import dataclass, field

import crypto
import protocol
import transport
from phrases import random_join_line_index

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8400

_NAME_MIN, _NAME_MAX = 2, 20
_JOIN_ATTEMPTS = 4


# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------

def sanitize_name(raw: str) -> str:
    """Validate a username. Defensive against terminal escape injection:
    control/format characters are stripped, then the charset is restricted."""
    cleaned = "".join(
        ch for ch in (raw or "").strip()
        if unicodedata.category(ch) not in ("Cc", "Cf")  # controls, BOM/ZWSP...
    )
    cleaned = " ".join(cleaned.split())
    if not _NAME_MIN <= len(cleaned) <= _NAME_MAX:
        raise ValueError(f"username must be {_NAME_MIN}-{_NAME_MAX} characters")
    if not all(ch.isalnum() or ch in "_-. " for ch in cleaned):
        raise ValueError("letters, numbers, spaces and _ - . only")
    return cleaned


# ---------------------------------------------------------------------------
# Encrypted inner payloads (carried inside AES-256-GCM ciphertext)
# ---------------------------------------------------------------------------

def encode_inner_chat(text: str) -> bytes:
    return json.dumps({"t": "chat", "m": text}, separators=(",", ":")).encode("utf-8")


def encode_inner_presence(name: str, first: bool, join_line: int) -> bytes:
    return json.dumps(
        {"t": "presence", "name": name, "first": bool(first), "jl": int(join_line)},
        separators=(",", ":"),
    ).encode("utf-8")


def decode_inner(blob: bytes) -> dict:
    try:
        obj = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise protocol.ProtocolError("bad_inner", "payload is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise protocol.ProtocolError("bad_inner", "payload must be an object")
    t = obj.get("t")
    if t == "chat" and isinstance(obj.get("m"), str):
        return obj
    if (t == "presence" and isinstance(obj.get("name"), str)
            and isinstance(obj.get("first"), bool) and isinstance(obj.get("jl"), int)
            and not isinstance(obj.get("jl"), bool)):
        return obj
    raise protocol.ProtocolError("bad_inner", "unknown payload type")


# ---------------------------------------------------------------------------
# Roster: tag -> display name (names never touch the server)
# ---------------------------------------------------------------------------

class Roster:
    def __init__(self, my_tag: str | None = None):
        self.my_tag = my_tag
        self._names: dict[str, str | None] = {}

    def set_name(self, tag: str, name: str | None) -> str | None:
        """Returns the previous raw name (for 'X is now known as Y' lines)."""
        old = self._names.get(tag)
        if name is None:
            self._names.pop(tag, None)
            return old
        try:
            clean = sanitize_name(name)
        except ValueError:
            clean = None
        self._names[tag] = clean
        return old

    def get(self, tag: str) -> str | None:
        return self._names.get(tag)

    def label(self, tag: str) -> str:
        name = self._names.get(tag)
        if name is None:
            return f"anon-{tag[:4]}"
        dupes = [t for t, n in self._names.items() if n is not None and n == name]
        if len(dupes) > 1:
            return f"{name} ({tag[:4]})"
        return name

    def ordered_labels(self, member_tags) -> list[tuple[str, str]]:
        out = []
        for tag in sorted(member_tags):
            me = " (you)" if tag == self.my_tag else ""
            out.append((tag, self.label(tag) + me))
        return out


# ---------------------------------------------------------------------------
# Events pushed to the UI
# ---------------------------------------------------------------------------

@dataclass
class Event:
    kind: str            # chat | system | roster | ui | disconnected
    text: str = ""
    name: str = ""       # display label for chat lines
    mine: bool = False
    warn: bool = False


# ---------------------------------------------------------------------------
# ChatSession — protocol + crypto state, UI-agnostic
# ---------------------------------------------------------------------------

class ChatSession:
    def __init__(self, *, code: str, name: str, reader, writer,
                 conn_info: transport.ConnInfo, plain_join: bool = False):
        self.keys = crypto.derive_keys(code)
        self.room_id = self.keys.room_id
        self.display_code = crypto.format_code(code)
        self.my_name = name
        self.reader = reader
        self.writer = writer
        self.conn_info = conn_info
        self.plain_join = plain_join
        self.aad = crypto.make_aad(self.room_id)
        self.sender: crypto.Sender | None = None
        self.receiver: crypto.Receiver | None = None
        self.my_tag: str | None = None
        self.members: set[str] = set()
        self.roster = Roster()
        self.events: asyncio.Queue[Event] = asyncio.Queue()
        self.connected = False
        self._tasks: list[asyncio.Task] = []
        self._closed = False

    # -- join handshake ------------------------------------------------------
    async def join(self) -> None:
        """Join the room; retries automatically on tag collision."""
        for _ in range(_JOIN_ATTEMPTS):
            tag = crypto.new_tag()
            self.writer.write(protocol.encode_frame(
                {"type": "join", "v": protocol.PROTOCOL_VERSION,
                 "room": self.room_id, "tag": tag.hex()}
            ))
            await self.writer.drain()
            try:
                line = await asyncio.wait_for(self.reader.readuntil(b"\n"), timeout=10)
            except asyncio.TimeoutError as exc:
                raise transport.TransportError("server did not answer the join request") from exc
            obj = protocol.parse_frame(line)
            if obj.get("type") == "err":
                code, msg = obj.get("code", "error"), obj.get("msg", "unknown error")
                if code == "bad_tag":
                    continue  # regenerate tag and retry
                raise transport.TransportError(f"server refused join: {msg}")
            if obj.get("type") != "joined":
                raise transport.TransportError("unexpected reply to join")
            _room, srv_tag, members = protocol.validate_joined(obj)
            self.my_tag = srv_tag
            self.sender = crypto.Sender(self.keys.enc_key, bytes.fromhex(srv_tag))
            self.receiver = crypto.Receiver(self.keys.enc_key)
            self.members = set(members) | {srv_tag}
            self.roster = Roster(srv_tag)
            self.roster.set_name(srv_tag, self.my_name)
            self.connected = True
            break
        else:
            raise transport.TransportError("could not pick a free tag after several attempts")

        self._start_tasks()
        await self._send_presence(first=True)

    def _start_tasks(self) -> None:
        self._tasks.append(asyncio.create_task(self._reader_loop(), name="reader"))
        self._tasks.append(asyncio.create_task(self._pinger(), name="pinger"))

    # -- background tasks ------------------------------------------------------
    async def _reader_loop(self) -> None:
        try:
            while self.connected:
                line = await self.reader.readuntil(b"\n")
                self._dispatch(protocol.parse_frame(line))
        except asyncio.IncompleteReadError:
            self._mark_disconnected("connection closed by server")
        except asyncio.LimitOverrunError:
            self._mark_disconnected("protocol error: oversized frame from server")
        except protocol.ProtocolError as exc:
            self._mark_disconnected(f"protocol error: {exc.msg}")
        except (ConnectionError, OSError):
            self._mark_disconnected("connection lost")

    async def _pinger(self) -> None:
        try:
            while self.connected:
                await asyncio.sleep(30)
                self.writer.write(protocol.encode_frame({"type": "ping"}))
                await self.writer.drain()
        except (ConnectionError, OSError):
            self._mark_disconnected("connection lost")

    # -- dispatch ---------------------------------------------------------------
    def _dispatch(self, obj: dict) -> None:
        ftype = obj.get("type")
        if ftype == "msg":
            self._on_msg(obj)
        elif ftype == "member_join":
            self._on_member_join(obj)
        elif ftype == "member_leave":
            self._on_member_leave(obj)
        elif ftype == "err":
            self._sys(f"server: {obj.get('msg', 'error')} ({obj.get('code')})", warn=True)
        elif ftype == "pong":
            pass
        # unknown frame types are ignored (forward compatibility)

    def _on_msg(self, obj: dict) -> None:
        try:
            from_tag, data = protocol.validate_server_msg(obj)
        except protocol.ProtocolError as exc:
            self._sys(f"bad frame from server: {exc.msg}", warn=True)
            return
        try:
            blob = base64.b64decode(data, validate=True)
            inner = decode_inner(self.receiver.open(blob, self.aad, bytes.fromhex(from_tag)))
        except crypto.DecryptionError:
            self._sys("received a tampered or garbled message — dropped", warn=True)
            return
        except crypto.ReplayError:
            self._sys("replayed message dropped", warn=True)
            return
        except (protocol.ProtocolError, ValueError):
            self._sys("malformed encrypted payload dropped", warn=True)
            return
        if from_tag not in self.members:
            return  # stale event for a member who already left

        if inner["t"] == "chat":
            label = self.roster.label(from_tag)
            self._put(Event("chat", text=inner["m"], name=label))
        else:  # presence
            name = inner.get("name")
            old = self.roster.set_name(from_tag, name)
            label = self.roster.label(from_tag)
            if inner.get("first"):
                line = f"{label} joined!" if self.plain_join \
                    else _join_line(inner.get("jl"), label, from_tag)
                self._sys(f"*** {line} ***")
            elif old is not None and old != name:
                self._sys(f"*** {old} is now known as {label} ***")
            self._put(Event("roster"))

    def _on_member_join(self, obj: dict) -> None:
        try:
            tag, _ = protocol.validate_member_event(obj)
        except protocol.ProtocolError:
            return
        if tag not in self.members:
            self.members.add(tag)
            self._put(Event("roster"))
        # Answer with a silent presence so the newcomer learns our name.
        asyncio.get_running_loop().create_task(self._send_presence(first=False))

    def _on_member_leave(self, obj: dict) -> None:
        try:
            tag, _reason = protocol.validate_member_event(obj)
        except protocol.ProtocolError:
            return
        if tag in self.members:
            self.members.discard(tag)
            label = self.roster.label(tag)
            self.roster.set_name(tag, None)
            self._sys(f"*** {label} left ***")
            self._put(Event("roster"))

    # -- outbound ---------------------------------------------------------------
    async def _send_presence(self, *, first: bool) -> None:
        if not self.connected or self.sender is None:
            return
        blob = self.sender.seal(
            encode_inner_presence(self.my_name, first, random_join_line_index()),
            self.aad,
        )
        await self._send_blob(blob)

    async def _send_blob(self, blob: bytes) -> None:
        try:
            self.writer.write(protocol.encode_frame(
                {"type": "msg", "data": base64.b64encode(blob).decode("ascii")}
            ))
            await self.writer.drain()
        except (ConnectionError, OSError):
            self._mark_disconnected("connection lost while sending")

    async def send_chat(self, text: str) -> bool:
        """Returns False when the UI should exit (/quit)."""
        text = text.rstrip()
        if not text:
            return True
        if text.startswith("/"):
            return await self._command(text)
        if self.sender is None:
            return True
        if len(text.encode("utf-8")) > crypto.MAX_MESSAGE_BYTES:
            self._sys(f"message too long (max {crypto.MAX_MESSAGE_BYTES} bytes)", warn=True)
            return True
        try:
            blob = self.sender.seal(protocol_ok(text), self.aad)
        except crypto.MessageTooLong:
            self._sys(f"message too long (max {crypto.MAX_MESSAGE_BYTES} bytes)", warn=True)
            return True
        self._put(Event("chat", text=text, name=self.roster.label(self.my_tag), mine=True))
        await self._send_blob(blob)
        return True

    async def _command(self, text: str) -> bool:
        cmd, _, arg = text.partition(" ")
        arg = arg.strip()
        if cmd in ("/quit", "/exit", "/q", "/leave"):
            self.stop()
            return False
        if cmd == "/help":
            self._sys("commands: /help  /code  /who  /nick <name>  /burn  /quit")
        elif cmd == "/code":
            self._sys(f"*** room code: {self.display_code} — share it only with "
                      f"people you want in the room ***")
        elif cmd == "/who":
            self._put(Event("ui", text="users"))
        elif cmd == "/burn":
            self._put(Event("ui", text="burn"))
        elif cmd == "/nick":
            try:
                name = sanitize_name(arg)
            except ValueError as exc:
                self._sys(f"invalid name: {exc}", warn=True)
                return True
            old = self.roster.label(self.my_tag)
            self.my_name = name
            self.roster.set_name(self.my_tag, name)
            self._sys(f"*** {old} is now known as {name} ***")
            await self._send_presence(first=False)
        else:
            self._sys(f"unknown command {cmd!r} — try /help", warn=True)
        return True

    # -- lifecycle ------------------------------------------------------------
    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.connected = False
        for t in self._tasks:
            t.cancel()
        try:
            self.writer.write(protocol.encode_frame({"type": "leave"}))
        except Exception:
            pass
        try:
            self.writer.close()
        except Exception:
            pass

    # -- events -----------------------------------------------------------------
    def _put(self, ev: Event) -> None:
        self.events.put_nowait(ev)

    def _sys(self, text: str, warn: bool = False) -> None:
        self._put(Event("system", text=text, warn=warn))

    def _mark_disconnected(self, reason: str) -> None:
        if self._closed:
            return
        self.connected = False
        self._put(Event("disconnected", text=reason))


def protocol_ok(text: str) -> bytes:
    return encode_inner_chat(text)


def _join_line(index, label: str, tag: str) -> str:
    from phrases import join_message
    return join_message(index, label, tag)


# ---------------------------------------------------------------------------
# Interactive prompts (plain terminal, before the TUI starts)
# ---------------------------------------------------------------------------

def prompt_username() -> str:
    while True:
        try:
            raw = input(f"Choose a username ({_NAME_MIN}-{_NAME_MAX} chars, "
                        f"letters/numbers/_-.): ")
        except (EOFError, KeyboardInterrupt):
            raise SystemExit(1)
        try:
            return sanitize_name(raw)
        except ValueError as exc:
            print(f"  ! {exc}")


def prompt_room_code(create: bool) -> str:
    if create:
        code = crypto.normalize_code(crypto.generate_room_code())
        print()
        print(f"  Your room code: {code}")
        print("  Share it ONLY with people you want in the room.")
        print("  Anyone with the code can join; it is never sent to the server.")
        print()
        return code
    while True:
        try:
            raw = input("Enter the room code (XXXX-XXXX-XXXX-XXXX): ")
        except (EOFError, KeyboardInterrupt):
            raise SystemExit(1)
        try:
            return crypto.normalize_code(raw)
        except ValueError as exc:
            print(f"  ! {exc}")


def confirm_fingerprint(fp: str) -> bool:
    print("  Server TLS certificate fingerprint (SHA-256):")
    print("    " + transport.format_fingerprint(fp))
    try:
        ans = input("  Trust and pin this server? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("y", "yes")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="securechat",
        description="End-to-end encrypted temporary terminal chat rooms.",
        epilog="IP privacy: peers never see each other's IP. Add --tor to hide "
               "your IP from the server too (needs a local Tor SOCKS proxy).",
    )
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--room", help="room code (interactive prompt if omitted)")
    ap.add_argument("--name", help="username (interactive prompt if omitted)")
    ap.add_argument("--tls", action="store_true", help="use TLS to the relay")
    ap.add_argument("--tls-fp", help="pinned server TLS fingerprint (sha256 hex)")
    ap.add_argument("--tor", action="store_true",
                    help="route through a Tor SOCKS5 proxy (socks5h; .onion works)")
    ap.add_argument("--tor-proxy", default="127.0.0.1:9050",
                    help="Tor SOCKS5 address (default 127.0.0.1:9050)")
    ap.add_argument("--plain-join", action="store_true",
                    help="plain '<name> joined!' announcements (no fun lines)")
    return ap.parse_args(argv)


async def run(args) -> None:
    interactive = sys.stdin.isatty() and sys.stdout.isatty()

    # -- username -----------------------------------------------------------
    name = args.name
    if name:
        try:
            name = sanitize_name(name)
        except ValueError as exc:
            raise SystemExit(f"error: invalid --name: {exc}")
    elif interactive:
        name = prompt_username()
    else:
        raise SystemExit("error: --name is required in non-interactive mode")

    # -- room code ------------------------------------------------------------
    created = False
    if args.room:
        try:
            code = crypto.normalize_code(args.room)
        except ValueError as exc:
            raise SystemExit(f"error: {exc}")
        if not crypto.format_code(code) == args.room.strip().upper().replace(" ", ""):
            print("  note: hand-picked codes are weaker than generated ones — "
                  "use long, random codes.")
    elif interactive:
        ans = input("Create a new room [C] or join an existing one [J]? ").strip().lower()
        created = ans.startswith("c")
        code = prompt_room_code(create=created)
    else:
        raise SystemExit("error: --room is required in non-interactive mode")

    # -- connect ---------------------------------------------------------------
    mode = "Tor" if args.tor else ("TLS" if args.tls else "TCP")
    print(f"  Connecting to {args.host}:{args.port} via {mode} ...")
    try:
        reader, writer, info = await transport.connect(
            args.host, args.port,
            tls=args.tls, tls_fp=args.tls_fp,
            tor=args.tor, proxy=args.tor_proxy,
        )
    except transport.TransportError as exc:
        raise SystemExit(f"error: {exc}")

    if info.tls and not args.tls_fp:
        ok = confirm_fingerprint(info.fingerprint) if interactive else True
        if interactive and not ok:
            writer.close()
            raise SystemExit("aborted: server fingerprint not trusted")

    print("  Connected. Deriving room keys ...")
    session = ChatSession(code=code, name=name, reader=reader, writer=writer,
                          conn_info=info, plain_join=args.plain_join)
    try:
        await session.join()
    except transport.TransportError as exc:
        writer.close()
        raise SystemExit(f"error: {exc}")

    print(f"  Joined. {len(session.members)} online. Starting TUI "
          f"(Ctrl+C or /quit to leave; /help for commands) ...")

    from ui import ChatUI  # TUI imports stay out of headless/test paths
    ui = ChatUI(session)
    try:
        await ui.run()
    finally:
        session.stop()

    print("  Closed. Nothing was stored.")


def main() -> None:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n  Interrupted. Nothing was stored.")


if __name__ == "__main__":
    main()
