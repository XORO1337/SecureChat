"""securechat.server — asyncio relay for end-to-end-encrypted rooms.

Rooms live in a dict in RAM. Nothing is ever written to disk and message
contents are opaque ciphertext that is never logged.

The relay enforces envelope rules only:
  * first frame must be a valid 'join' (room id + tag format)
  * room capacity, per-connection message rate, duplicate-ciphertext
    suppression (replay defense at the relay), heartbeat timeouts

The server NEVER learns: the room code, usernames, or message plaintext.
It DOES see (unavoidably): connecting IPs, opaque room ids, random tags,
timings and padded ciphertext sizes. Run behind Tor to hide IPs (README).

Wire spoofing note: outbound 'msg' frames always carry the tag the server
associated with the connection — clients cannot forge another member's tag.
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import hashlib
import sys
import time
from collections import OrderedDict, deque

import protocol
import crypto
from protocol import (
    ProtocolError,
    encode_frame,
    parse_frame,
    validate_client_msg,
    validate_join,
    frame_err,
    frame_joined,
    frame_member_join,
    frame_member_leave,
    frame_pong,
    frame_relay_msg,
)
from transport import cert_file_fingerprint, format_fingerprint, generate_self_signed_context

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8400
PORT_FALLBACK_COUNT = 20

JOIN_TIMEOUT = 15.0        # seconds to join after connecting
CLIENT_TIMEOUT = 120.0     # drop connections silent for this long
ROOM_IDLE = 2 * 3600.0     # delete rooms idle this long
MAX_ROOM_DEFAULT = 12
MSG_RATE = 5.0             # sustained messages/second per client
MSG_BURST = 10             # token-bucket capacity
CONNECT_RATE = 30          # new connections per IP per minute
RECENT_CIPHERS = 256       # duplicate-ciphertext ring per room
MAX_BUFFERED = 1 << 20     # kill readers buffering > 1 MiB (slow-loris defense)


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class Member:
    def __init__(self, tag: str, writer: asyncio.StreamWriter, addr):
        self.tag = tag
        self.writer = writer
        self.addr = addr
        self.room: Room | None = None
        self.last_seen = time.monotonic()
        self.tokens = float(MSG_BURST)
        self.last_refill = time.monotonic()


class Room:
    def __init__(self, room_id: str):
        self.id = room_id
        self.members: dict[str, Member] = {}
        self.recent: OrderedDict[str, None] = OrderedDict()  # cipher digest ring
        self.created = time.monotonic()
        self.last_activity = self.created

    def remember_cipher(self, digest: str) -> None:
        self.recent[digest] = None
        self.recent.move_to_end(digest)
        while len(self.recent) > RECENT_CIPHERS:
            self.recent.popitem(last=False)


class Relay:
    def __init__(self, *, max_room: int = MAX_ROOM_DEFAULT,
                 msg_rate: float = MSG_RATE, log_connections: bool = False):
        self.rooms: dict[str, Room] = {}
        self.max_room = max_room
        self.msg_rate = msg_rate
        self.log_connections = log_connections
        self._connect_times: dict[str, deque] = {}

    # -- connection rate limiting ------------------------------------------
    def _allow_connect(self, ip: str) -> bool:
        now = time.monotonic()
        dq = self._connect_times.setdefault(ip, deque())
        while dq and now - dq[0] > 60.0:
            dq.popleft()
        if len(dq) >= CONNECT_RATE:
            return False
        dq.append(now)
        return True

    def _allow_msg(self, m: Member) -> bool:
        now = time.monotonic()
        m.tokens = min(MSG_BURST, m.tokens + (now - m.last_refill) * self.msg_rate)
        m.last_refill = now
        if m.tokens < 1.0:
            return False
        m.tokens -= 1.0
        return True

    # -- serving -------------------------------------------------------------
    async def serve(self, host: str, port: int, ssl_ctx=None,
                    port_fallback: int = PORT_FALLBACK_COUNT,
                    advertise_host: str | None = None,
                    room_code: str | None = None) -> None:
        requested_port = port
        last_error: OSError | None = None
        for offset in range(port_fallback + 1):
            candidate = port + offset
            if candidate > 65535:
                break
            try:
                server = await asyncio.start_server(
                    self._handle, host, candidate, ssl=ssl_ctx,
                    limit=protocol.stream_limit(),
                )
                break
            except OSError as exc:
                if exc.errno != errno.EADDRINUSE:
                    raise
                last_error = exc
        else:
            server = None

        if server is None:
            assert last_error is not None
            raise OSError(
                f"ports {requested_port}-{requested_port + port_fallback} "
                f"are unavailable"
            ) from last_error

        gc_task = asyncio.create_task(self._gc_loop())
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets or [])
        actual_ports = {
            s.getsockname()[1] for s in server.sockets or []
        }
        actual_port = next(iter(actual_ports), requested_port)
        if requested_port != 0 and actual_port != requested_port:
            log(f"[!] port {requested_port} is in use; using closest open port "
                f"{actual_port}")
        log(f"[*] securechat relay listening on {addrs}")
        log(f"[*] clients must connect to port {actual_port}")
        if room_code is not None:
            invitation_host = advertise_host or host
            if invitation_host in ("0.0.0.0", "::", ""):
                invitation_host = "127.0.0.1"
                log("[!] no --advertise-host supplied; invitation is local-only "
                    "(use the server's reachable hostname or IP)")
            invitation = crypto.format_invitation(
                invitation_host, actual_port, room_code, tls=ssl_ctx is not None,
            )
            log(f"[*] share this room invitation: {invitation}")
        log("[*] RAM only: no message storage, no message logging.")
        try:
            async with server:
                await server.serve_forever()
        finally:
            gc_task.cancel()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        ip = addr[0] if isinstance(addr, tuple) and addr else "?"
        member: Member | None = None
        room: Room | None = None
        try:
            if not self._allow_connect(ip):
                raise ProtocolError("rate", "too many connections from your address; slow down")

            line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=JOIN_TIMEOUT)
            obj = parse_frame(line)
            if obj.get("type") != "join":
                raise ProtocolError("bad_frame", "first frame must be 'join'")
            room_id, tag = validate_join(obj)

            room = self.rooms.setdefault(room_id, Room(room_id))
            if tag in room.members:
                raise ProtocolError("bad_tag", "tag collision; regenerate your tag")
            if len(room.members) >= self.max_room:
                raise ProtocolError("room_full", f"room is full (max {self.max_room})")

            member = Member(tag, writer, addr)
            member.room = room
            room.members[tag] = member
            self._send(writer, frame_joined(room_id, tag, list(room.members)))
            self._broadcast(room, frame_member_join(tag), exclude=tag)
            room.last_activity = time.monotonic()
            if self.log_connections:
                log(f"[join]  room={room_id[:8]}… tag={tag[:4]}… ip={ip}")

            await self._loop(member, room, reader)

        except ProtocolError as exc:
            self._send(writer, frame_err(exc.code, exc.msg))
        except (asyncio.IncompleteReadError, asyncio.TimeoutError,
                asyncio.LimitOverrunError, ConnectionError, OSError):
            pass
        finally:
            if member is not None and member.room is not None:
                room = member.room
                room.members.pop(member.tag, None)
                self._broadcast(room, frame_member_leave(member.tag, "timeout"))
                if self.log_connections:
                    log(f"[leave] room={room.id[:8]}… tag={member.tag[:4]}… ip={ip}")
                if not room.members and self.rooms.get(room.id) is room:
                    del self.rooms[room.id]
            try:
                await writer.drain()
            except Exception:
                pass
            writer.close()

    async def _loop(self, member: Member, room: Room, reader: asyncio.StreamReader) -> None:
        while True:
            line = await reader.readuntil(b"\n")
            member.last_seen = time.monotonic()
            obj = parse_frame(line)
            ftype = obj["type"]

            if ftype == "msg":
                data = validate_client_msg(obj)
                if not self._allow_msg(member):
                    self._send(member.writer, frame_err("rate", "slow down — message rate limit"))
                    continue
                digest = hashlib.sha256(data.encode("ascii")).hexdigest()
                if digest in room.recent:
                    continue  # duplicate ciphertext (replay) — silently dropped
                room.remember_cipher(digest)
                room.last_activity = time.monotonic()
                self._broadcast(room, frame_relay_msg(member.tag, data), exclude=member.tag)

            elif ftype == "ping":
                self._send(member.writer, frame_pong())

            elif ftype == "leave":
                return

            else:
                self._send(member.writer, frame_err("bad_type", f"unknown frame type {ftype!r}"))

    # -- helpers ---------------------------------------------------------------
    @staticmethod
    def _send(writer: asyncio.StreamWriter, frame: dict) -> None:
        try:
            writer.write(encode_frame(frame))
        except Exception:
            pass

    def _broadcast(self, room: Room, frame: dict, exclude: str | None = None) -> None:
        try:
            data = encode_frame(frame)
        except ProtocolError:
            return
        for m in list(room.members.values()):
            if m.tag == exclude:
                continue
            try:
                m.writer.write(data)
            except Exception:
                pass  # dead writers reaped by timeout / finally

    async def _gc_loop(self) -> None:
        while True:
            await asyncio.sleep(15)
            now = time.monotonic()
            for room in list(self.rooms.values()):
                for m in list(room.members.values()):
                    timed_out = now - m.last_seen > CLIENT_TIMEOUT
                    bloated = m.writer.transport is not None and \
                        m.writer.transport.get_write_buffer_size() > MAX_BUFFERED
                    if timed_out or bloated:
                        m.writer.close()  # read loop unwinds -> finally cleans up
                if not room.members and now - room.last_activity > ROOM_IDLE:
                    if self.rooms.get(room.id) is room:
                        del self.rooms[room.id]
            for ip, dq in list(self._connect_times.items()):
                if not dq or now - dq[-1] > 120.0:
                    self._connect_times.pop(ip, None)


# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="securechat-server",
        description="E2E-encrypted terminal chat — relay server. "
                    "Stores nothing, reads no plaintext.",
    )
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help=f"bind address (default {DEFAULT_HOST}; use 0.0.0.0 on a VPS)")
    ap.add_argument("--advertise-host",
                    help="hostname/IP embedded in the startup invitation")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--port-fallback", type=int, default=PORT_FALLBACK_COUNT,
                    metavar="COUNT",
                    help=f"try this many higher ports if --port is busy "
                         f"(default {PORT_FALLBACK_COUNT})")
    ap.add_argument("--no-port-fallback", dest="port_fallback",
                    action="store_const", const=0,
                    help="fail instead of trying a higher port")
    ap.add_argument("--tls", action="store_true",
                    help="serve TLS (auto-generates a self-signed cert if none given)")
    ap.add_argument("--tls-cert", help="existing certificate (PEM) — implies --tls")
    ap.add_argument("--tls-key", help="existing private key (PEM) — implies --tls")
    ap.add_argument("--max-room", type=int, default=MAX_ROOM_DEFAULT,
                    help=f"max members per room (default {MAX_ROOM_DEFAULT})")
    ap.add_argument("--log-connections", action="store_true",
                    help="log joins/leaves (room id prefix, tag prefix, IP) to stderr")
    args = ap.parse_args()
    if not 0 <= args.port <= 65535:
        ap.error("--port must be between 0 and 65535")
    if not 0 <= args.port_fallback <= 65535:
        ap.error("--port-fallback must be between 0 and 65535")

    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ssl_ctx = None
    if args.tls or args.tls_cert or args.tls_key:
        if bool(args.tls_cert) != bool(args.tls_key):
            ap.error("--tls-cert and --tls-key must be given together")
        if args.tls_cert:
            ssl_ctx = _server_ctx_from_files(args.tls_cert, args.tls_key)
            fp = cert_file_fingerprint(args.tls_cert)
        else:
            ssl_ctx, fp = generate_self_signed_context()
        log("[*] TLS enabled — pin this fingerprint on clients (--tls-fp):")
        log("    " + format_fingerprint(fp))

    relay = Relay(max_room=args.max_room, log_connections=args.log_connections)
    room_code = crypto.normalize_code(crypto.generate_room_code())
    try:
        asyncio.run(relay.serve(
            args.host, args.port, ssl_ctx, args.port_fallback,
            args.advertise_host, room_code,
        ))
    except OSError as exc:
        raise SystemExit(f"error: could not bind a listening port ({exc})") from exc
    except KeyboardInterrupt:
        log("[*] shutting down — all rooms discarded")


def _server_ctx_from_files(cert: str, key: str):
    from transport import _server_ctx
    return _server_ctx(cert, key)


if __name__ == "__main__":
    main()
