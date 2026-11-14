"""securechat.transport — connection factory: plain TCP, TLS, Tor (SOCKS5h).

- Plain TCP: asyncio.open_connection.
- TLS:       certificate verification is done by explicit SHA-256 fingerprint
             pinning (TOFU). The server prints its fingerprint; clients pin it
             with --tls-fp or confirm interactively.
- Tor:       SOCKS5 with remote DNS resolution (socks5h semantics), so neither
             the local resolver nor a passive observer learns destinations;
             .onion hosts work. The relay then only sees a Tor exit IP.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import ssl
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

DEFAULT_TOR_PROXY = ("127.0.0.1", 9050)


class TransportError(Exception):
    pass


@dataclass
class ConnInfo:
    transport: str            # "TCP" | "TOR"
    tls: bool
    fingerprint: str | None   # sha256 hex of peer cert DER (TLS only)

    @property
    def badge(self) -> str:
        base = "TOR" if self.transport == "TOR" else "TCP"
        return f"{base}+TLS" if self.tls else base


def parse_proxy_spec(spec: str) -> tuple[str, int]:
    """'127.0.0.1:9050' -> ('127.0.0.1', 9050)."""
    spec = (spec or "").strip()
    host, sep, port = spec.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise TransportError(f"invalid proxy spec {spec!r} — expected HOST:PORT")
    p = int(port)
    if not 1 <= p <= 65535:
        raise TransportError(f"proxy port {p} out of range")
    return host, p


def format_fingerprint(fp: str) -> str:
    """aa:bb:.. colon-separated uppercase, for human comparison."""
    clean = (fp or "").replace(":", "").replace(" ", "").lower()
    return ":".join(clean[i:i + 2].upper() for i in range(0, len(clean), 2))


def normalize_fingerprint(fp: str) -> str:
    return (fp or "").replace(":", "").replace(" ", "").lower()


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def _client_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False          # identity comes from the pinned fingerprint
    ctx.verify_mode = ssl.CERT_NONE     # (self-signed / hidden-service deployments)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _server_ctx(cert_path: str, key_path: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def cert_file_fingerprint(cert_path: str) -> str:
    from cryptography import x509
    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    der = cert.public_bytes(_der_encoding())
    return hashlib.sha256(der).hexdigest()


def _der_encoding():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def generate_self_signed_context() -> tuple[ssl.SSLContext, str]:
    """Fresh in-memory P-256 self-signed cert. Files live only for the load."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "securechat-relay")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # SSLContext only loads from files: write a throwaway pair into the OS
    # temp dir and let TemporaryDirectory delete it immediately after load.
    with tempfile.TemporaryDirectory(prefix="securechat-tls-") as td:
        cert_path = os.path.join(td, "cert.pem")
        key_path = os.path.join(td, "key.pem")
        with open(cert_path, "wb") as fh:
            fh.write(cert_pem)
        with open(key_path, "wb") as fh:
            fh.write(key_pem)
        ctx.load_cert_chain(cert_path, key_path)
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return ctx, fp


# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------

async def connect(
    host: str,
    port: int,
    *,
    tls: bool = False,
    tls_fp: str | None = None,
    tor: bool = False,
    proxy: tuple[str, int] | str = DEFAULT_TOR_PROXY,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, ConnInfo]:
    """Open a connection. Returns (reader, writer, ConnInfo).

    With tls=True and no tls_fp, the caller is responsible for verifying
    info.fingerprint (TOFU prompt) — mismatch aborts only when tls_fp given.
    """
    if isinstance(proxy, str):
        proxy = parse_proxy_spec(proxy)

    sock = None
    if tor:
        try:
            from python_socks.async_.asyncio import Proxy
        except ImportError as exc:
            raise TransportError(
                "Tor mode needs 'python-socks[asyncio]' — pip install python-socks[asyncio]"
            ) from exc
        phost, pport = proxy
        p = Proxy.from_url(f"socks5://{phost}:{pport}", rdns=True)  # remote DNS
        try:
            sock = await p.connect(dest_host=host, dest_port=port)
        except Exception as exc:
            raise TransportError(
                f"could not reach the Tor SOCKS proxy at {phost}:{pport} — is Tor running? ({exc})"
            ) from exc

    ctx = _client_ctx() if tls else None
    try:
        if sock is not None:
            reader, writer = await asyncio.open_connection(
                None, None, sock=sock, ssl=ctx,
                server_hostname=host if tls else None,
                limit=8192 * 2,
            )
        else:
            reader, writer = await asyncio.open_connection(
                host, port, ssl=ctx,
                server_hostname=host if tls else None,
                limit=8192 * 2,
            )
    except TransportError:
        raise
    except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
        raise TransportError(f"could not connect to {host}:{port} ({exc})") from exc

    fp = None
    if tls:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        fp = hashlib.sha256(der).hexdigest()
        if tls_fp:
            if normalize_fingerprint(tls_fp) != fp:
                writer.close()
                raise TransportError(
                    "TLS fingerprint mismatch — the server is NOT the one you pinned.\n"
                    f"  pinned:     {format_fingerprint(normalize_fingerprint(tls_fp))}\n"
                    f"  advertised: {format_fingerprint(fp)}"
                )
    return reader, writer, ConnInfo("TOR" if tor else "TCP", tls, fp)
