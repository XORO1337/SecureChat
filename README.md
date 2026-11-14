![SecureChat Banner](<assets/banner.png>)
End-to-end-encrypted temporary chat rooms in your terminal.

Two or more people share one random code, connect to a relay, and chat in
real time. Messages are encrypted with **AES-256-GCM** before they leave your
machine, **nothing is ever written to disk**, and — unlike Omegle-style P2P
apps — **participants can never see each other's IP addresses**.

![End-to-end encrypted relay flow](<assets/End-to-End Encrypted Relay Flow.png>)

---

## Quick start

Requirements: Python 3.10+ (`pip install -r requirements.txt`)

```bash
# 1. On the relay host (a VPS, your PC, or wherever):
python server.py --host 0.0.0.0 --port 8400

# 2. Each participant:
python client.py --host <relay-ip>
#   -> choose a username (asked every start, never stored)
#   -> [C] create a room  -> share the XXXX-XXXX-XXXX-XXXX code out-of-band
#   -> [J] join with a code you received
```

Windows: use `run_client.bat` / `run_server.bat`.

### In-chat commands
| Command | Effect |
|---|---|
| `/help` | list commands |
| `/code` | reveal the room code (status bar masks it) |
| `/who` | toggle the **Online Users** panel (also: click `* N online`, or F2) |
| `/nick <name>` | change your username |
| `/burn` | wipe the transcript from the screen + memory |
| `/quit` | leave and close (aliases: `/leave`, `/exit`, `/q`) |

Mouse: wheel scrolls the chat pane; clicking `* N online` (or anywhere in the
users panel) toggles the user list. F2 / Esc work in terminals without mouse
support. PageUp/PageDown also scroll.

---

## How the privacy works

### 1. No IP leaks (the Omegle problem)
There is **no peer-to-peer layer at all**. Every message flows through the
relay as opaque ciphertext; clients never learn each other's addresses, and
the relay never sends anyone's IP to anyone. What each party knows:

| Party | Can see | Can't see |
|---|---|---|
| Relay | your IP, opaque room-id hash, random tags, ciphertext sizes, timing | room code, usernames, message text |
| Peers | usernames, messages | your IP, your location, anything else |

Add `--tor` and the relay only sees a Tor exit IP too (see below).

### 2. End-to-end encryption
* The first client generates the room code locally: **16 Crockford-base32
  chars ≈ 80 bits**. It is never sent to the server.
* `master = Argon2id(code)` (scrypt fallback), then HKDF splits it into an
  **opaque room id** (what the wire/server sees) and the **AES-256-GCM key**.
* Nonces are `tag(8 random) + counter(4)` per sender — no nonce reuse — and
  receivers reject non-increasing counters (**replay protection**), with a
  second duplicate-suppression layer in the relay.
* Every ciphertext is AAD-bound to its room id: captured frames can't be
  replayed into a different room.
* Plaintext is padded to size buckets (256…4096 B) so ciphertext length
  doesn't reveal message length.
* Usernames travel **inside** the encrypted payload — the relay only sees
  random tags (`anon-9f2c` style labels appear only if a name is unknown).

### 3. Zero storage
* Server: rooms are dicts in RAM, deleted when the last person leaves.
  No message logging (connection logging is opt-in `--log-connections`).
* Client: in-memory buffers only; input history is `InMemoryHistory`;
  `/burn` clears the transcript; nothing is written anywhere.

---

## Transport options

### Plain TCP (default)
Fine for localhost/LAN. Content is E2E-encrypted regardless.

### TLS (`--tls`)
Recommended over the internet. The relay prints its certificate fingerprint
at startup; pin it on clients:

```bash
python server.py --host 0.0.0.0 --tls          # auto self-signed cert
python client.py --host relay.example.com --tls --tls-fp F9:59:...:96
```

Without `--tls-fp` the client shows the fingerprint and asks for
confirmation (TOFU, in-memory only). A fingerprint mismatch aborts hard.

### Tor (`--tor`, maximum privacy)
```bash
# client (needs Tor running: tor --SocksPort 9050)
python client.py --host <relay-ip-or-xxx.onion> --tor
python client.py --host xxx.onion --tor --tls --tls-fp ...   # both together
```
* Uses SOCKS5 with **remote DNS** (socks5h) — no DNS leaks; `.onion` works.
* Install the extra dependency if needed: `pip install python-socks[asyncio]`

To hide the **server's** IP as well, run the relay as a hidden service:

```tor
# torrc — Hostname will be printed to /var/lib/tor/hidden_service/hostname
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 8400 127.0.0.1:8400
```
Then clients connect to that `.onion` with `--tor`. In this mode nobody in
the network layer — peers, relay, or observers — knows anyone's real IP.

---

## Threat model — read before trusting it

**Protected**
* Relay operators and network observers cannot read messages or usernames.
* Participants cannot discover each other's IP (relay architecture, no P2P).
* With `--tor` (+ hidden-service relay): neither peers nor the relay see real IPs.
* Nothing is stored: no logs, no history, no backfill for late joiners.
* Replay, cross-room frame movement, bit-flip tampering, tag spoofing
  (server stamps the tag itself) and name-based terminal injection
  (strict charset + control-char stripping) are all actively rejected.

**Not protected (be honest with users)**
* **The code is the room.** Anyone who has the code can join and read. Share
  it only over channels you trust.
* **No forward secrecy.** If the code leaks *and* someone recorded ciphertext,
  they can decrypt old messages offline. (A code-authenticated X25519
  handshake is the designed v2 upgrade.)
* Hand-picked codes (`--room`) are as weak as you make them — generated
  codes are 80-bit random; "hunter2" is not.
* The relay can deny service, correlate timing, and see padded sizes.
* Endpoint compromise and your terminal's **scrollback** are out of scope —
  `/burn` clears the app's view, not your terminal emulator's scroll history.

---

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest tests/ -q       # 51 tests: crypto, protocol, transport,
                                 # sanitization, presence, live E2E
```

Project layout:
```
server.py      asyncio relay — RAM-only rooms, rate limits, replay dedupe, TLS
client.py      username prompt, join flow, presence/roster, commands
ui.py          prompt_toolkit TUI (clickable online-count, users overlay)
crypto.py      code generation, Argon2id+HKDF, AES-256-GCM, padding, replay
protocol.py    NDJSON frames, validation, size caps
transport.py   plain / TLS(+fingerprint pin) / Tor SOCKS5h connection factory
phrases.py     join announcement templates
tests/         unit + integration suites (incl. wire-tap plaintext check)
```

*Test utilities* (`tests/setup_wsl.sh`, `tests/smoke_wsl.sh`) were used to
verify under WSL/Kali Python 3.14; the project itself is pure cross-platform
Python with no OS-specific dependencies.
