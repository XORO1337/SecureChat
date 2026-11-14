"""Local browser dashboard for starting SecureChat processes.

The dashboard deliberately binds to localhost by default. It starts the
existing relay and terminal client without a shell, and keeps their recent
startup output in memory only.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
_lock = threading.Lock()
_processes: dict[str, subprocess.Popen] = {}
_logs: dict[str, list[str]] = {"server": [], "client": []}


def _read_output(kind: str, process: subprocess.Popen) -> None:
    if process.stdout is None:
        return
    for line in process.stdout:
        with _lock:
            _logs[kind].append(line.rstrip())
            _logs[kind] = _logs[kind][-80:]


def _stop(kind: str) -> None:
    with _lock:
        process = _processes.pop(kind, None)
    if process is not None and process.poll() is None:
        process.terminate()


def _start(kind: str, args: list[str]) -> str:
    _stop(kind)
    try:
        process = subprocess.Popen(
            [sys.executable, *args],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        return f"Could not start {kind}: {exc}"
    with _lock:
        _processes[kind] = process
        _logs[kind] = [f"started: {' '.join([sys.executable, *args])}"]
    threading.Thread(target=_read_output, args=(kind, process), daemon=True).start()
    return f"{kind.capitalize()} started."


def _field(form: dict[str, list[str]], name: str, default: str = "") -> str:
    return (form.get(name, [default])[0] or default).strip()


def _page(message: str = "") -> bytes:
    with _lock:
        states = {
            kind: ("running" if process.poll() is None else f"exited ({process.returncode})")
            for kind, process in _processes.items()
        }
        logs = {kind: list(lines) for kind, lines in _logs.items()}
    def block(kind: str) -> str:
        state = states.get(kind, "stopped")
        text = html.escape("\n".join(logs[kind]))
        running = state == "running"
        dot = "bg-emerald-400 shadow-[0_0_12px_#34d399]" if running else "bg-slate-500"
        return (
            f'<div class="flex items-center gap-2 text-sm text-[var(--muted)]">'
            f'<span class="h-2 w-2 rounded-full {dot}"></span>'
            f'<span>{html.escape(state)}</span></div>'
            f'<pre class="mt-4 max-h-64 overflow-auto rounded-xl border border-[var(--border)] '
            f'bg-black/20 p-4 text-xs leading-6 text-[var(--muted)]">{text}</pre>'
        )
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureChat dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
 :root {{ --bg: #10151c; --panel: #171e27; --input: #0d1117;
--text: #e6edf3; --muted: #8b949e; --accent: #58a6ff; --accent-text: #fff;
--success: #7ee787; --warning: #f2cc60; --border: #30363d;
--shadow: 0 12px 30px #0005 }}
[data-theme="netherworld"] {{ --bg: #140b18; --panel: #24102b; --input: #100813;
--text: #f6e8ff; --muted: #c398d1; --accent: #ff3864; --accent-text: #fff;
--success: #d7ff70; --warning: #ffb86c; --border: #6b214f; --shadow: 0 0 24px #ff174455 }}
[data-theme="hacker"] {{ --bg: #020604; --panel: #07130b; --input: #010301;
--text: #b7ffc4; --muted: #54a866; --accent: #00ff66; --accent-text: #001b08;
--success: #00ff66; --warning: #d5ff00; --border: #12652c; --shadow: 0 0 18px #00ff6633 }}
[data-theme="terminal"] {{ --bg: #00110a; --panel: #002015; --input: #000b07;
--text: #a8ffc1; --muted: #51a66c; --accent: #39ff88; --accent-text: #00150a;
--success: #39ff88; --warning: #d8ff75; --border: #176b3b; --shadow: 0 0 0 transparent }}
[data-theme="ocean"] {{ --bg: #071923; --panel: #0d2938; --input: #06131b;
--text: #d7f4ff; --muted: #79b8cc; --accent: #38c8e8; --accent-text: #03202b;
--success: #76e6b5; --warning: #ffd166; --border: #1d5b70; --shadow: 0 12px 30px #00182299 }}
[data-theme="solarized"] {{ --bg: #002b36; --panel: #073642; --input: #00212b;
--text: #eee8d5; --muted: #93a1a1; --accent: #b58900; --accent-text: #fff;
--success: #859900; --warning: #cb4b16; --border: #586e75; --shadow: 0 12px 30px #00151a99 }}
body {{ background: var(--bg); color: var(--text); transition: background .25s, color .25s }}
body[data-theme="terminal"] {{ font-family: "Courier New", monospace }}
.modal {{ display: none }} .modal.open {{ display: flex }}
</style></head><body>
<div class="mx-auto min-h-screen max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
<header class="mb-10 flex flex-col justify-between gap-6 sm:flex-row sm:items-center">
<div><div class="mb-3 flex items-center gap-3"><span class="h-3 w-3 rounded-full bg-[var(--success)] shadow-[0_0_16px_var(--success)]"></span>
<span class="text-xs font-bold uppercase tracking-[.25em] text-[var(--muted)]">Secure relay</span></div>
<h1 class="text-4xl font-black tracking-tight text-[var(--accent)] sm:text-5xl">SecureChat</h1>
<p class="mt-2 text-[var(--muted)]">Encrypted relay control center</p></div>
<label class="w-full text-xs font-bold uppercase tracking-wider text-[var(--muted)] sm:w-48">Theme
<select id="theme" class="mt-2 w-full rounded-xl border border-[var(--border)] bg-[var(--input)] px-3 py-2.5 text-sm text-[var(--text)] outline-none transition focus:border-[var(--accent)]" onchange="setTheme(this.value)">
<option value="dark">Dark</option>
<option value="netherworld">Netherworld</option>
<option value="hacker">Hacker</option>
<option value="terminal">Terminalistic</option>
<option value="ocean">Ocean</option>
<option value="solarized">Solarized</option>
</select></label>
</header>
<div class="mb-6 flex items-center gap-3 rounded-2xl border border-[var(--border)] bg-[var(--panel)] px-4 py-3 text-sm text-[var(--warning)] shadow-[var(--shadow)]">
<span class="text-lg">◈</span><span>Local dashboard · keep it bound to <code>127.0.0.1</code></span></div>
<p id="message" class="mb-6 min-h-6 text-sm font-medium text-[var(--success)]">{html.escape(message)}</p>
<main class="grid gap-5 lg:grid-cols-2">
<section class="rounded-3xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)] transition hover:-translate-y-0.5">
<form method="post" action="/server" class="space-y-5">
<div class="mb-6 flex items-start justify-between"><div><p class="text-xs font-bold uppercase tracking-[.2em] text-[var(--success)]">Relay</p><h2 class="mt-2 text-2xl font-bold">Start server</h2><p class="mt-1 text-sm text-[var(--muted)]">Create a room and generate an invitation.</p></div><span class="rounded-2xl bg-[var(--accent)]/10 px-3 py-2 text-xl text-[var(--accent)]">⌁</span></div>
<label class="block text-sm font-medium text-[var(--muted)]">Bind host<input class="mt-2 w-full rounded-xl border border-[var(--border)] bg-[var(--input)] px-4 py-3 text-[var(--text)] outline-none transition focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/20" name="host" value="127.0.0.1"></label>
<label class="block text-sm font-medium text-[var(--muted)]">Advertised host<input class="mt-2 w-full rounded-xl border border-[var(--border)] bg-[var(--input)] px-4 py-3 text-[var(--text)] outline-none transition focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/20" name="advertise_host" placeholder="127.0.0.1 or relay.example.com"></label>
<label class="block text-sm font-medium text-[var(--muted)]">Port<input class="mt-2 w-full rounded-xl border border-[var(--border)] bg-[var(--input)] px-4 py-3 text-[var(--text)] outline-none transition focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/20" name="port" value="8400" inputmode="numeric"></label>
<button class="w-full rounded-xl bg-[var(--accent)] px-4 py-3 font-bold text-[var(--accent-text)] shadow-lg transition hover:brightness-110 active:scale-[.98]">Start relay server <span class="float-right">→</span></button></form>
</section>
<section class="rounded-3xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)] transition hover:-translate-y-0.5">
<form method="post" action="/client" class="space-y-5">
<div class="mb-6 flex items-start justify-between"><div><p class="text-xs font-bold uppercase tracking-[.2em] text-[var(--success)]">Client</p><h2 class="mt-2 text-2xl font-bold">Join a room</h2><p class="mt-1 text-sm text-[var(--muted)]">Launch the secure terminal client.</p></div><span class="rounded-2xl bg-[var(--accent)]/10 px-3 py-2 text-xl text-[var(--accent)]">↗</span></div>
<label class="block text-sm font-medium text-[var(--muted)]">Invitation<input class="mt-2 w-full rounded-xl border border-[var(--border)] bg-[var(--input)] px-4 py-3 font-mono text-sm text-[var(--text)] outline-none transition focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/20" name="room" required placeholder="SC1...."></label>
<label class="block text-sm font-medium text-[var(--muted)]">Username<input class="mt-2 w-full rounded-xl border border-[var(--border)] bg-[var(--input)] px-4 py-3 text-[var(--text)] outline-none transition focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent)]/20" name="name" required minlength="2" maxlength="20" placeholder="Your display name"></label>
<button class="w-full rounded-xl bg-[var(--accent)] px-4 py-3 font-bold text-[var(--accent-text)] shadow-lg transition hover:brightness-110 active:scale-[.98]">Launch client <span class="float-right">→</span></button></form>
</section>
<section class="rounded-3xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)] lg:col-span-2">
<div class="flex flex-col justify-between gap-4 sm:flex-row sm:items-center"><div><p class="text-xs font-bold uppercase tracking-[.2em] text-[var(--muted)]">Workspace</p><h2 class="mt-2 text-2xl font-bold">Process controls</h2></div>
<div class="flex flex-wrap gap-3"><form method="post" action="/stop"><button class="rounded-xl border border-rose-400/30 bg-rose-500/10 px-4 py-2.5 text-sm font-bold text-rose-300 transition hover:bg-rose-500/20" name="kind" value="server">Stop server</button><button class="rounded-xl border border-rose-400/30 bg-rose-500/10 px-4 py-2.5 text-sm font-bold text-rose-300 transition hover:bg-rose-500/20" name="kind" value="client">Stop client</button></form>
<button id="show-invite" class="rounded-xl border border-[var(--border)] px-4 py-2.5 text-sm font-bold text-[var(--text)] transition hover:border-[var(--accent)] hover:text-[var(--accent)]" type="button" hidden onclick="openInvite()">Show invitation</button></div></div>
</section>
<section class="rounded-3xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)]"><div class="mb-4 flex items-center justify-between"><h2 class="text-lg font-bold">Relay status</h2><span class="text-xs uppercase tracking-wider text-[var(--muted)]">Live</span></div><div id="server-status">{block("server")}</div></section>
<section class="rounded-3xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-[var(--shadow)]"><div class="mb-4 flex items-center justify-between"><h2 class="text-lg font-bold">Client status</h2><span class="text-xs uppercase tracking-wider text-[var(--muted)]">Live</span></div><div id="client-status">{block("client")}</div></section>
</main>
<div id="invite-modal" class="modal fixed inset-0 z-10 items-center justify-center bg-black/70 p-4 backdrop-blur-sm" role="dialog" aria-modal="true">
<div class="w-full max-w-2xl rounded-3xl border border-[var(--accent)] bg-[var(--panel)] p-6 shadow-2xl sm:p-8"><div class="flex items-start justify-between"><div><p class="text-xs font-bold uppercase tracking-[.2em] text-[var(--success)]">Room ready</p><h2 class="mt-2 text-2xl font-bold">Share invitation</h2></div><button class="rounded-xl px-3 py-2 text-xl text-[var(--muted)] hover:bg-white/10" type="button" onclick="closeInvite()">×</button></div><p class="mt-6 text-sm text-[var(--muted)]">Anyone holding this code can join the room.</p>
<div id="invite-code" class="mt-4 break-all rounded-2xl border border-[var(--border)] bg-[var(--input)] p-5 font-mono text-sm leading-7 text-[var(--success)] selection:bg-[var(--accent)] selection:text-[var(--accent-text)]"></div>
<button class="mt-5 rounded-xl bg-[var(--accent)] px-5 py-3 font-bold text-[var(--accent-text)] transition hover:brightness-110" type="button" onclick="copyInvite()">Copy invitation</button></div></div>
<script>
function setTheme(theme) {{
  document.body.dataset.theme = theme;
  document.getElementById("theme").value = theme;
  localStorage.setItem("securechat-theme", theme);
}}
setTheme(localStorage.getItem("securechat-theme") || "dark");
let invitation = localStorage.getItem("securechat-invitation") || "";
function openInvite() {{
  if (!invitation) return;
  document.getElementById("invite-code").textContent = invitation;
  document.getElementById("invite-modal").classList.add("open");
}}
function closeInvite() {{ document.getElementById("invite-modal").classList.remove("open"); }}
function copyInvite() {{ navigator.clipboard.writeText(invitation); }}
function updateStatus(data) {{
  for (const kind of ["server", "client"]) {{
    const state = data.states[kind] || "stopped";
    const lines = (data.logs[kind] || []).join("\\n");
    const safe = lines.replaceAll("&", "&amp;").replaceAll("<", "&lt;");
    document.getElementById(kind + "-status").innerHTML =
      "<h2>" + kind[0].toUpperCase() + kind.slice(1) +
      " <small>" + state + "</small></h2><pre>" + safe + "</pre>";
    const match = lines.match(/share this room invitation:\\s*(SC1\\.\\S+)/i);
    if (kind === "server" && match) {{
      if (match[1] !== invitation) {{
        invitation = match[1];
        localStorage.setItem("securechat-invitation", invitation);
        openInvite();
      }}
      document.getElementById("show-invite").hidden = false;
    }}
  }}
}}
async function poll() {{
  const response = await fetch("/api/status");
  updateStatus(await response.json());
}}
setInterval(poll, 1500);
if (invitation) document.getElementById("show-invite").hidden = false;
</script>
</body></html>"""
    return body.encode("utf-8")


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            self._reply_json(self._status())
            return
        notice = parse_qs(parsed.query).get("notice", [""])[0]
        self._reply(200, _page(notice))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        if self.path == "/server":
            host = _field(form, "host", "127.0.0.1")
            advertise = _field(form, "advertise_host")
            port = _field(form, "port", "8400")
            args = ["server.py", "--host", host, "--port", port]
            if advertise:
                args += ["--advertise-host", advertise]
            message = _start("server", args)
        elif self.path == "/client":
            room = _field(form, "room")
            name = _field(form, "name")
            message = _start("client", ["client.py", "--room", room, "--name", name])
        elif self.path == "/stop":
            kind = _field(form, "kind")
            if kind not in ("server", "client"):
                message = "Unknown process."
            else:
                _stop(kind)
                message = f"{kind.capitalize()} stopped."
        else:
            message = "Unknown action."
        query = urlencode({"notice": message})
        self._reply(303, b"", location=f"/?{query}")

    @staticmethod
    def _status() -> dict:
        with _lock:
            return {
                "states": {
                    kind: ("running" if process.poll() is None
                           else f"exited ({process.returncode})")
                    for kind, process in _processes.items()
                },
                "logs": {kind: list(lines) for kind, lines in _logs.items()},
            }

    def _reply_json(self, value: dict) -> None:
        body = json.dumps(value).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reply(self, status: int, body: bytes, location: str | None = None) -> None:
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        else:
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if status != 303:
            self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="SecureChat local web dashboard")
    parser.add_argument("--host", default="127.0.0.1",
                        help="dashboard bind host (default: localhost)")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"SecureChat dashboard: http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _stop("client")
        _stop("server")


if __name__ == "__main__":
    main()
