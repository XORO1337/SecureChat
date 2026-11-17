"""Local browser dashboard for starting SecureChat processes.

The dashboard deliberately binds to localhost by default. It starts the
existing relay and terminal client without a shell, and keeps their recent
startup output in memory only.

The page is a single self-contained document: hand-written CSS (no CDN), a
theme engine with eight built-in themes, themed ambient background effects,
live consoles, toasts, and the invitation popup.
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
_args: dict[str, list[str]] = {"server": [], "client": []}

# Plain template: the only substitution is __NOTICE__ (html-escaped before
# insertion). Deliberately not an f-string — the CSS/JS below contain many
# braces that would need doubling.
_PAGE = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureChat · Relay Control Center</title>
<meta name="color-scheme" content="dark">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%234da3ff' d='M12 2.6 20 5.6v5.8c0 4.9-3.4 8.7-8 10-4.6-1.3-8-5.1-8-10V5.6l8-3z'/%3E%3C/svg%3E">
<script>
/* Restore the saved theme before first paint (no flash). */
(function () {
  try {
    var t = localStorage.getItem("securechat-theme");
    if (t && ["dark","netherworld","hacker","terminal","interstellar","ocean","solarized","aurora"].indexOf(t) !== -1) {
      document.documentElement.dataset.theme = t;
    }
  } catch (e) {}
})();
</script>
<style>
/* ============================================================
   SecureChat design system — eight themes, all hand-rolled CSS
   (fully offline: no Tailwind/CDN required).
   ============================================================ */
*, *::before, *::after { box-sizing: border-box; }
html { color-scheme: dark; scrollbar-gutter: stable; }
:root {
  --font-ui: "Inter", "SF Pro Text", "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  --font-mono: "Cascadia Code", "JetBrains Mono", "Fira Code", "SF Mono", ui-monospace, Consolas, "Courier New", monospace;
  --radius: 18px;
  --shadow: 0 12px 40px rgba(0, 0, 0, .35);
  --text-glow: none;
}

/* ---------- Themes ---------- */
:root, [data-theme="dark"] {
  --bg: #0b0f16; --bg-hi: #101827;
  --panel: rgba(17, 24, 34, .72); --panel-solid: #111820; --input: rgba(9, 13, 19, .85);
  --text: #e8eef7; --muted: #8d9aaf;
  --accent: #4da3ff; --accent-2: #8b5cf6; --accent-text: #ffffff;
  --success: #3fd68f; --warning: #f2c14e; --danger: #ff5d73;
  --border: rgba(148, 163, 184, .16); --border-strong: rgba(148, 163, 184, .34);
  --grid-c: rgba(148, 163, 184, .055);
  --glow-a: rgba(77, 163, 255, .14); --glow-b: rgba(139, 92, 246, .13);
  --scan-o: 0;
}
[data-theme="netherworld"] {
  --bg: #140919; --bg-hi: #200b29;
  --panel: rgba(33, 13, 42, .74); --panel-solid: #220d2b; --input: rgba(18, 7, 23, .85);
  --text: #fdeaff; --muted: #c48cd6;
  --accent: #ff2e63; --accent-2: #b44bff; --accent-text: #ffffff;
  --success: #a6ff70; --warning: #ffb454; --danger: #ff5d73;
  --border: rgba(255, 46, 99, .22); --border-strong: rgba(255, 46, 99, .42);
  --grid-c: rgba(255, 46, 99, .05);
  --glow-a: rgba(255, 46, 99, .17); --glow-b: rgba(120, 32, 220, .17);
  --scan-o: 0;
}
[data-theme="hacker"] {
  --font-ui: var(--font-mono);
  --bg: #020604; --bg-hi: #04160b;
  --panel: rgba(4, 21, 11, .78); --panel-solid: #04160c; --input: rgba(1, 7, 3, .9);
  --text: #c9ffd8; --muted: #55a468;
  --accent: #00ff66; --accent-2: #00d9a6; --accent-text: #00150a;
  --success: #00ff66; --warning: #d8ff4f; --danger: #ff5c5c;
  --border: rgba(0, 255, 102, .18); --border-strong: rgba(0, 255, 102, .4);
  --grid-c: rgba(0, 255, 102, .05);
  --glow-a: rgba(0, 255, 102, .07); --glow-b: rgba(0, 217, 166, .06);
  --scan-o: .05;
  --text-glow: 0 0 10px rgba(0, 255, 102, .35);
}
[data-theme="terminal"] {
  --font-ui: var(--font-mono);
  --bg: #0d0700; --bg-hi: #180f02;
  --panel: rgba(28, 18, 3, .78); --panel-solid: #1b1204; --input: rgba(13, 8, 0, .9);
  --text: #ffc97b; --muted: #ab8143;
  --accent: #ffb020; --accent-2: #ff8a3d; --accent-text: #1c1000;
  --success: #8aff80; --warning: #ff6b4a; --danger: #ff5c5c;
  --border: rgba(255, 176, 32, .2); --border-strong: rgba(255, 176, 32, .45);
  --grid-c: rgba(255, 176, 32, .05);
  --glow-a: rgba(255, 140, 32, .1); --glow-b: rgba(255, 176, 32, .07);
  --scan-o: .07;
  --text-glow: 0 0 10px rgba(255, 176, 32, .3);
}
[data-theme="interstellar"] {
  --bg: #05060f; --bg-hi: #0c0e26;
  --panel: rgba(15, 17, 38, .74); --panel-solid: #0f1126; --input: rgba(7, 8, 18, .85);
  --text: #e9ebff; --muted: #8f94c9;
  --accent: #7df3ff; --accent-2: #a78bfa; --accent-text: #051019;
  --success: #5effc4; --warning: #ffd36e; --danger: #ff6b8a;
  --border: rgba(160, 170, 255, .16); --border-strong: rgba(160, 170, 255, .34);
  --grid-c: rgba(160, 170, 255, .05);
  --glow-a: rgba(125, 243, 255, .1); --glow-b: rgba(167, 139, 250, .12);
  --scan-o: 0;
}
[data-theme="ocean"] {
  --bg: #041420; --bg-hi: #082c40;
  --panel: rgba(10, 35, 50, .74); --panel-solid: #0a2433; --input: rgba(4, 17, 25, .85);
  --text: #dbf3ff; --muted: #71a7c1;
  --accent: #2fd6c8; --accent-2: #4aa8ff; --accent-text: #032024;
  --success: #63e6a5; --warning: #ffd166; --danger: #ff6b7d;
  --border: rgba(90, 200, 220, .16); --border-strong: rgba(90, 200, 220, .34);
  --grid-c: rgba(90, 200, 220, .05);
  --glow-a: rgba(47, 214, 200, .12); --glow-b: rgba(74, 168, 255, .12);
  --scan-o: 0;
}
[data-theme="solarized"] {
  --bg: #002b36; --bg-hi: #0a4253;
  --panel: rgba(7, 54, 66, .78); --panel-solid: #073642; --input: rgba(0, 33, 43, .85);
  --text: #eee8d5; --muted: #93a1a1;
  --accent: #2aa8cc; --accent-2: #d33682; --accent-text: #ffffff;
  --success: #859900; --warning: #cb4b16; --danger: #dc322f;
  --border: rgba(147, 161, 161, .22); --border-strong: rgba(147, 161, 161, .42);
  --grid-c: rgba(147, 161, 161, .05);
  --glow-a: rgba(38, 139, 210, .13); --glow-b: rgba(133, 153, 0, .08);
  --scan-o: 0;
}
[data-theme="aurora"] {
  --bg: #04090d; --bg-hi: #08141d;
  --panel: rgba(11, 23, 31, .74); --panel-solid: #0a141c; --input: rgba(5, 12, 16, .85);
  --text: #e4f8ef; --muted: #7fb0a2;
  --accent: #3cf5c0; --accent-2: #8a7dff; --accent-text: #04130e;
  --success: #5cf0ae; --warning: #ffcf6e; --danger: #ff6b8a;
  --border: rgba(60, 245, 192, .16); --border-strong: rgba(60, 245, 192, .34);
  --grid-c: rgba(60, 245, 192, .045);
  --glow-a: rgba(60, 245, 192, .12); --glow-b: rgba(138, 125, 255, .14);
  --scan-o: 0;
}

/* ---------- Base ---------- */
body {
  margin: 0; min-height: 100svh;
  font-family: var(--font-ui); font-size: 15px; line-height: 1.6;
  color: var(--text); letter-spacing: .005em;
  background:
    radial-gradient(1100px 720px at 88% -12%, var(--glow-a), transparent 62%),
    radial-gradient(950px 640px at -8% 108%, var(--glow-b), transparent 58%),
    linear-gradient(180deg, var(--bg-hi), var(--bg) 46%);
  background-attachment: fixed;
}
[hidden] { display: none !important; }
code { font-family: var(--font-mono); font-size: .92em; }
::selection { background: var(--accent); color: var(--accent-text); }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 8px; border: 2px solid transparent; background-clip: content-box; }
::-webkit-scrollbar-track { background: transparent; }
* { scrollbar-width: thin; scrollbar-color: var(--border-strong) transparent; }

/* ---------- Ambient background layers ---------- */
.bg-grid {
  position: fixed; inset: 0; z-index: 1; pointer-events: none;
  background-image:
    linear-gradient(var(--grid-c) 1px, transparent 1px),
    linear-gradient(90deg, var(--grid-c) 1px, transparent 1px);
  background-size: 46px 46px;
  -webkit-mask-image: radial-gradient(120% 78% at 50% -6%, #000 0%, transparent 72%);
  mask-image: radial-gradient(120% 78% at 50% -6%, #000 0%, transparent 72%);
}
#fx { position: fixed; inset: 0; z-index: 2; pointer-events: none; }
.vignette {
  position: fixed; inset: 0; z-index: 3; pointer-events: none;
  background: radial-gradient(130% 100% at 50% 42%, transparent 58%, rgba(0, 0, 0, .3));
}
.scanlines {
  position: fixed; inset: 0; z-index: 4; pointer-events: none;
  opacity: var(--scan-o);
  background: repeating-linear-gradient(0deg, rgba(0, 0, 0, .5) 0 1px, transparent 1px 3px);
}
html[data-theme="terminal"] .scanlines { animation: flicker 5s linear infinite; }
@keyframes flicker {
  0%, 89%, 100% { opacity: var(--scan-o); }
  90% { opacity: calc(var(--scan-o) * 1.9); }
  92% { opacity: calc(var(--scan-o) * .6); }
  94% { opacity: calc(var(--scan-o) * 1.4); }
}
.bg-ribbons { position: fixed; inset: -22%; z-index: 1; pointer-events: none; display: none; filter: blur(70px); }
html[data-theme="aurora"] .bg-ribbons { display: block; }
.bg-ribbons i { position: absolute; width: 46%; height: 36%; border-radius: 50%; }
.bg-ribbons i:nth-child(1) { left: 4%; top: 10%; background: radial-gradient(closest-side, rgba(60, 245, 192, .5), transparent 72%); animation: drift 24s ease-in-out infinite alternate; }
.bg-ribbons i:nth-child(2) { right: 2%; top: 34%; background: radial-gradient(closest-side, rgba(138, 125, 255, .46), transparent 72%); animation: drift 30s ease-in-out infinite alternate-reverse; }
.bg-ribbons i:nth-child(3) { left: 30%; bottom: 4%; background: radial-gradient(closest-side, rgba(255, 94, 168, .3), transparent 72%); animation: drift 36s ease-in-out infinite alternate; }
@keyframes drift {
  from { transform: translate3d(-2%, -2%, 0) scale(1); }
  to { transform: translate3d(4%, 6%, 0) scale(1.12); }
}

/* ---------- Topbar ---------- */
.topbar {
  position: sticky; top: 0; z-index: 50;
  background: var(--panel);
  backdrop-filter: blur(16px) saturate(1.25);
  -webkit-backdrop-filter: blur(16px) saturate(1.25);
  border-bottom: 1px solid var(--border);
}
.topbar-inner {
  max-width: 1180px; margin: 0 auto; padding: 12px 24px;
  display: flex; align-items: center; flex-wrap: wrap; gap: 12px 18px;
}
.brand { display: inline-flex; align-items: center; gap: 10px; text-decoration: none; }
.brand svg { width: 27px; height: 27px; color: var(--accent); filter: drop-shadow(0 0 7px var(--accent)); }
.brand-name {
  font-weight: 800; font-size: 17.5px; letter-spacing: -.02em;
  background: linear-gradient(92deg, var(--text) 25%, var(--accent) 80%);
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
.top-status { display: flex; gap: 8px; margin-left: auto; }
.pill {
  display: inline-flex; align-items: center; gap: 8px; padding: 6px 13px;
  border-radius: 999px; border: 1px solid var(--border); background: var(--input);
  font-size: 12px; font-weight: 700; letter-spacing: .04em; color: var(--muted);
}
.pill .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--border-strong); }
.pill.running { color: var(--success); border-color: var(--border-strong); }
.pill.running { border-color: color-mix(in srgb, var(--success) 38%, transparent); }
.pill.running .dot { background: var(--success); box-shadow: 0 0 9px var(--success); animation: pulse 1.9s ease-in-out infinite; }
.pill.exited { color: var(--danger); border-color: var(--border-strong); }
.pill.exited { border-color: color-mix(in srgb, var(--danger) 40%, transparent); }
.pill.exited .dot { background: var(--danger); }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }

/* ---------- Theme switcher ---------- */
.theme-widget { position: relative; }
#theme-btn {
  display: inline-flex; align-items: center; gap: 9px; padding: 8px 13px;
  border-radius: 12px; border: 1px solid var(--border); background: var(--input);
  color: var(--text); font: inherit; font-size: 13px; font-weight: 700; cursor: pointer;
  transition: border-color .2s, color .2s;
}
#theme-btn:hover { border-color: var(--accent); }
#theme-btn .chev { width: 14px; height: 14px; color: var(--muted); transition: transform .2s; }
#theme-btn[aria-expanded="true"] .chev { transform: rotate(180deg); }
.swatch {
  width: 15px; height: 15px; border-radius: 6px;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, .18);
}
.theme-menu {
  position: absolute; right: 0; top: calc(100% + 8px); width: 220px; padding: 6px;
  border-radius: 14px; border: 1px solid var(--border-strong);
  background: var(--panel-solid);
  box-shadow: var(--shadow), 0 24px 70px rgba(0, 0, 0, .5); z-index: 60;
}
.theme-opt {
  display: flex; align-items: center; gap: 10px; width: 100%; padding: 9px 10px;
  border: 0; border-radius: 10px; background: transparent; color: var(--text);
  font: inherit; font-size: 13px; font-weight: 600; text-align: left; cursor: pointer;
}
.theme-opt:hover { background: rgba(255, 255, 255, .06); }
.theme-opt:hover { background: color-mix(in srgb, var(--accent) 14%, transparent); }
.theme-opt::after { content: ""; margin-left: auto; }
.theme-opt[aria-checked="true"] { color: var(--accent); }
.theme-opt[aria-checked="true"]::after { content: "✓"; font-weight: 800; }
.theme-menu .swatch { width: 17px; height: 17px; border-radius: 7px; }
.sw-dark { background: linear-gradient(135deg, #4da3ff, #8b5cf6); }
.sw-netherworld { background: linear-gradient(135deg, #ff2e63, #b44bff); }
.sw-hacker { background: linear-gradient(135deg, #00ff66, #00d9a6); }
.sw-terminal { background: linear-gradient(135deg, #ffb020, #ff8a3d); }
.sw-interstellar { background: linear-gradient(135deg, #7df3ff, #a78bfa); }
.sw-ocean { background: linear-gradient(135deg, #2fd6c8, #4aa8ff); }
.sw-solarized { background: linear-gradient(135deg, #2aa8cc, #859900); }
.sw-aurora { background: linear-gradient(135deg, #3cf5c0, #8a7dff); }
/* ---------- Layout shell & hero ---------- */
.shell {
  position: relative; z-index: 5; max-width: 1180px; margin: 0 auto;
  padding: 36px 24px 26px; display: grid; gap: 18px;
}
.hero { padding: 10px 2px 2px; }
.hero-chips { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.chip-tag {
  padding: 5px 12px; border-radius: 999px; border: 1px solid var(--border);
  background: var(--input); color: var(--muted);
  font-size: 10.5px; font-weight: 800; letter-spacing: .16em; text-transform: uppercase;
}
.chip-tag.alt { color: var(--accent); border-color: var(--border-strong); }
.chip-tag.alt { border-color: color-mix(in srgb, var(--accent) 45%, transparent); }
.title {
  margin: 0; font-size: clamp(34px, 4.6vw, 52px);
  font-weight: 800; letter-spacing: -.035em; line-height: 1.04;
}
.title .grad {
  background: linear-gradient(94deg, var(--accent) 0%, var(--accent-2) 55%, var(--accent) 110%);
  background-size: 220% 100%;
  -webkit-background-clip: text; background-clip: text; color: transparent;
  animation: shimmer 8s ease-in-out infinite alternate;
}
@keyframes shimmer { from { background-position: 0% 0; } to { background-position: 100% 0; } }
.lede { margin: 12px 0 0; max-width: 660px; color: var(--muted); font-size: 16px; }

/* ---------- Cards ---------- */
.card {
  border-radius: var(--radius); border: 1px solid var(--border);
  background: var(--panel);
  backdrop-filter: blur(14px) saturate(1.2);
  -webkit-backdrop-filter: blur(14px) saturate(1.2);
  box-shadow: var(--shadow);
}

/* ---------- Stat cards ---------- */
.stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
.stat { display: flex; align-items: center; gap: 14px; padding: 17px 19px; }
.stat-icon {
  flex: 0 0 auto; width: 44px; height: 44px; border-radius: 13px;
  display: grid; place-items: center; color: var(--accent);
  background: var(--input); border: 1px solid var(--border);
}
.stat-icon svg { width: 21px; height: 21px; }
.stat h4 {
  margin: 0; font-size: 10.5px; font-weight: 800;
  letter-spacing: .2em; text-transform: uppercase; color: var(--muted);
}
.stat .v { margin: 2px 0 0; font-size: 16.5px; font-weight: 750; letter-spacing: -.01em; }
.stat .v.ok { color: var(--success); text-shadow: var(--text-glow); }
.stat .v.bad { color: var(--danger); }
.stat .s {
  margin: 1px 0 0; font-size: 12px; color: var(--muted);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 30vw;
}

/* ---------- Launcher cards ---------- */
.launchers { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.launcher { padding: 24px; transition: transform .18s ease, border-color .25s ease, box-shadow .25s ease; }
.launcher:hover {
  transform: translateY(-3px); border-color: var(--border-strong);
  box-shadow: 0 18px 50px rgba(0, 0, 0, .45);
}
.launcher-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 20px; }
.eyebrow {
  margin: 0; font-size: 10.5px; font-weight: 800;
  letter-spacing: .24em; text-transform: uppercase;
  color: var(--accent); text-shadow: var(--text-glow);
}
.launcher h2 { margin: 6px 0 4px; font-size: 21px; font-weight: 750; letter-spacing: -.02em; }
.desc { margin: 0; color: var(--muted); font-size: 13.5px; }
.launcher-icon {
  flex: 0 0 auto; width: 42px; height: 42px; border-radius: 12px;
  display: grid; place-items: center; color: var(--accent);
  background: var(--input); border: 1px solid var(--border);
}
.launcher-icon {
  background: color-mix(in srgb, var(--accent) 10%, transparent);
  border-color: color-mix(in srgb, var(--accent) 26%, transparent);
}
.launcher-icon svg { width: 20px; height: 20px; }

/* ---------- Fields ---------- */
.field { margin-bottom: 15px; }
.field label {
  display: block; margin-bottom: 7px; font-size: 11px; font-weight: 800;
  letter-spacing: .1em; text-transform: uppercase; color: var(--muted);
}
.field input {
  width: 100%; padding: 11.5px 14px; border-radius: 12px;
  border: 1px solid var(--border); background: var(--input); color: var(--text);
  font: inherit; font-size: 14.5px;
  transition: border-color .2s, box-shadow .2s;
}
.field input.mono { font-family: var(--font-mono); font-size: 13.5px; }
.field input::placeholder { color: var(--muted); opacity: .55; }
.field input:focus {
  outline: none; border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(127, 127, 127, .2);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent),
              0 0 24px color-mix(in srgb, var(--accent) 14%, transparent);
}
.hint { margin: 7px 0 0; font-size: 11.5px; color: var(--muted); opacity: .85; }

/* ---------- Buttons ---------- */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  border: 0; border-radius: 12px; font: inherit; font-size: 14px; font-weight: 700;
  padding: 12px 18px; cursor: pointer; text-decoration: none;
  transition: transform .15s ease, filter .2s ease, background .2s ease,
              border-color .2s ease, color .2s ease;
}
.btn svg { width: 16px; height: 16px; }
.btn.primary {
  color: var(--accent-text);
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, .12);
}
.btn.primary {
  box-shadow: 0 10px 26px color-mix(in srgb, var(--accent) 28%, transparent),
              inset 0 0 0 1px rgba(255, 255, 255, .12);
}
.btn.primary:hover { filter: brightness(1.08); transform: translateY(-1px); }
.btn.primary:active { transform: translateY(0) scale(.985); }
.btn .arr { transition: transform .2s ease; }
.btn:hover .arr { transform: translateX(3px); }
.btn.ghost { background: transparent; border: 1px solid var(--border-strong); color: var(--text); }
.btn.ghost:hover { border-color: var(--accent); color: var(--accent); }
.btn.danger-ghost {
  background: rgba(255, 92, 112, .08);
  border: 1px solid rgba(255, 92, 112, .3);
  color: #ff5d73;
}
.btn.danger-ghost {
  background: color-mix(in srgb, var(--danger) 10%, transparent);
  border-color: color-mix(in srgb, var(--danger) 30%, transparent);
  color: var(--danger);
}
.btn.danger-ghost:hover { filter: brightness(1.2); }
.btn.block { width: 100%; }
.stop-form { display: flex; gap: 10px; flex-wrap: wrap; }

/* ---------- Process controls ---------- */
.controls {
  display: flex; align-items: center; justify-content: space-between;
  flex-wrap: wrap; gap: 14px; padding: 18px 22px;
}
.controls h2 { margin: 5px 0 3px; font-size: 19px; font-weight: 750; letter-spacing: -.02em; }
.controls-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
/* ---------- Consoles ---------- */
.consoles { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.console { display: flex; flex-direction: column; overflow: hidden; }
.console-head {
  display: flex; align-items: center; gap: 12px; padding: 11px 16px;
  border-bottom: 1px solid var(--border); background: var(--input);
}
.tl { display: flex; gap: 6px; }
.tl i { width: 9px; height: 9px; border-radius: 50%; background: var(--border-strong); }
.console-head h3 {
  flex: 1; margin: 0; font-size: 11.5px; font-weight: 800;
  letter-spacing: .18em; text-transform: uppercase; color: var(--muted);
}
.chip {
  padding: 3px 10px; border-radius: 999px; border: 1px solid var(--border);
  font-size: 10.5px; font-weight: 800; letter-spacing: .08em;
  text-transform: uppercase; color: var(--muted);
}
.chip.running { color: var(--success); border-color: var(--border-strong); text-shadow: var(--text-glow); }
.chip.running { border-color: color-mix(in srgb, var(--success) 42%, transparent); }
.chip.exited { color: var(--danger); border-color: var(--border-strong); }
.chip.exited { border-color: color-mix(in srgb, var(--danger) 45%, transparent); }
.console-body {
  margin: 0; padding: 14px 16px 18px; min-height: 230px; max-height: 320px; overflow: auto;
  font-family: var(--font-mono); font-size: 12.5px; line-height: 1.75;
  color: var(--muted); white-space: pre-wrap; word-break: break-word;
}
.console-body .ln { display: block; }
.console-body .ln.inv { color: var(--success); text-shadow: var(--text-glow); }
.console-body .ln.err { color: var(--danger); }
.console-body .ln.warn { color: var(--warning); }
.console-body .empty { font-style: italic; opacity: .65; }

/* ---------- Footer ---------- */
.site-footer {
  position: relative; z-index: 5; max-width: 1180px; margin: 0 auto;
  padding: 6px 24px 44px; display: flex; justify-content: space-between;
  flex-wrap: wrap; gap: 6px 20px; color: var(--muted); font-size: 12.5px;
}
.site-footer p { margin: 0; }

/* ---------- Invitation modal ---------- */
.modal { position: fixed; inset: 0; z-index: 100; display: grid; place-items: center; padding: 22px; }
.modal-backdrop {
  position: absolute; inset: 0; background: rgba(3, 4, 8, .62);
  backdrop-filter: blur(9px); -webkit-backdrop-filter: blur(9px);
  animation: fade .2s ease;
}
.modal-card {
  position: relative; width: min(620px, 100%); padding: 26px 28px;
  border-radius: 22px; border: 1px solid var(--border-strong);
  background: var(--panel-solid); box-shadow: 0 30px 90px rgba(0, 0, 0, .6);
  animation: pop .22s cubic-bezier(.2, .9, .3, 1.2);
}
.modal-card h2 { margin: 6px 0 6px; font-size: 22px; letter-spacing: -.02em; }
.modal-x {
  position: absolute; top: 14px; right: 14px; width: 34px; height: 34px;
  display: grid; place-items: center; border-radius: 10px;
  border: 1px solid transparent; background: transparent; color: var(--muted);
  cursor: pointer; transition: color .2s, border-color .2s;
}
.modal-x:hover { color: var(--text); border-color: var(--border-strong); }
.modal-x svg { width: 15px; height: 15px; }
.invite-code {
  margin: 18px 0 0; padding: 16px 18px; border-radius: 14px;
  border: 1px solid var(--border); background: var(--input);
  font-family: var(--font-mono); font-size: 13.5px; line-height: 1.8;
  word-break: break-all; color: var(--success); text-shadow: var(--text-glow);
  user-select: all; cursor: text; max-height: 190px; overflow: auto;
}
.modal-actions { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }
@keyframes fade { from { opacity: 0; } }
@keyframes pop { from { opacity: 0; transform: translateY(12px) scale(.97); } }

/* ---------- Toast ---------- */
.toast {
  position: fixed; top: 76px; right: 22px; z-index: 200;
  display: flex; align-items: center; gap: 10px;
  max-width: min(440px, calc(100vw - 44px)); padding: 12px 16px;
  border-radius: 14px; border: 1px solid var(--border-strong);
  background: var(--panel-solid); color: var(--text);
  font-size: 13.5px; font-weight: 600; box-shadow: var(--shadow);
  pointer-events: none; opacity: 1; transform: none;
  transition: opacity .28s ease, transform .28s ease;
  animation: toast-in .28s cubic-bezier(.2, .9, .3, 1.1);
}
.toast .ticon { width: 16px; height: 16px; color: var(--success); flex: 0 0 auto; }
.toast.hide { opacity: 0; transform: translateY(-8px); }
@keyframes toast-in { from { opacity: 0; transform: translateY(-10px); } }

/* ---------- Responsive ---------- */
@media (max-width: 980px) {
  .launchers { grid-template-columns: 1fr; }
  .consoles { grid-template-columns: 1fr; }
}
@media (max-width: 620px) {
  .stats { grid-template-columns: 1fr; }
  .shell { padding: 26px 16px 18px; }
  .topbar-inner { padding: 10px 16px; }
  .top-status { margin-left: 0; }
  .site-footer { padding: 6px 16px 36px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: .01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: .01ms !important;
  }
  #fx { display: none; }
}
</style>
</head>
<body data-notice="__NOTICE__">
<canvas id="fx" aria-hidden="true"></canvas>
<div class="bg-ribbons" aria-hidden="true"><i></i><i></i><i></i></div>
<div class="bg-grid" aria-hidden="true"></div>
<div class="vignette" aria-hidden="true"></div>
<div class="scanlines" aria-hidden="true"></div>

<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="/" aria-label="SecureChat home">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2.6 20 5.6v5.8c0 4.9-3.4 8.7-8 10-4.6-1.3-8-5.1-8-10V5.6l8-3z"/><path d="M12 10.2v3"/><circle cx="12" cy="14.6" r="1.4" fill="currentColor" stroke="none"/></svg>
      <span class="brand-name">SecureChat</span>
    </a>
    <nav class="top-status" aria-label="Process status">
      <span class="pill" id="pill-server" title="Stopped"><i class="dot"></i><span>Relay</span></span>
      <span class="pill" id="pill-client" title="Stopped"><i class="dot"></i><span>Client</span></span>
    </nav>
    <div class="theme-widget">
      <button id="theme-btn" type="button" aria-haspopup="true" aria-expanded="false">
        <span class="swatch" aria-hidden="true"></span>
        <span id="theme-name">Dark</span>
        <svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9.5 6 6 6-6"/></svg>
      </button>
      <div id="theme-menu" class="theme-menu" role="menu" aria-label="Choose theme" hidden></div>
    </div>
  </div>
</header>
<main class="shell">
  <section class="hero">
    <div class="hero-chips">
      <span class="chip-tag alt">End-to-end encrypted</span>
      <span class="chip-tag">AES-256-GCM</span>
      <span class="chip-tag">Zero storage</span>
      <span class="chip-tag">No IP leaks</span>
    </div>
    <h1 class="title">Relay <span class="grad">Control Center</span></h1>
    <p class="lede">Spin up an encrypted relay, share one invitation code, and talk without leaving a trace — nothing ever touches disk.</p>
  </section>

  <section class="stats" aria-label="Live status">
    <article class="stat card">
      <span class="stat-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>
      </span>
      <div>
        <h4>Relay</h4>
        <p class="v" id="stat-server-v">Stopped</p>
        <p class="s" id="stat-server-s">Not running</p>
      </div>
    </article>
    <article class="stat card">
      <span class="stat-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8.2" r="3.4"/><path d="M5.2 19.4c1.1-3 3.7-4.8 6.8-4.8s5.7 1.8 6.8 4.8"/></svg>
      </span>
      <div>
        <h4>Client</h4>
        <p class="v" id="stat-client-v">Stopped</p>
        <p class="s" id="stat-client-s">Not running</p>
      </div>
    </article>
  </section>

  <section class="launchers">
    <form class="card launcher" method="post" action="/server" autocomplete="off">
      <div class="launcher-head">
        <div>
          <p class="eyebrow">Relay</p>
          <h2>Start a server</h2>
          <p class="desc">Create a room and generate the invitation.</p>
        </div>
        <span class="launcher-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>
        </span>
      </div>
      <div class="field">
        <label for="srv-host">Bind host</label>
        <input id="srv-host" name="host" value="127.0.0.1" spellcheck="false">
        <p class="hint">Keep the dashboard-bound relay on <code>127.0.0.1</code> unless it is firewalled.</p>
      </div>
      <div class="field">
        <label for="srv-adv">Advertised host</label>
        <input id="srv-adv" name="advertise_host" placeholder="relay.example.com" spellcheck="false">
        <p class="hint">Optional — the host written into invitations. Leave blank for LAN use.</p>
      </div>
      <div class="field">
        <label for="srv-port">Port</label>
        <input id="srv-port" name="port" value="8400" inputmode="numeric" pattern="[0-9]{1,5}">
      </div>
      <button class="btn primary block" type="submit">
        Start relay server
        <svg class="arr" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.5 12h15m-6.5-6.5L19.5 12 13 18.5"/></svg>
      </button>
    </form>

    <form class="card launcher" method="post" action="/client" autocomplete="off">
      <div class="launcher-head">
        <div>
          <p class="eyebrow">Client</p>
          <h2>Join a room</h2>
          <p class="desc">Launch the secure client with an invitation.</p>
        </div>
        <span class="launcher-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8.2" r="3.4"/><path d="M5.2 19.4c1.1-3 3.7-4.8 6.8-4.8s5.7 1.8 6.8 4.8"/></svg>
        </span>
      </div>
      <div class="field">
        <label for="cli-room">Invitation</label>
        <input id="cli-room" name="room" required placeholder="SC1.…" spellcheck="false" class="mono">
      </div>
      <div class="field">
        <label for="cli-name">Username</label>
        <input id="cli-name" name="name" required minlength="2" maxlength="20" placeholder="Your display name">
        <p class="hint">Asked every start, never stored. 2–20 characters.</p>
      </div>
      <button class="btn primary block" type="submit">
        Launch client
        <svg class="arr" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.5 12h15m-6.5-6.5L19.5 12 13 18.5"/></svg>
      </button>
    </form>
  </section>

  <section class="card controls" aria-label="Process controls">
    <div>
      <p class="eyebrow">Workspace</p>
      <h2>Process controls</h2>
      <p class="desc" id="controls-desc">The invitation appears here once the relay prints it.</p>
    </div>
    <div class="controls-row">
      <form class="stop-form" method="post" action="/stop">
        <button class="btn danger-ghost" id="stop-server" type="submit" name="kind" value="server">
          <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="7" y="7" width="10" height="10" rx="2"/></svg>
          Stop relay
        </button>
        <button class="btn danger-ghost" id="stop-client" type="submit" name="kind" value="client">
          <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="7" y="7" width="10" height="10" rx="2"/></svg>
          Stop client
        </button>
      </form>
      <button id="show-invite" class="btn ghost" type="button" hidden>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2.5 12S6 5.8 12 5.8 21.5 12 21.5 12 18 18.2 12 18.2 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.6"/></svg>
        Show invitation
      </button>
    </div>
  </section>

  <section class="consoles">
    <div class="card console">
      <header class="console-head">
        <span class="tl" aria-hidden="true"><i></i><i></i><i></i></span>
        <h3>Relay console</h3>
        <span class="chip" id="chip-server">Stopped</span>
      </header>
      <div class="console-body" id="log-server" tabindex="0"></div>
    </div>
    <div class="card console">
      <header class="console-head">
        <span class="tl" aria-hidden="true"><i></i><i></i><i></i></span>
        <h3>Client console</h3>
        <span class="chip" id="chip-client">Stopped</span>
      </header>
      <div class="console-body" id="log-client" tabindex="0"></div>
    </div>
  </section>
</main>

<footer class="site-footer">
  <p>SecureChat — end-to-end encrypted relay chat. Nothing is ever written to disk.</p>
  <p>Local dashboard · <code>127.0.0.1</code> only</p>
</footer>

<div class="modal" id="invite-modal" hidden>
  <div class="modal-backdrop" data-close></div>
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="invite-title">
    <button class="modal-x" type="button" data-close aria-label="Close">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>
    </button>
    <p class="eyebrow">Room ready</p>
    <h2 id="invite-title">Share the invitation</h2>
    <p class="desc">Anyone holding this code can join the room — treat the code as the room itself.</p>
    <div class="invite-code" id="invite-code"></div>
    <div class="modal-actions">
      <button class="btn primary" id="copy-invite" type="button">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2.2"/><path d="M5.5 15V6.8A1.8 1.8 0 0 1 7.3 5h8.2"/></svg>
        Copy invitation
      </button>
      <button class="btn ghost" id="select-invite" type="button">Select all</button>
    </div>
  </div>
</div>

<div id="toast" class="toast" hidden>
  <svg class="ticon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 13 4.2 4.2L19 7.5"/></svg>
  <span></span>
</div>
<script>
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  /* ================= Theme switcher ================= */
  var THEMES = [
    ["dark", "Dark"], ["netherworld", "Netherworld"], ["hacker", "Hacker"],
    ["terminal", "Terminal"], ["interstellar", "Interstellar"], ["ocean", "Ocean"],
    ["solarized", "Solarized"], ["aurora", "Aurora"]
  ];
  var FX_MODE = { hacker: "matrix", interstellar: "stars", netherworld: "embers" };
  var menu = $("theme-menu"), themeBtn = $("theme-btn");

  function setTheme(id, persist) {
    document.documentElement.dataset.theme = id;
    var name = id;
    for (var i = 0; i < THEMES.length; i++) if (THEMES[i][0] === id) name = THEMES[i][1];
    $("theme-name").textContent = name;
    var opts = menu.querySelectorAll(".theme-opt");
    for (var j = 0; j < opts.length; j++) {
      opts[j].setAttribute("aria-checked", String(opts[j].dataset.themeOpt === id));
    }
    if (persist !== false) {
      try { localStorage.setItem("securechat-theme", id); } catch (e) {}
    }
    FX.setMode(FX_MODE[id] || null);
  }

  function openMenu() { menu.hidden = false; themeBtn.setAttribute("aria-expanded", "true"); }
  function closeMenu(refocus) {
    menu.hidden = true; themeBtn.setAttribute("aria-expanded", "false");
    if (refocus) themeBtn.focus();
  }
  themeBtn.addEventListener("click", function () { menu.hidden ? openMenu() : closeMenu(false); });
  document.addEventListener("click", function (e) {
    if (!menu.hidden && !e.target.closest(".theme-widget")) closeMenu(false);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !menu.hidden) closeMenu(true);
  });
  menu.addEventListener("keydown", function (e) {
    var opts = Array.prototype.slice.call(menu.querySelectorAll(".theme-opt"));
    var i = opts.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); opts[(i + 1) % opts.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); opts[(i - 1 + opts.length) % opts.length].focus(); }
    else if (e.key === "Home") { e.preventDefault(); opts[0].focus(); }
    else if (e.key === "End") { e.preventDefault(); opts[opts.length - 1].focus(); }
  });
  THEMES.forEach(function (t) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "theme-opt";
    b.dataset.themeOpt = t[0];
    b.setAttribute("role", "menuitemradio");
    b.setAttribute("aria-checked", "false");
    var sw = document.createElement("span");
    sw.className = "swatch sw-" + t[0];
    sw.setAttribute("aria-hidden", "true");
    b.appendChild(sw);
    b.appendChild(document.createTextNode(t[1]));
    b.addEventListener("click", function () { setTheme(t[0]); closeMenu(false); });
    menu.appendChild(b);
  });

  /* ================= Ambient background FX ================= */
  var reduced = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var FX = (function () {
    if (reduced) return { setMode: function () {} };
    var cv = $("fx");
    if (!cv || !cv.getContext) return { setMode: function () {} };
    var ctx = cv.getContext("2d");
    var GLYPHS = "01<>{}[]$#%&*+=/|ABCDEF";
    var TAU = Math.PI * 2;
    var mode = null, W = 0, H = 0, raf = 0, last = 0, rz = 0;
    var items = [], meteors = [], spawn = 3000;
    var mono = getComputedStyle(document.documentElement)
      .getPropertyValue("--font-mono") || "Consolas, monospace";

    function resize() {
      var dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = window.innerWidth; H = window.innerHeight;
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      seed();
    }
    function seed() {
      items = []; meteors = [];
      if (mode === "matrix") {
        var n = Math.ceil(W / 15);
        for (var i = 0; i < n; i++) items.push({
          x: i * 15 + 4, y: Math.random() * -H,
          sp: 60 + Math.random() * 140
        });
      } else if (mode === "stars") {
        for (var s = 0; s < 170; s++) items.push({
          x: Math.random() * W, y: Math.random() * H,
          r: 0.4 + Math.random() * 1.2, tw: 1 + Math.random() * 2.2,
          ph: Math.random() * TAU, dr: 2 + Math.random() * 6,
          c: Math.random() < 0.14 ? "#9ff3ff" : Math.random() < 0.2 ? "#c3b5ff" : "#e8ecff"
        });
      } else if (mode === "embers") {
        var colors = ["#ff6a3d", "#ffb454", "#ff2e63", "#ffd166"];
        for (var e = 0; e < 70; e++) items.push({
          x: Math.random() * W, y: H + Math.random() * H,
          vy: 18 + Math.random() * 40, wob: 6 + Math.random() * 18,
          ph: Math.random() * TAU, r: 0.8 + Math.random() * 1.8,
          c: colors[e % 4]
        });
      }
    }
    function fade(alpha) {
      ctx.globalCompositeOperation = "destination-out";
      ctx.fillStyle = "rgba(0,0,0," + alpha + ")";
      ctx.fillRect(0, 0, W, H);
      ctx.globalCompositeOperation = "source-over";
    }
    function drawMatrix(dt) {
      fade(0.14);
      ctx.font = "13px " + mono;
      ctx.textBaseline = "top";
      for (var i = 0; i < items.length; i++) {
        var c = items[i];
        c.y += (c.sp * dt) / 1000;
        if (c.y > H + 40) {
          c.y = -40 - Math.random() * 200;
          c.x = Math.floor(Math.random() * (W / 15)) * 15 + 4;
        }
        ctx.fillStyle = "rgba(0,255,102,0.5)";
        ctx.fillText(GLYPHS.charAt((Math.random() * GLYPHS.length) | 0), c.x, c.y - 16);
        ctx.fillStyle = "rgba(196,255,216,0.9)";
        ctx.fillText(GLYPHS.charAt((Math.random() * GLYPHS.length) | 0), c.x, c.y);
      }
    }
    function drawStars(dt, t) {
      ctx.clearRect(0, 0, W, H);
      var k = dt / 1000;
      for (var i = 0; i < items.length; i++) {
        var s = items[i];
        s.y += s.dr * k * 0.35;
        if (s.y > H + 4) s.y = -4;
        var a = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin((t / 1000) * s.tw + s.ph));
        ctx.globalAlpha = a * 0.85;
        ctx.fillStyle = s.c;
        ctx.beginPath(); ctx.arc(s.x, s.y, s.r, 0, TAU); ctx.fill();
      }
      ctx.globalAlpha = 1;
      spawn -= dt;
      if (spawn <= 0 && meteors.length < 2) {
        meteors.push({
          x: W * (0.15 + Math.random() * 0.7), y: H * (0.05 + Math.random() * 0.35),
          vx: 420 + Math.random() * 260, vy: 130 + Math.random() * 110, life: 1
        });
        spawn = 5000 + Math.random() * 7000;
      }
      for (var m = meteors.length - 1; m >= 0; m--) {
        var mt = meteors[m];
        mt.x += mt.vx * k; mt.y += mt.vy * k; mt.life -= k * 0.9;
        if (mt.life <= 0 || mt.x > W + 60 || mt.y > H + 60) { meteors.splice(m, 1); continue; }
        var tail = 0.16;
        var grad = ctx.createLinearGradient(mt.x, mt.y, mt.x - mt.vx * tail, mt.y - mt.vy * tail);
        grad.addColorStop(0, "rgba(233,236,255," + (0.85 * mt.life).toFixed(3) + ")");
        grad.addColorStop(1, "rgba(233,236,255,0)");
        ctx.strokeStyle = grad; ctx.lineWidth = 1.6; ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(mt.x, mt.y);
        ctx.lineTo(mt.x - mt.vx * tail, mt.y - mt.vy * tail);
        ctx.stroke();
      }
    }
    function drawEmbers(dt, t) {
      ctx.clearRect(0, 0, W, H);
      var k = dt / 1000;
      for (var i = 0; i < items.length; i++) {
        var e = items[i];
        e.y -= (e.vy * dt) / 1000;
        if (e.y < -12) { e.y = H + 12 + Math.random() * 40; e.x = Math.random() * W; }
        var x = e.x + Math.sin((t / 1000) * 1.3 + e.ph) * e.wob;
        var a = Math.max(0, Math.min(1, (e.y / H) * 1.5)) *
                (0.55 + 0.45 * Math.sin(t / 300 + e.ph));
        ctx.globalAlpha = a * 0.8;
        ctx.shadowBlur = 10; ctx.shadowColor = e.c;
        ctx.fillStyle = e.c;
        ctx.beginPath(); ctx.arc(x, e.y, e.r, 0, TAU); ctx.fill();
      }
      ctx.shadowBlur = 0; ctx.globalAlpha = 1;
    }
    function frame(t) {
      raf = requestAnimationFrame(frame);
      var dt = Math.min(64, t - last || 16);
      last = t;
      if (mode === "matrix") drawMatrix(dt);
      else if (mode === "stars") drawStars(dt, t);
      else if (mode === "embers") drawEmbers(dt, t);
    }
    function setMode(m) {
      if (mode === m) return;
      mode = m;
      if (!m) {
        if (raf) cancelAnimationFrame(raf);
        raf = 0;
        ctx.clearRect(0, 0, W, H);
        return;
      }
      seed();
      if (!raf) { last = performance.now(); raf = requestAnimationFrame(frame); }
    }
    window.addEventListener("resize", function () {
      clearTimeout(rz); rz = setTimeout(resize, 150);
    });
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) { if (raf) cancelAnimationFrame(raf); raf = 0; }
      else if (mode) { last = performance.now(); raf = requestAnimationFrame(frame); }
    });
    resize();
    return { setMode: setMode };
  })();

  /* ================= Live status ================= */
  var INV_RE = /share this room invitation:\s*(SC1\.\S+)/i;
  var invitation = "";
  try { invitation = localStorage.getItem("securechat-invitation") || ""; } catch (e) {}
  var refs = {
    server: {
      pill: $("pill-server"), chip: $("chip-server"),
      v: $("stat-server-v"), s: $("stat-server-s"), log: $("log-server")
    },
    client: {
      pill: $("pill-client"), chip: $("chip-client"),
      v: $("stat-client-v"), s: $("stat-client-s"), log: $("log-client")
    }
  };

  function stateOf(st) {
    if (!st || st === "stopped") return { cls: "stopped", label: "Stopped" };
    if (st === "running") return { cls: "running", label: "Running" };
    return { cls: "exited", label: st.charAt(0).toUpperCase() + st.slice(1) };
  }
  function parseArgs(list) {
    var o = {};
    for (var i = 1; i < list.length; i++) {
      if (list[i].indexOf("--") === 0) {
        o[list[i].slice(2)] =
          (i + 1 < list.length && list[i + 1].indexOf("--") !== 0) ? list[++i] : "";
      }
    }
    return o;
  }
  function maskCode(s) {
    return s && s.length > 20 ? s.slice(0, 10) + "…" + s.slice(-6) : s;
  }
  function subText(kind, args) {
    if (!args.length) return "Not running";
    var o = parseArgs(args);
    if (kind === "server") {
      var t = (o.host || "?") + ":" + (o.port || "?");
      if (o["advertise-host"]) t += "  ·  advertises " + o["advertise-host"];
      return t;
    }
    var c = o.name || "";
    if (o.room) c += (c ? "  ·  " : "") + maskCode(o.room);
    return c || "Running";
  }
  function renderLog(kind, lines) {
    var el = refs[kind].log;
    var near = el.scrollHeight - el.scrollTop - el.clientHeight < 36;
    if (!lines.length) {
      var empty = document.createElement("span");
      empty.className = "empty";
      empty.textContent = "No output yet — the process hasn't printed anything.";
      el.replaceChildren(empty);
      return;
    }
    var frag = document.createDocumentFragment();
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var line = document.createElement("span");
      line.className = "ln";
      var low = raw.toLowerCase();
      if (/share this .*invitation/i.test(raw)) line.classList.add("inv");
      else if (/error|traceback|failed|refused|denied|invalid|exception/.test(low)) line.classList.add("err");
      else if (/warn|note:/.test(low)) line.classList.add("warn");
      line.textContent = raw;
      frag.appendChild(line);
    }
    el.replaceChildren(frag);
    if (near) el.scrollTop = el.scrollHeight;
  }
  function apply(kind, st, args, lines) {
    var r = refs[kind];
    var info = stateOf(st);
    r.pill.classList.toggle("running", info.cls === "running");
    r.pill.classList.toggle("exited", info.cls === "exited");
    r.pill.title = info.label;
    r.chip.textContent = info.label;
    r.chip.className = "chip " + info.cls;
    r.v.textContent = info.label;
    r.v.className = "v " + (info.cls === "running" ? "ok" : info.cls === "exited" ? "bad" : "");
    r.s.textContent = subText(kind, args);
    r.s.title = r.s.textContent;
    renderLog(kind, lines);
  }
  function updateControls(states) {
    var serverRunning = states.server === "running";
    var clientRunning = states.client === "running";
    var any = serverRunning || clientRunning;
    $("stop-server").hidden = !serverRunning;
    $("stop-client").hidden = !clientRunning;
    $("show-invite").hidden = !(any && invitation);
    var row = document.querySelector(".controls-row");
    if (row) row.hidden = !any;
    var desc = $("controls-desc");
    if (desc) {
      desc.textContent = any
        ? "The invitation appears here once the relay prints it."
        : "Nothing is running — start a relay or join a room to see controls here.";
    }
  }
  async function poll() {
    var data;
    try {
      data = await (await fetch("/api/status", { cache: "no-store" })).json();
    } catch (e) { return; }
    for (var i = 0; i < ["server", "client"].length; i++) {
      var kind = ["server", "client"][i];
      apply(kind, data.states[kind], (data.args || {})[kind] || [], data.logs[kind] || []);
    }
    var m = (data.logs.server || []).join("\n").match(INV_RE);
    if (m && m[1] !== invitation) {
      invitation = m[1];
      try { localStorage.setItem("securechat-invitation", m[1]); } catch (e) {}
      openInvite();
    }
    updateControls(data.states || {});
  }

  /* ================= Invitation modal ================= */
  var modal = $("invite-modal");
  function openInvite() {
    if (!invitation) return;
    $("invite-code").textContent = invitation;
    modal.hidden = false;
    $("copy-invite").focus();
  }
  function closeInvite() { modal.hidden = true; }
  modal.addEventListener("click", function (e) {
    if (e.target.closest("[data-close]")) closeInvite();
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !modal.hidden) closeInvite();
  });
  $("show-invite").addEventListener("click", openInvite);
  $("select-invite").addEventListener("click", function () {
    var r = document.createRange();
    r.selectNodeContents($("invite-code"));
    var sel = window.getSelection();
    sel.removeAllRanges(); sel.addRange(r);
  });

  /* ================= Copy & toasts ================= */
  async function copyText(t) {
    try { await navigator.clipboard.writeText(t); return true; }
    catch (e) {
      var ta = document.createElement("textarea");
      ta.value = t;
      ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (err) {}
      ta.remove(); return ok;
    }
  }
  var toastEl = $("toast"), toastT = 0;
  function toast(msg) {
    toastEl.querySelector("span").textContent = msg;
    toastEl.hidden = false;
    toastEl.classList.remove("hide");
    void toastEl.offsetWidth;
    clearTimeout(toastT);
    toastT = setTimeout(function () { toastEl.classList.add("hide"); }, 3800);
  }
  $("copy-invite").addEventListener("click", async function () {
    var ok = await copyText(invitation);
    toast(ok ? "Invitation copied to clipboard." : "Copy failed — select it manually.");
  });

  /* ================= Init ================= */
  setTheme(document.documentElement.dataset.theme || "dark", false);
  var notice = document.body.dataset.notice;
  if (notice) {
    toast(notice);
    history.replaceState(null, "", location.pathname);
  }
  poll();
  setInterval(poll, 1400);
})();
</script>
</body>
</html>
"""

def _read_output(kind: str, process: subprocess.Popen) -> None:
    if process.stdout is None:
        return
    for line in process.stdout:
        with _lock:
            _logs[kind].append(line.rstrip())
            _logs[kind] = _logs[kind][-160:]


def _stop(kind: str) -> None:
    with _lock:
        process = _processes.pop(kind, None)
    if process is not None and process.poll() is None:
        process.terminate()


# The client runs a full-screen prompt_toolkit TUI, which on Windows needs a
# real console attached to its std handles — piped stdio raises
# NoConsoleScreenBufferError. So on Windows the client is spawned into its own
# console window (not piped into the page). The relay has no TUI and keeps
# being piped so its invitation stays visible on the dashboard.
_NEW_CONSOLE = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)


def _start(kind: str, args: list[str]) -> str:
    _stop(kind)
    windowed = kind == "client" and os.name == "nt"
    kwargs: dict = {"cwd": ROOT}
    if windowed:
        kwargs["creationflags"] = _NEW_CONSOLE
    else:
        kwargs.update(
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    try:
        process = subprocess.Popen([sys.executable, *args], **kwargs)
    except OSError as exc:
        return f"Could not start {kind}: {exc}"
    started = f"started: {' '.join([sys.executable, *args])}"
    with _lock:
        _processes[kind] = process
        _args[kind] = [sys.executable, *args]
        if windowed:
            _logs[kind] = [started,
                           "the terminal chat window opened separately — "
                           "chat with it there (this page cannot mirror a full-screen TUI)."]
        else:
            _logs[kind] = [started]
    if not windowed:
        threading.Thread(target=_read_output, args=(kind, process), daemon=True).start()
    return f"{kind.capitalize()} started."


def _field(form: dict[str, list[str]], name: str, default: str = "") -> str:
    return (form.get(name, [default])[0] or default).strip()


def _page(notice: str = "") -> bytes:
    body = _PAGE.replace("__NOTICE__", html.escape(notice, quote=True))
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
                "args": {kind: list(args) for kind, args in _args.items()},
                "logs": {kind: list(lines) for kind, lines in _logs.items()},
            }

    def _reply_json(self, value: dict) -> None:
        body = json.dumps(value).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reply(self, status: int, body: bytes, location: str | None = None) -> None:
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        else:
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
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

