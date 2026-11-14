"""securechat.ui — minimal prompt_toolkit TUI.

Layout:
  +------------------------------------------------------+
  | chat pane (follows the tail; wheel/PageUp scrollback)|
  |------------------------------------------------------|
  | > input line                                         |
  |------------------------------------------------------|
  | ROOM **** | * N online | E2E AES-256 | TCP | state   |
  +------------------------------------------------------+

Clicking "* N online" in the status bar (or F2, or /who) toggles the
Online-Users overlay. All state is in RAM only.
"""

from __future__ import annotations

import asyncio
import time

from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.filters import Condition
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import (Float, FloatContainer, HSplit, Layout,
                                   VSplit, Window)
from prompt_toolkit.layout.containers import ConditionalContainer
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.lexers import Lexer
from prompt_toolkit.mouse_events import MouseEventType
from prompt_toolkit.styles import Style

MAX_CHAT_LINES = 2000
COMMANDS = (
    "/help", "/code", "/who", "/nick", "/burn", "/quit",
)

STYLE = Style.from_dict({
    "status": "bg:#1b2430 #93a4bd",
    "status.code": "bg:#1b2430 #e6c07b",
    "status.click": "bg:#1b2430 #61dafb bold underline",
    "status.badge": "bg:#1b2430 #98c379 bold",
    "status.state": "bg:#1b2430 #98c379",
    "status.warn": "bg:#1b2430 #e06c75 bold",
    "time": "#5c6370",
    "chat.name": "#61dafb bold",
    "chat.me": "#98c379 bold",
    "chat.text": "#d7dde8",
    "system": "#8fa3bf italic",
    "warn": "#e06c75 bold",
    "prompt": "#61dafb bold",
    "users.title": "#e6c07b bold",
    "users.item": "#d7dde8",
    "users.you": "#98c379 bold",
})


class _ChatLexer(Lexer):
    """Styles transcript lines from the parallel fragment table.

    The chat Buffer holds plain text; `ChatUI._frags` holds the styled
    fragments for each line, in the same order. lex(i) returns line i's
    fragments (text is identical by construction).
    """

    def __init__(self, ui: "ChatUI"):
        self._ui = ui

    def lex_document(self, document):
        ui = self._ui

        def lex(line_no: int):
            if 0 <= line_no < len(ui._frags):
                return ui._frags[line_no]
            return [("", document.lines[line_no])]

        return lex


class ChatUI:
    def __init__(self, session, *, full_screen: bool = True):
        self.session = session
        self.show_users = False
        self.show_help = False
        self._frags: list[list[tuple[str, str]]] = []   # parallel to _out lines

        # Chat transcript buffer: cursor parked at the end -> window follows
        # the tail; moving the cursor up (wheel/PageUp) reads scrollback.
        self._out = Buffer(multiline=True)

        self._inp = Buffer(
            multiline=False,
            history=InMemoryHistory(),          # in-memory only, never on disk
            read_only=Condition(lambda: not session.connected),
            accept_handler=self._accept,
            completer=WordCompleter(COMMANDS, ignore_case=True),
            complete_while_typing=True,
        )
        self._build(full_screen)

    # ------------------------------------------------------------------ layout
    def _build(self, full_screen: bool) -> None:
        chat_window = Window(
            BufferControl(buffer=self._out, lexer=_ChatLexer(self), focusable=False),
            wrap_lines=True,
        )

        separator = Window(FormattedTextControl([("class:status", "-" * 300)]), height=1)

        input_row = VSplit([
            Window(FormattedTextControl([("class:prompt", " > ")]), dont_extend_width=True),
            Window(BufferControl(buffer=self._inp), wrap_lines=True),
        ])

        status = Window(FormattedTextControl(self._status_text, show_cursor=False), height=1)

        users_window = Window(FormattedTextControl(self._users_text, show_cursor=False))
        users_float = Float(
            content=ConditionalContainer(users_window, Condition(lambda: self.show_users)),
            top=1,
            right=1,
        )
        help_window = Window(
            FormattedTextControl(self._help_text, show_cursor=False),
            width=44,
            height=9,
        )
        help_float = Float(
            content=ConditionalContainer(help_window, Condition(lambda: self.show_help)),
            top=1,
            left=1,
        )

        root = FloatContainer(
            content=HSplit([chat_window, separator, input_row, status]),
            floats=[users_float, help_float],
        )
        self._app: Application = Application(
            layout=Layout(root, focused_element=input_row.children[1]),
            key_bindings=self._bindings(),
            style=STYLE,
            full_screen=full_screen,
            mouse_support=True,
        )

    # ------------------------------------------------------------------ keybinds
    def _bindings(self) -> KeyBindings:
        kb = KeyBindings()

        @kb.add("f2")
        def _toggle(_ev) -> None:
            self.toggle_users()

        @kb.add("f1")
        def _toggle_help(_ev) -> None:
            self.show_help = not self.show_help
            self._app.invalidate()

        @kb.add("escape", filter=Condition(lambda: self.show_users))
        def _close(_ev) -> None:
            self.show_users = False

        @kb.add("escape", filter=Condition(lambda: self.show_help))
        def _close_help(_ev) -> None:
            self.show_help = False

        @kb.add("pageup")
        def _up(_ev) -> None:
            self._out.cursor_up(10)
            self._app.invalidate()

        @kb.add("pagedown")
        def _down(_ev) -> None:
            self._out.cursor_down(10)
            self._app.invalidate()

        @kb.add("c-c")
        @kb.add("c-q")
        def _quit(_ev) -> None:
            self._app.exit()

        return kb

    # ------------------------------------------------------------------ renderers
    def _status_text(self):
        s = self.session
        n = len(s.members)
        state = "CONNECTED" if s.connected else "DISCONNECTED"
        state_cls = "class:status.state" if s.connected else "class:status.warn"
        return [
            ("class:status", "  ROOM "),
            ("class:status.code", "****-****-****-****"),
            ("class:status", "  |  "),
            ("class:status.click", f"* {n} online ", self._click_users),
            ("class:status", "|  E2E AES-256 | "),
            ("class:status.badge", s.conn_info.badge),
            ("class:status", " | "),
            (state_cls, state),
            ("class:status", "  [F1 help, F2 users, Tab complete]"),
        ]

    def _users_text(self):
        if not self.show_users:
            return []
        s = self.session
        close = self._click_close
        rows: list[tuple[str, str, object]] = [
            ("class:users.title", f"  Online - {len(s.members)}  ", close),
            ("class:users.title", "(F2/Esc/click closes)\n", close),
        ]
        for tag, label in s.roster.ordered_labels(s.members):
            style = "class:users.you" if tag == s.my_tag else "class:users.item"
            rows.append((style, f"  * {label}\n", close))
        return rows

    def _help_text(self):
        return [
            ("class:users.title", "  SecureChat shortcuts\n"),
            ("class:users.item", "  F1 / Esc   close this help\n"),
            ("class:users.item", "  F2          online users\n"),
            ("class:users.item", "  PageUp/Down scroll transcript\n"),
            ("class:users.item", "  Tab         complete a command\n"),
            ("class:users.item", "  Ctrl+C/Q    leave chat\n"),
            ("class:users.item", "  /help       show all commands\n"),
        ]

    # ------------------------------------------------------------------ mouse
    def _click_users(self, ev) -> None:
        if ev.event_type == MouseEventType.MOUSE_UP:
            self.toggle_users()

    def _click_close(self, ev) -> None:
        if ev.event_type == MouseEventType.MOUSE_UP:
            self.show_users = False

    def toggle_users(self) -> None:
        self.show_users = not self.show_users
        if self.show_users:
            self.show_help = False
        self._app.invalidate()

    # ------------------------------------------------------------------ output
    def _add(self, frags: list[tuple[str, str]]) -> None:
        """Append one transcript line; keep cursor position if reading back."""
        buf = self._out
        line = "".join(t for _s, t in frags)
        offset = buf.cursor_position
        was_at_end = offset >= len(buf.text)
        buf.text = buf.text + line + "\n"
        self._frags.append(frags)
        if len(self._frags) > MAX_CHAT_LINES:
            drop = len(self._frags) - MAX_CHAT_LINES
            del self._frags[:drop]
            buf.text = "".join("".join(t for _s, t in f) + "\n" for f in self._frags)
        if was_at_end:
            buf.cursor_position = len(buf.text)      # follow the tail
        else:
            buf.cursor_position = min(offset, len(buf.text))  # keep reading spot
        self._app.invalidate()

    def _chat_line(self, who: str, text: str, mine: bool) -> None:
        ts = time.strftime("%H:%M")
        text = text.replace("\r", " ").replace("\n", " ")
        self._add([
            ("class:time", f"{ts}  "),
            ("class:chat.me" if mine else "class:chat.name", f"{who}: "),
            ("class:chat.text", text),
        ])

    # ------------------------------------------------------------------ events
    async def _pump(self) -> None:
        s = self.session
        while True:
            ev = await s.events.get()
            if ev.kind == "chat":
                self._chat_line("you" if ev.mine else ev.name, ev.text, ev.mine)
            elif ev.kind == "system":
                self._add([("class:warn" if ev.warn else "class:system", ev.text)])
            elif ev.kind == "roster":
                pass  # status bar / user list re-render on next invalidate
            elif ev.kind == "ui":
                if ev.text == "users":
                    self.toggle_users()
                elif ev.text == "burn":
                    self._frags.clear()
                    self._out.text = ""
                    self._add([("class:system",
                                "*** screen burned - transcript cleared (RAM only) ***")])
            elif ev.kind == "disconnected":
                self._add([("class:warn", f"*** {ev.text} - /quit to exit ***")])
            self._app.invalidate()

    # ------------------------------------------------------------------ input
    def _accept(self, buffer: Buffer) -> None:
        text = buffer.text
        buffer.reset()
        asyncio.get_running_loop().create_task(self._submit(text))

    async def _submit(self, text: str) -> None:
        keep = await self.session.send_chat(text)
        if keep is False:
            self._app.exit()

    # ------------------------------------------------------------------ run
    async def run(self) -> None:
        pump_task = self._app.create_background_task(self._pump())
        try:
            await self._app.run_async()
        finally:
            pump_task.cancel()
