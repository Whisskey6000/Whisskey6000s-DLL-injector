"""
DLL Injector — Textual TUI Application
by whissky
"""

from __future__ import annotations

import os
import threading
from datetime import datetime

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    RichLog,
    Static,
)

from .injector_core import (
    InjectionResult,
    ProcessInfo,
    get_process_by_pid,
    inject_dll,
    list_processes,
    validate_dll,
)

# ── ASCII Art Banner ───────────────────────────────────────────────────

BANNER = r"""
 ██╗    ██╗██╗  ██╗██╗███████╗███████╗██╗  ██╗██╗   ██╗
 ██║    ██║██║  ██║██║██╔════╝██╔════╝██║ ██╔╝╚██╗ ██╔╝
 ██║ █╗ ██║███████║██║███████╗███████╗█████╔╝  ╚████╔╝
 ██║███╗██║██╔══██║██║╚════██║╚════██║██╔═██╗   ╚██╔╝
 ╚███╔███╔╝██║  ██║██║███████║███████║██║  ██╗   ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝
"""


class DLLInjectorApp(App):
    """DLL Injector — interactive TUI by whissky."""

    CSS_PATH = "styles.tcss"
    TITLE = "DLL Injector by whissky"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("i", "inject", "Inject", show=True),
    ]

    selected_process: ProcessInfo | None = None

    # ── Compose ────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Static(BANNER, id="banner")
        yield Static("[ DLL INJECTOR  ─  v1.0 ]", id="subtitle")
        yield Static("─" * 120, id="separator-top")

        with Horizontal(id="main-container"):
            # ── Left Panel: Process List ───────────────────────────────
            with Vertical(id="process-panel") as panel:
                panel.border_title = "⬡ PROCESSES"

                with Horizontal(id="search-row"):
                    yield Input(
                        placeholder="🔍 Filter processes...",
                        id="search-input",
                    )
                    yield Button("⟳ Refresh", id="refresh-btn")

                yield DataTable(id="process-table")

                with Horizontal(id="pid-row"):
                    yield Static("PID ▸", id="pid-label")
                    yield Input(
                        placeholder="Enter PID manually...",
                        id="pid-input",
                        type="integer",
                    )
                    yield Button("▸ Select", id="pid-select-btn")

            # ── Right Panel: Injection ─────────────────────────────────
            with Vertical(id="inject-panel") as panel:
                panel.border_title = "◈ INJECTION"

                with Vertical(id="selected-info"):
                    yield Static("▸ TARGET PROCESS", id="selected-title")
                    yield Static("  No process selected", id="selected-process-name")
                    yield Static("  PID: —", id="selected-pid")
                    yield Static("  MEM: —", id="selected-mem")

                with Vertical(id="dll-section"):
                    yield Static("▸ DLL FILE", id="dll-label")
                    with Horizontal(id="dll-row"):
                        yield Input(
                            placeholder="Path to DLL file...",
                            id="dll-input",
                        )
                        yield Button("📂 Browse", id="browse-btn")

                yield Button("💉  I N J E C T", id="inject-btn", classes="-disabled")

                with Vertical(id="log-section"):
                    yield Static("▸ OPERATION LOG", id="log-label")
                    yield RichLog(id="log-panel", highlight=True, markup=True)

        yield Footer()

    # ── Mount / Init ───────────────────────────────────────────────────

    def on_mount(self) -> None:
        table = self.query_one("#process-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("PID", "Process Name", "Memory (MB)")
        self._log_message("[cyan]DLL Injector[/cyan] initialized. Welcome, [bold magenta]whissky[/bold magenta]!")
        self._log_message("Select a process and DLL to begin.")
        self._refresh_processes()

    # ── Process Refresh ────────────────────────────────────────────────

    @work(thread=True)
    def _refresh_processes(self, filter_text: str = "") -> None:
        """Refresh the process list (runs in background thread)."""
        procs = list_processes(filter_text)
        self.app.call_from_thread(self._populate_table, procs)

    def _populate_table(self, procs: list[ProcessInfo]) -> None:
        table = self.query_one("#process-table", DataTable)
        table.clear()
        for p in procs:
            table.add_row(
                str(p.pid),
                p.name,
                str(p.memory_mb),
                key=str(p.pid),
            )

    # ── Event Handlers ─────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self._refresh_processes(event.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """User clicked a row in the process table."""
        row_data = self.query_one("#process-table", DataTable).get_row(event.row_key)
        pid = int(row_data[0])
        self._select_process_by_pid(pid)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh-btn":
            self.action_refresh()
        elif event.button.id == "pid-select-btn":
            self._on_pid_select()
        elif event.button.id == "browse-btn":
            self._browse_dll()
        elif event.button.id == "inject-btn":
            self.action_inject()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "pid-input":
            self._on_pid_select()

    # ── Actions ────────────────────────────────────────────────────────

    def action_refresh(self) -> None:
        search = self.query_one("#search-input", Input)
        self._refresh_processes(search.value)
        self._log_message("[cyan]↻[/cyan] Process list refreshed")

    def action_inject(self) -> None:
        if not self.selected_process:
            self._log_message("[red]✗[/red] No process selected!")
            return

        dll_path = self.query_one("#dll-input", Input).value.strip()
        if not dll_path:
            self._log_message("[red]✗[/red] No DLL path specified!")
            return

        self._perform_injection(self.selected_process.pid, dll_path)

    # ── Internal Methods ───────────────────────────────────────────────

    def _select_process_by_pid(self, pid: int) -> None:
        proc = get_process_by_pid(pid)
        if proc:
            self.selected_process = proc
            self.query_one("#selected-process-name", Static).update(
                f"  {proc.name}"
            )
            self.query_one("#selected-pid", Static).update(f"  PID: {proc.pid}")
            self.query_one("#selected-mem", Static).update(
                f"  MEM: {proc.memory_mb} MB"
            )
            self.query_one("#inject-btn", Button).remove_class("-disabled")
            self._log_message(
                f"[green]✓[/green] Selected: [bold]{proc.name}[/bold] (PID {proc.pid})"
            )
        else:
            self._log_message(f"[red]✗[/red] Process with PID {pid} not found")

    def _on_pid_select(self) -> None:
        pid_input = self.query_one("#pid-input", Input)
        try:
            pid = int(pid_input.value.strip())
        except (ValueError, AttributeError):
            self._log_message("[red]✗[/red] Invalid PID — enter a number")
            return
        self._select_process_by_pid(pid)

    def _browse_dll(self) -> None:
        """Open a native file dialog in a thread so UI doesn't freeze."""
        def _dialog():
            try:
                import tkinter as tk
                from tkinter import filedialog
                root = tk.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                path = filedialog.askopenfilename(
                    title="Select DLL",
                    filetypes=[("DLL files", "*.dll"), ("All files", "*.*")],
                )
                root.destroy()
                if path:
                    self.app.call_from_thread(self._set_dll_path, path)
            except Exception as e:
                self.app.call_from_thread(
                    self._log_message,
                    f"[red]✗[/red] File dialog error: {e}",
                )

        threading.Thread(target=_dialog, daemon=True).start()

    def _set_dll_path(self, path: str) -> None:
        self.query_one("#dll-input", Input).value = path
        valid, msg = validate_dll(path)
        if valid:
            self._log_message(f"[green]✓[/green] DLL loaded: [bold]{os.path.basename(path)}[/bold]")
        else:
            self._log_message(f"[yellow]⚠[/yellow] DLL warning: {msg}")

    @work(thread=True)
    def _perform_injection(self, pid: int, dll_path: str) -> None:
        self.app.call_from_thread(
            self._log_message,
            f"[cyan]⏳[/cyan] Injecting into PID {pid}...",
        )
        result: InjectionResult = inject_dll(pid, dll_path)
        if result.success:
            self.app.call_from_thread(
                self._log_message,
                f"[green]✓ SUCCESS[/green] — {result.message} (thread: {result.thread_id})",
            )
        else:
            err = f" (code: {result.error_code})" if result.error_code else ""
            self.app.call_from_thread(
                self._log_message,
                f"[red]✗ FAILED[/red] — {result.message}{err}",
            )

    def _log_message(self, msg: str) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        log = self.query_one("#log-panel", RichLog)
        log.write(f"[dim]{now}[/dim] {msg}")
