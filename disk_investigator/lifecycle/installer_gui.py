"""
installer_gui.py - Native Windows 11 Tkinter + ttk Progress UI for Disk Investigator Setup.

Provides a non-blocking, DPI-aware installation window that executes the
transactional installer engine in a background worker thread, streams step and
log events via queue.Queue, locks WM_DELETE_WINDOW during critical mutations,
and presents a clear summary (success or safe rollback status) with log copy.
"""

from __future__ import annotations

import ctypes
import queue
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import tkinter as tk
from tkinter import ttk

from .common import get_resource_path


def enable_high_dpi_awareness() -> None:
    """Enables Per-Monitor/System DPI awareness on Windows before creating Tk root."""
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class InstallerWindow:
    """Tkinter + ttk progress window driving the Disk Investigator installer."""

    POLL_INTERVAL_MS = 40

    def __init__(
        self,
        root: tk.Tk,
        version: str,
        app_display_name: str,
        install_fn: Callable[..., bool],
        repair: bool = False,
        update_result: Optional[Path] = None,
        update_id: Optional[str] = None,
    ) -> None:
        self.root = root
        self.version = version
        self.app_display_name = app_display_name
        self.install_fn = install_fn
        self.repair = repair
        self.update_result = update_result
        self.update_id = update_id

        self.event_queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        self.is_running: bool = True
        self.transaction_locked: bool = True
        self.final_success: bool = False
        self.result_info: Dict[str, Any] = {}
        self.log_lines: List[str] = []
        self._copy_reset_after_id: Optional[str] = None
        self._window_icon_img: Optional[tk.PhotoImage] = None
        self._header_logo_img: Optional[tk.PhotoImage] = None

        self._configure_window()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close_requested)

    def _configure_window(self) -> None:
        action_label = "Sửa chữa / Cài lại" if self.repair else "Cài đặt"
        self.root.title(f"{action_label} {self.app_display_name} v{self.version}")
        width, height = 680, 520
        self.root.minsize(600, 460)
        self.root.configure(bg="#F3F3F3")

        try:
            ico_path = get_resource_path("app_icon.ico")
            if ico_path.exists():
                self.root.iconbitmap(default=str(ico_path))
        except Exception:
            pass

        try:
            app_png = get_resource_path("app_icon.png")
            if app_png.exists():
                self._window_icon_img = tk.PhotoImage(master=self.root, file=str(app_png))
                self.root.iconphoto(True, self._window_icon_img)
        except Exception:
            pass

        try:
            self.root.update_idletasks()
            screen_w = self.root.winfo_screenwidth()
            screen_h = self.root.winfo_screenheight()
            pos_x = max(0, (screen_w - width) // 2)
            pos_y = max(0, (screen_h - height) // 2)
            self.root.geometry(f"{width}x{height}+{pos_x}+{pos_y}")
        except Exception:
            self.root.geometry(f"{width}x{height}")

        style = ttk.Style(self.root)
        for theme_name in ("vista", "winnative", "clam"):
            if theme_name in style.theme_names():
                style.theme_use(theme_name)
                break
        style.configure("Installer.Horizontal.TProgressbar", thickness=14)

    def _build_ui(self) -> None:
        # Header banner
        header = tk.Frame(self.root, bg="#FFFFFF", padx=20, pady=14)
        header.pack(fill="x")

        header_inner = tk.Frame(header, bg="#FFFFFF")
        header_inner.pack(fill="x")

        try:
            logo_path = get_resource_path("logo_48.png")
            if logo_path.exists():
                self._header_logo_img = tk.PhotoImage(master=self.root, file=str(logo_path))
                logo_lbl = tk.Label(
                    header_inner,
                    image=self._header_logo_img,
                    bg="#FFFFFF",
                )
                logo_lbl.pack(side="left", padx=(0, 12))
        except Exception:
            pass

        header_text = tk.Frame(header_inner, bg="#FFFFFF")
        header_text.pack(side="left", fill="x", expand=True)

        title_row = tk.Frame(header_text, bg="#FFFFFF")
        title_row.pack(fill="x")

        title_lbl = tk.Label(
            title_row,
            text=self.app_display_name,
            font=("Segoe UI", 13, "bold"),
            fg="#1A1A1A",
            bg="#FFFFFF",
            anchor="w",
        )
        title_lbl.pack(side="left")

        ver_badge = tk.Label(
            title_row,
            text=f"v{self.version}",
            font=("Segoe UI", 9, "bold"),
            fg="#0067C0",
            bg="#EBF3FC",
            padx=8,
            pady=2,
        )
        ver_badge.pack(side="right")

        subtitle_text = (
            "Đang sửa chữa và đồng bộ cấu hình hệ thống..."
            if self.repair
            else "Bộ cài đặt All-in-One cho Windows 11 (Binary, User PATH & Antigravity Skill)"
        )
        subtitle_lbl = tk.Label(
            header_text,
            text=subtitle_text,
            font=("Segoe UI", 9),
            fg="#5A5A5A",
            bg="#FFFFFF",
            anchor="w",
        )
        subtitle_lbl.pack(fill="x", pady=(4, 0))

        tk.Frame(self.root, bg="#E0E0E0", height=1).pack(fill="x")

        # Main content body
        body = tk.Frame(self.root, bg="#F3F3F3", padx=20, pady=14)
        body.pack(fill="both", expand=True)

        # Current step row
        step_row = tk.Frame(body, bg="#F3F3F3")
        step_row.pack(fill="x")

        self.step_var = tk.StringVar(value="[0/6] Đang khởi tạo tiến trình cài đặt...")
        self.step_lbl = tk.Label(
            step_row,
            textvariable=self.step_var,
            font=("Segoe UI", 10, "bold"),
            fg="#1F1F1F",
            bg="#F3F3F3",
            anchor="w",
        )
        self.step_lbl.pack(side="left", fill="x", expand=True)

        self.percent_var = tk.StringVar(value="0%")
        self.percent_lbl = tk.Label(
            step_row,
            textvariable=self.percent_var,
            font=("Segoe UI", 10, "bold"),
            fg="#0067C0",
            bg="#F3F3F3",
            width=5,
            anchor="e",
        )
        self.percent_lbl.pack(side="right")

        # Progress bar
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            body,
            orient="horizontal",
            mode="determinate",
            maximum=100.0,
            variable=self.progress_var,
            style="Installer.Horizontal.TProgressbar",
        )
        self.progress_bar.pack(fill="x", pady=(8, 12))

        # Result summary banner (initially neutral/in-progress)
        self.summary_frame = tk.Frame(
            body,
            bg="#FFFFFF",
            highlightbackground="#DCDCDC",
            highlightthickness=1,
            padx=12,
            pady=10,
        )
        self.summary_frame.pack(fill="x", pady=(0, 10))

        self.summary_title_var = tk.StringVar(value="Đang thiết lập môi trường cài đặt an toàn...")
        self.summary_title_lbl = tk.Label(
            self.summary_frame,
            textvariable=self.summary_title_var,
            font=("Segoe UI", 10, "bold"),
            fg="#1A1A1A",
            bg="#FFFFFF",
            anchor="w",
            justify="left",
        )
        self.summary_title_lbl.pack(fill="x")

        self.summary_detail_var = tk.StringVar(
            value="Vui lòng giữ cửa sổ mở cho đến khi quá trình cài đặt và kiểm tra hoàn tất."
        )
        self.summary_detail_lbl = tk.Label(
            self.summary_frame,
            textvariable=self.summary_detail_var,
            font=("Segoe UI", 9),
            fg="#4A4A4A",
            bg="#FFFFFF",
            anchor="w",
            justify="left",
            wraplength=610,
        )
        self.summary_detail_lbl.pack(fill="x", pady=(3, 0))

        # Log output area
        log_header = tk.Label(
            body,
            text="Nhật ký chi tiết:",
            font=("Segoe UI", 9, "bold"),
            fg="#4A4A4A",
            bg="#F3F3F3",
            anchor="w",
        )
        log_header.pack(fill="x", pady=(2, 4))

        log_container = tk.Frame(body, bg="#FFFFFF", bd=1, relief="solid")
        log_container.pack(fill="both", expand=True)

        self.log_text = tk.Text(
            log_container,
            wrap="word",
            height=10,
            font=("Consolas", 9),
            bg="#FAFAFA",
            fg="#222222",
            relief="flat",
            padx=8,
            pady=6,
            state="disabled",
        )
        scrollbar = ttk.Scrollbar(log_container, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)

        self.log_text.tag_configure("step", foreground="#005A9E", font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("success", foreground="#107C10")
        self.log_text.tag_configure("warning", foreground="#9D5D00")
        self.log_text.tag_configure("error", foreground="#C42B1C", font=("Consolas", 9, "bold"))
        self.log_text.tag_configure("info", foreground="#222222")

        # Footer action bar
        tk.Frame(self.root, bg="#E0E0E0", height=1).pack(fill="x")
        footer = tk.Frame(self.root, bg="#F3F3F3", padx=20, pady=12)
        footer.pack(fill="x")

        self.copy_btn = ttk.Button(
            footer,
            text="Sao chép log",
            command=self._copy_logs_to_clipboard,
        )
        self.copy_btn.pack(side="left")

        self.lock_hint_var = tk.StringVar(value="Đang khóa đóng cửa sổ để bảo vệ giao dịch cài đặt...")
        self.lock_hint_lbl = tk.Label(
            footer,
            textvariable=self.lock_hint_var,
            font=("Segoe UI", 9),
            fg="#666666",
            bg="#F3F3F3",
            anchor="w",
        )
        self.lock_hint_lbl.pack(side="left", padx=(12, 12), fill="x", expand=True)

        self.close_btn = ttk.Button(
            footer,
            text="Đang cài đặt...",
            state="disabled",
            command=self._on_close_requested,
        )
        self.close_btn.pack(side="right")

    def start(self) -> None:
        """Starts background installation worker thread and schedules queue polling."""
        worker = threading.Thread(target=self._run_worker, daemon=True)
        worker.start()
        self.root.after(self.POLL_INTERVAL_MS, self._poll_queue)

    def _run_worker(self) -> None:
        success = False
        try:
            success = bool(
                self.install_fn(
                    silent=False,
                    repair=self.repair,
                    wait_for_pid=0,
                    update_result=self.update_result,
                    update_id=self.update_id,
                    on_progress=self.event_queue.put,
                )
            )
        except Exception as exc:
            self.event_queue.put(
                {
                    "type": "log",
                    "level": "error",
                    "message": f"[ERROR] Lỗi không mong muốn trong tiến trình cài đặt: {exc}",
                }
            )
            self.event_queue.put(
                {
                    "type": "result",
                    "success": False,
                    "error": str(exc),
                    "rollback_attempted": False,
                    "rollback_succeeded": False,
                }
            )
            success = False
        finally:
            self.event_queue.put({"type": "worker_done", "success": success})

    def _poll_queue(self) -> None:
        self.drain_events()
        if self.is_running:
            self.root.after(self.POLL_INTERVAL_MS, self._poll_queue)

    def drain_events(self) -> None:
        """Processes all currently queued events on the UI main thread."""
        while True:
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break
            self.handle_event(event)

    def handle_event(self, event: Dict[str, Any]) -> None:
        """Dispatches a single progress event to update Tkinter widgets safely."""
        ev_type = event.get("type")

        if ev_type == "lock_ui":
            self.transaction_locked = bool(event.get("locked", True))
            if self.transaction_locked:
                self.lock_hint_var.set("Đang khóa đóng cửa sổ để bảo vệ giao dịch ghi tệp / Registry...")
            else:
                self.lock_hint_var.set("")
            return

        if ev_type == "step":
            step_num = event.get("step")
            total_steps = event.get("total_steps", 6)
            status_text = event.get("status_text") or event.get("message") or ""
            percent = event.get("percent")
            if step_num is not None:
                self.step_var.set(f"[{step_num}/{total_steps}] {status_text}")
            elif status_text:
                self.step_var.set(status_text)

            if percent is not None:
                clamped = max(0.0, min(100.0, float(percent)))
                self.progress_var.set(clamped)
                self.percent_var.set(f"{int(round(clamped))}%")

            log_msg = event.get("message")
            if log_msg:
                self._append_log(log_msg, level=event.get("level", "step"))
            return

        if ev_type == "log":
            msg = event.get("message", "")
            if msg:
                self._append_log(msg, level=event.get("level", "info"))
            return

        if ev_type == "result":
            self.result_info = dict(event)
            self._render_result_summary(self.result_info)
            return

        if ev_type == "worker_done":
            self.is_running = False
            self.transaction_locked = False
            self.final_success = bool(event.get("success", False))

            if self.final_success:
                self.progress_var.set(100.0)
                self.percent_var.set("100%")
                self.step_var.set("Cài đặt hoàn tất thành công!")
                self.close_btn.configure(text="Hoàn tất", state="normal")
                self.lock_hint_var.set("Bạn có thể đóng cửa sổ hoặc sao chép nhật ký cài đặt.")
            else:
                if self.progress_var.get() < 100.0:
                    self.step_var.set("Cài đặt không thành công.")
                self.close_btn.configure(text="Đóng", state="normal")
                self.lock_hint_var.set("Giao dịch đã kết thúc an toàn. Bạn có thể đóng cửa sổ.")

            if not self.result_info:
                self._render_result_summary(
                    {
                        "success": self.final_success,
                        "error": None if self.final_success else "Cài đặt thất bại.",
                        "rollback_attempted": False,
                        "rollback_succeeded": False,
                    }
                )

    def _append_log(self, message: str, level: str = "info") -> None:
        text = message.rstrip("\r\n")
        if not text:
            return
        self.log_lines.append(text)
        tag = level if level in ("step", "success", "warning", "error", "info") else "info"
        if text.startswith("[ERROR]"):
            tag = "error"
        elif text.startswith("[!]"):
            tag = "warning"
        elif text.startswith("[+]"):
            tag = "success"

        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _set_summary_colors(self, bg: str, border: str, title_fg: str, detail_fg: str) -> None:
        self.summary_frame.configure(bg=bg, highlightbackground=border)
        self.summary_title_lbl.configure(bg=bg, fg=title_fg)
        self.summary_detail_lbl.configure(bg=bg, fg=detail_fg)

    def _render_result_summary(self, info: Dict[str, Any]) -> None:
        success = bool(info.get("success", False))
        if success:
            self._set_summary_colors(
                bg="#DFF6DD",
                border="#9FD89F",
                title_fg="#107C10",
                detail_fg="#1B4D1B",
            )
            ver = info.get("version") or self.version
            self.summary_title_var.set(f"Cài đặt thành công Disk Investigator v{ver}!")
            details = []
            if info.get("target_exe"):
                details.append(f"• Binary: {info['target_exe']}")
            if info.get("target_skill"):
                details.append(f"• Skill AI: {info['target_skill']}")
            if info.get("skill_backup"):
                details.append(f"• Đã sao lưu Skill tùy chỉnh: {info['skill_backup']}")
            if info.get("install_dir"):
                details.append(f"• Gỡ cài đặt: {Path(info['install_dir']) / 'uninstall.cmd'}")
            details.append("• Mở PowerShell / CMD mới và chạy: disk_investigator --help")
            self.summary_detail_var.set("\n".join(details))
        else:
            self._set_summary_colors(
                bg="#FDE7E9",
                border="#F1AEB5",
                title_fg="#A4262C",
                detail_fg="#5C1A1E",
            )
            error_msg = info.get("error") or "Đã xảy ra lỗi trong quá trình cài đặt."
            self.summary_title_var.set("Cài đặt thất bại")

            rollback_attempted = bool(info.get("rollback_attempted", False))
            rollback_succeeded = bool(info.get("rollback_succeeded", False))
            if rollback_attempted and rollback_succeeded:
                rb_text = "Trạng thái Rollback: Đã khôi phục an toàn về trạng thái trước cài đặt (100% nguyên vẹn)."
            elif rollback_attempted and not rollback_succeeded:
                rb_text = "Trạng thái Rollback: Rollback gặp lỗi một phần. Vui lòng sao chép log để kiểm tra."
            else:
                rb_text = "Trạng thái Rollback: Không có tệp hệ thống nào bị thay đổi trước khi dừng."

            self.summary_detail_var.set(f"Lỗi: {error_msg}\n{rb_text}")

    def _copy_logs_to_clipboard(self) -> None:
        header = f"Disk Investigator Setup v{self.version}\n"
        summary = f"{self.summary_title_var.get()}\n{self.summary_detail_var.get()}\n"
        separator = "-" * 55 + "\n"
        payload = header + summary + separator + "\n".join(self.log_lines)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(payload)
            self.root.update()
            self.copy_btn.configure(text="Đã sao chép!")
            if self._copy_reset_after_id is not None:
                try:
                    self.root.after_cancel(self._copy_reset_after_id)
                except Exception:
                    pass
            self._copy_reset_after_id = self.root.after(
                1500, lambda: self.copy_btn.configure(text="Sao chép log")
            )
        except Exception:
            pass

    def _on_close_requested(self) -> None:
        if self.is_running or self.transaction_locked:
            self.lock_hint_var.set(
                "Đang ghi tệp / cấu hình Registry, vui lòng chờ cài đặt hoặc rollback xong!"
            )
            try:
                self.root.bell()
            except Exception:
                pass
            return
        self.root.destroy()


def run_installer_gui(
    version: str,
    app_display_name: str,
    install_fn: Callable[..., bool],
    repair: bool = False,
    update_result: Optional[Path] = None,
    update_id: Optional[str] = None,
) -> int:
    """
    Launches the Tkinter installation window and blocks until closed.
    Returns 0 on successful installation, 1 otherwise.
    """
    enable_high_dpi_awareness()
    root = tk.Tk()
    window = InstallerWindow(
        root=root,
        version=version,
        app_display_name=app_display_name,
        install_fn=install_fn,
        repair=repair,
        update_result=update_result,
        update_id=update_id,
    )
    window.start()
    root.mainloop()
    return 0 if window.final_success else 1
