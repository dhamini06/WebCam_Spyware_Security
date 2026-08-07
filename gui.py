"""
GUI Application for Webcam Spyware Security
Built with CustomTkinter - Modern Dark Theme GUI
"""

import customtkinter as ctk
from tkinter import messagebox
import threading
import sys
from typing import Optional, Callable, Dict, Any, List
import logging
import os

from database import DatabaseManager
from authentication import AuthenticationManager
from user_manager import UserManager
from camera_controller import CameraController
from policy_manager import PolicyManager, Policy
from scheduler import Scheduler
from face_manager import FaceManager
from logging_manager import LoggingManager
from report_generator import ReportGenerator
from utils import SystemInfo, DateTimeUtils
from project_info import get_project_info

logger = logging.getLogger(__name__)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class AppConfig:
    WINDOW_WIDTH = 1200
    WINDOW_HEIGHT = 700
    SIDEBAR_WIDTH = 200
    FONT_TITLE = ("Segoe UI", 24, "bold")
    FONT_HEADING = ("Segoe UI", 18, "bold")
    FONT_SUBHEADING = ("Segoe UI", 14, "bold")
    FONT_NORMAL = ("Segoe UI", 12)
    FONT_SMALL = ("Segoe UI", 10)
    COLOR_PRIMARY = "#1f6aa5"
    COLOR_SUCCESS = "#2da346"
    COLOR_WARNING = "#f79646"
    COLOR_DANGER = "#c5504b"
    COLOR_DARK_BG = "#1a1a1a"
    COLOR_DARKER_BG = "#0d0d0d"
    COLOR_TEXT = "#e0e0e0"


class LoginScreen(ctk.CTkFrame):
    def __init__(self, parent, on_login: Callable):
        super().__init__(parent, fg_color=AppConfig.COLOR_DARK_BG)
        self.on_login = on_login
        self.auth = AuthenticationManager()
        self.build_ui()

    def build_ui(self):
        center_frame = ctk.CTkFrame(self, fg_color="transparent")
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        title = ctk.CTkLabel(
            center_frame, text="Webcam Spyware Security",
            font=AppConfig.FONT_TITLE, text_color=AppConfig.COLOR_TEXT
        )
        title.pack(pady=(0, 10))

        subtitle = ctk.CTkLabel(
            center_frame, text="Enterprise Webcam Protection",
            font=AppConfig.FONT_SMALL, text_color="#888888"
        )
        subtitle.pack(pady=(0, 40))

        card = ctk.CTkFrame(center_frame, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=20, fill="both", expand=False)

        ctk.CTkLabel(card, text="Username", font=AppConfig.FONT_NORMAL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(20, 5))

        self.username_entry = ctk.CTkEntry(
            card, placeholder_text="Enter username", font=AppConfig.FONT_NORMAL,
            height=40, corner_radius=8
        )
        self.username_entry.pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkLabel(card, text="Password", font=AppConfig.FONT_NORMAL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 5))

        self.password_entry = ctk.CTkEntry(
            card, placeholder_text="Enter password", show="*",
            font=AppConfig.FONT_NORMAL, height=40, corner_radius=8
        )
        self.password_entry.pack(fill="x", padx=20, pady=(0, 20))

        login_btn = ctk.CTkButton(
            card, text="Login", command=self.handle_login,
            font=AppConfig.FONT_NORMAL, height=40,
            fg_color=AppConfig.COLOR_PRIMARY, corner_radius=8
        )
        login_btn.pack(fill="x", padx=20, pady=(0, 10))

        register_btn = ctk.CTkButton(
            card, text="Register New Account",
            command=self.show_register,
            font=AppConfig.FONT_SMALL, height=30,
            fg_color="transparent", hover_color="#333333",
            text_color=AppConfig.COLOR_PRIMARY, corner_radius=8
        )
        register_btn.pack(fill="x", padx=20, pady=(0, 20))

        self.status_label = ctk.CTkLabel(
            card, text="", font=AppConfig.FONT_SMALL,
            text_color=AppConfig.COLOR_DANGER
        )
        self.status_label.pack(pady=(0, 10))

    def show_register(self):
        self.status_label.configure(text="")
        RegisterDialog(self, self.auth, self.on_register_complete)

    def on_register_complete(self, success, message):
        if success:
            self.status_label.configure(text=message, text_color=AppConfig.COLOR_SUCCESS)
        else:
            self.status_label.configure(text=message, text_color=AppConfig.COLOR_DANGER)

    def handle_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username or not password:
            self.status_label.configure(text="Please enter username and password")
            return

        self.status_label.configure(text="Logging in...", text_color="#888888")
        self.update_idletasks()

        try:
            success, msg, token = self.auth.login(username, password)
            if success:
                # Password was correct; a one-time code was emailed.
                # token is intentionally None until the code is verified.
                self.status_label.configure(text=msg, text_color=AppConfig.COLOR_SUCCESS)
                OtpDialog(self, self.auth, username, password, self.on_login, delivery_message=msg)
            else:
                self.status_label.configure(text=msg, text_color=AppConfig.COLOR_DANGER)
        except Exception as e:
            logger.error(f"Login error: {e}", exc_info=True)
            self.status_label.configure(text=f"Login failed: {e}", text_color=AppConfig.COLOR_DANGER)


class OtpDialog(ctk.CTkToplevel):
    """Shown after a correct username+password, before granting access -
    asks for the one-time code that was emailed to the user."""

    def __init__(self, parent, auth: AuthenticationManager, username: str, password: str,
                 on_login: Callable, delivery_message: str = None):
        super().__init__(parent)
        self.auth = auth
        self.username = username
        self._password = password  # held in memory only, for "Resend code"; never written to disk or logged
        self.on_login = on_login
        self._delivery_message = delivery_message
        self.title("Verification Code")
        self.geometry("380x300")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._center_window()
        self._build_ui()

    def _center_window(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        card = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(card, text="Enter Verification Code", font=AppConfig.FONT_NORMAL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(20, 5))
        delivery_text = self._delivery_message or "We emailed a 6-digit code to your registered address."

        import re
        code_match = re.search(r'\b(\d{6})\b', delivery_text)
        if code_match and "sent to" not in delivery_text:
            ctk.CTkLabel(card, text="Your code (shown because email isn't configured):",
                         font=AppConfig.FONT_SMALL, text_color="#888888", wraplength=280,
                         justify="left").pack(anchor="w", padx=20, pady=(0, 5))
            ctk.CTkLabel(card, text=code_match.group(1),
                         font=("Arial", 34, "bold"), text_color=AppConfig.COLOR_PRIMARY,
                         justify="center").pack(anchor="w", padx=20, pady=(0, 5))
        else:
            ctk.CTkLabel(card, text=delivery_text,
                         font=AppConfig.FONT_SMALL, text_color="#888888", wraplength=280,
                         justify="left").pack(anchor="w", padx=20, pady=(0, 15))

        self.code_entry = ctk.CTkEntry(card, placeholder_text="6-digit code",
                                       font=AppConfig.FONT_NORMAL, height=40, corner_radius=8)
        self.code_entry.pack(fill="x", padx=20, pady=(0, 15))
        self.code_entry.bind("<Return>", lambda e: self._handle_verify())

        ctk.CTkButton(card, text="Verify", command=self._handle_verify,
                      font=AppConfig.FONT_NORMAL, height=40,
                      fg_color=AppConfig.COLOR_PRIMARY, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkButton(card, text="Resend code", command=self._handle_resend,
                      font=AppConfig.FONT_SMALL, height=30,
                      fg_color="transparent", hover_color="#333333",
                      text_color=AppConfig.COLOR_PRIMARY, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 10))

        self.status_label = ctk.CTkLabel(card, text="", font=AppConfig.FONT_SMALL,
                                         text_color=AppConfig.COLOR_DANGER, wraplength=280)
        self.status_label.pack(pady=(0, 10))

    def _handle_verify(self):
        code = self.code_entry.get().strip()
        if not code:
            self.status_label.configure(text="Enter the code you received", text_color=AppConfig.COLOR_DANGER)
            return
        try:
            success, msg, token = self.auth.verify_login_otp(self.username, code)
            if success:
                self._password = None
                self.grab_release()
                self.destroy()
                self.on_login(self.auth.current_user, token)
            else:
                self.status_label.configure(text=msg, text_color=AppConfig.COLOR_DANGER)
        except Exception as e:
            logger.error(f"OTP verify error: {e}", exc_info=True)
            self.status_label.configure(text=f"Verification failed: {e}", text_color=AppConfig.COLOR_DANGER)

    def _handle_resend(self):
        try:
            success, msg, _ = self.auth.login(self.username, self._password)
            color = AppConfig.COLOR_SUCCESS if success else AppConfig.COLOR_DANGER
            self.status_label.configure(text=msg, text_color=color)
        except Exception as e:
            logger.error(f"OTP resend error: {e}", exc_info=True)
            self.status_label.configure(text=f"Resend failed: {e}", text_color=AppConfig.COLOR_DANGER)

    def _on_cancel(self):
        self._password = None
        self.grab_release()
        self.destroy()


class RegisterDialog(ctk.CTkToplevel):
    def __init__(self, parent, auth: AuthenticationManager, callback: Callable):
        super().__init__(parent)
        self.auth = auth
        self.callback = callback
        self.title("Register New Account")
        self.geometry("400x500")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)
        self.transient(parent)
        self.grab_set()

        self._center_window()
        self._build_ui()

    def _center_window(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        ctk.CTkLabel(self, text="Create Account", font=AppConfig.FONT_HEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(pady=20)

        card = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=10, fill="both", expand=True)

        ctk.CTkLabel(card, text="Username", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 5))
        self.username_entry = ctk.CTkEntry(card, placeholder_text="3-50 alphanumeric characters",
                                           font=AppConfig.FONT_NORMAL, height=35, corner_radius=8)
        self.username_entry.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(card, text="Email", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 5))
        self.email_entry = ctk.CTkEntry(card, placeholder_text="user@company.com",
                                        font=AppConfig.FONT_NORMAL, height=35, corner_radius=8)
        self.email_entry.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(card, text="Password", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 5))
        self.password_entry = ctk.CTkEntry(card, placeholder_text="Min 8 chars, upper, lower, digit, special",
                                           show="*", font=AppConfig.FONT_NORMAL, height=35, corner_radius=8)
        self.password_entry.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(card, text="Role", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 5))
        self.role_var = ctk.StringVar(value="employee")
        role_menu = ctk.CTkOptionMenu(card, variable=self.role_var,
                                      values=["employee", "admin"],
                                      font=AppConfig.FONT_NORMAL, height=35, corner_radius=8)
        role_menu.pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkButton(card, text="Register", command=self._handle_register,
                      font=AppConfig.FONT_NORMAL, height=40,
                      fg_color=AppConfig.COLOR_PRIMARY, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkButton(card, text="Cancel", command=self.destroy,
                      font=AppConfig.FONT_SMALL, height=30,
                      fg_color="transparent", hover_color="#333333",
                      text_color="#888888", corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 15))

        self.status_label = ctk.CTkLabel(card, text="", font=AppConfig.FONT_SMALL,
                                         text_color=AppConfig.COLOR_DANGER)
        self.status_label.pack(pady=(0, 5))

    def _handle_register(self):
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        role = self.role_var.get()

        if not username or not email or not password:
            self.status_label.configure(text="All fields are required", text_color=AppConfig.COLOR_DANGER)
            return

        success, msg = self.auth.register_user(username, email, password, role)
        self.callback(success, msg)
        if success:
            self.destroy()
        else:
            self.status_label.configure(text=msg, text_color=AppConfig.COLOR_DANGER)


class ChangePasswordDialog(ctk.CTkToplevel):
    def __init__(self, parent, auth: AuthenticationManager, user: Dict):
        super().__init__(parent)
        self.auth = auth
        self.user = user
        self.title("Change Password")
        self.geometry("400x380")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)
        self.transient(parent)
        self.grab_set()
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(self, text="Change Password", font=AppConfig.FONT_HEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(pady=20)

        card = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=10, fill="both", expand=True)

        ctk.CTkLabel(card, text="Current Password", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 5))
        self.old_pass = ctk.CTkEntry(card, show="*", font=AppConfig.FONT_NORMAL,
                                     height=35, corner_radius=8)
        self.old_pass.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(card, text="New Password", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 5))
        self.new_pass = ctk.CTkEntry(card, show="*", font=AppConfig.FONT_NORMAL,
                                     height=35, corner_radius=8)
        self.new_pass.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(card, text="Confirm New Password", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 5))
        self.confirm_pass = ctk.CTkEntry(card, show="*", font=AppConfig.FONT_NORMAL,
                                         height=35, corner_radius=8)
        self.confirm_pass.pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkButton(card, text="Change Password", command=self._handle_change,
                      font=AppConfig.FONT_NORMAL, height=40,
                      fg_color=AppConfig.COLOR_PRIMARY, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkButton(card, text="Cancel", command=self.destroy,
                      font=AppConfig.FONT_SMALL, height=30,
                      fg_color="transparent", hover_color="#333333",
                      text_color="#888888", corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 10))

        self.status_label = ctk.CTkLabel(card, text="", font=AppConfig.FONT_SMALL,
                                         text_color=AppConfig.COLOR_DANGER)
        self.status_label.pack(pady=(0, 5))

    def _handle_change(self):
        old = self.old_pass.get()
        new = self.new_pass.get()
        confirm = self.confirm_pass.get()

        if not old or not new or not confirm:
            self.status_label.configure(text="All fields are required")
            return

        if new != confirm:
            self.status_label.configure(text="New passwords do not match")
            return

        success, msg = self.auth.change_password(self.user['username'], old, new)
        if success:
            messagebox.showinfo("Success", msg)
            self.destroy()
        else:
            self.status_label.configure(text=msg)


class CameraAccessDialog(ctk.CTkToplevel):
    """
    Gates a sensitive camera action behind BOTH password re-entry AND face
    verification. A wrong password or a non-matching face captures a
    10-second video + one snapshot into the Intruders log instead of just
    silently refusing.
    """

    def __init__(self, parent, auth: AuthenticationManager, face_mgr: FaceManager,
                 db: DatabaseManager, user: Dict, action_label: str, on_verified: Callable):
        super().__init__(parent)
        self.auth = auth
        self.face_mgr = face_mgr
        self.db = db
        self.user = user
        self.on_verified = on_verified
        self.title("Verify Identity")
        self.geometry("420x340")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._center_window()
        self._build_ui(action_label)

    def _center_window(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self, action_label):
        card = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(card, text=f"Verify to: {action_label}", font=AppConfig.FONT_NORMAL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(card, text="Enter your password, then click Verify.\n"
                     "If the password is wrong, your camera will also check your face.",
                     font=AppConfig.FONT_SMALL, text_color="#888888",
                     justify="left").pack(anchor="w", padx=20, pady=(0, 15))

        self.password_entry = ctk.CTkEntry(card, placeholder_text="Password", show="*",
                                           font=AppConfig.FONT_NORMAL, height=40, corner_radius=8)
        self.password_entry.pack(fill="x", padx=20, pady=(0, 15))
        self.password_entry.bind("<Return>", lambda e: self._handle_verify())

        self.verify_btn = ctk.CTkButton(card, text="Verify & Proceed", command=self._handle_verify,
                                        font=AppConfig.FONT_NORMAL, height=40,
                                        fg_color=AppConfig.COLOR_PRIMARY, corner_radius=8)
        self.verify_btn.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkButton(card, text="Cancel", command=self._on_cancel,
                      font=AppConfig.FONT_SMALL, height=30,
                      fg_color="transparent", hover_color="#333333",
                      text_color="#888888", corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 10))

        self.status_label = ctk.CTkLabel(card, text="", font=AppConfig.FONT_SMALL,
                                         text_color=AppConfig.COLOR_DANGER, wraplength=320)
        self.status_label.pack(pady=(0, 5))

    def _on_cancel(self):
        self.grab_release()
        self.destroy()

    def _handle_verify(self):
        password = self.password_entry.get()
        if not password:
            self.status_label.configure(text="Enter your password", text_color=AppConfig.COLOR_DANGER)
            return

        self.verify_btn.configure(state="disabled")
        self.status_label.configure(text="Checking password and face - look at your camera...",
                                    text_color="#888888")
        self.update()

        try:
            password_ok = self.auth.verify_current_password(self.user['user_id'], password)

            face_ok = False
            if not password_ok:
                # Correct password is sufficient on its own; only fall back
                # to the camera when the password is wrong. This avoids
                # blocking legitimate users who haven't registered a face.
                frame = self.face_mgr.capture_face_from_camera(timeout_seconds=5)
                if frame is not None:
                    verified, confidence, msg = self.face_mgr.verify_face(
                        self.user['user_id'], image=frame, username=self.user['username'])
                    face_ok = verified

            if password_ok or face_ok:
                self.grab_release()
                self.destroy()
                self.on_verified()
                return

            reasons = []
            if not password_ok:
                reasons.append("wrong password")
            if not face_ok:
                reasons.append("face not recognized")
            reason_text = " + ".join(reasons)

            snapshot_path, video_path = self.face_mgr.capture_intruder_evidence()
            self.db.add_intruder_log(
                failed_attempts=1,
                image_path=snapshot_path,
                video_path=video_path,
                ip_address=SystemInfo.get_ip_address(),
                machine_name=SystemInfo.get_machine_name(),
                reason=f"Camera control ({reason_text})"
            )
            self.db.add_log(
                self.user['user_id'], self.user['username'], 'camera_access_denied', 'warning',
                f"Camera control verification failed: {reason_text}",
                SystemInfo.get_ip_address(), SystemInfo.get_machine_name()
            )

            self.verify_btn.configure(state="normal")
            self.status_label.configure(
                text=f"Verification failed ({reason_text}). This attempt was recorded.",
                text_color=AppConfig.COLOR_DANGER
            )
        except Exception as e:
            logger.error(f"Camera access verification error: {e}", exc_info=True)
            self.verify_btn.configure(state="normal")
            self.status_label.configure(text=f"Verification error: {e}", text_color=AppConfig.COLOR_DANGER)


class PasswordGateDialog(ctk.CTkToplevel):
    """
    Lighter-weight sibling of CameraAccessDialog: password only, no face
    check - for gates like View Logs. A wrong password still captures a
    single snapshot (no video) into the Intruders log.
    """

    def __init__(self, parent, auth: AuthenticationManager, face_mgr: FaceManager,
                 db: DatabaseManager, user: Dict, action_label: str, on_verified: Callable):
        super().__init__(parent)
        self.auth = auth
        self.face_mgr = face_mgr
        self.db = db
        self.user = user
        self.on_verified = on_verified
        self.title("Verify Identity")
        self.geometry("380x280")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._center_window()
        self._build_ui(action_label)

    def _center_window(self):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self, action_label):
        card = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=20, fill="both", expand=True)

        ctk.CTkLabel(card, text=f"Verify to: {action_label}", font=AppConfig.FONT_NORMAL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(card, text="Enter your password to continue.",
                     font=AppConfig.FONT_SMALL, text_color="#888888",
                     justify="left").pack(anchor="w", padx=20, pady=(0, 15))

        self.password_entry = ctk.CTkEntry(card, placeholder_text="Password", show="*",
                                           font=AppConfig.FONT_NORMAL, height=40, corner_radius=8)
        self.password_entry.pack(fill="x", padx=20, pady=(0, 15))
        self.password_entry.bind("<Return>", lambda e: self._handle_verify())

        self.verify_btn = ctk.CTkButton(card, text="Verify", command=self._handle_verify,
                                        font=AppConfig.FONT_NORMAL, height=40,
                                        fg_color=AppConfig.COLOR_PRIMARY, corner_radius=8)
        self.verify_btn.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkButton(card, text="Cancel", command=self._on_cancel,
                      font=AppConfig.FONT_SMALL, height=30,
                      fg_color="transparent", hover_color="#333333",
                      text_color="#888888", corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 10))

        self.status_label = ctk.CTkLabel(card, text="", font=AppConfig.FONT_SMALL,
                                         text_color=AppConfig.COLOR_DANGER, wraplength=320)
        self.status_label.pack(pady=(0, 5))

    def _handle_verify(self):
        password = self.password_entry.get()
        if not password:
            self.status_label.configure(text="Enter your password", text_color=AppConfig.COLOR_DANGER)
            return

        self.verify_btn.configure(state="disabled")
        self.status_label.configure(text="Checking...", text_color="#888888")
        self.update()

        try:
            password_ok = self.auth.verify_current_password(self.user['user_id'], password)
            if password_ok:
                self.grab_release()
                self.destroy()
                self.on_verified()
                return

            snapshot_path, _ = self.face_mgr.capture_intruder_evidence(capture_video=False)
            self.db.add_intruder_log(
                failed_attempts=1,
                image_path=snapshot_path,
                ip_address=SystemInfo.get_ip_address(),
                machine_name=SystemInfo.get_machine_name(),
                reason="View Logs (wrong password)"
            )
            self.db.add_log(
                self.user['user_id'], self.user['username'], 'logs_access_denied', 'warning',
                'Incorrect password entered to view activity logs',
                SystemInfo.get_ip_address(), SystemInfo.get_machine_name()
            )

            self.verify_btn.configure(state="normal")
            self.status_label.configure(
                text="Incorrect password. This attempt was recorded.",
                text_color=AppConfig.COLOR_DANGER
            )
        except Exception as e:
            logger.error(f"Password gate verification error: {e}", exc_info=True)
            self.verify_btn.configure(state="normal")
            self.status_label.configure(text=f"Verification error: {e}", text_color=AppConfig.COLOR_DANGER)

    def _on_cancel(self):
        self.grab_release()
        self.destroy()


class DashboardScreen(ctk.CTkFrame):
    def __init__(self, parent, user: Dict, token: str, on_logout: Callable):
        super().__init__(parent, fg_color=AppConfig.COLOR_DARK_BG)
        self.user = user
        self.token = token
        self.on_logout = on_logout
        self.db = DatabaseManager()
        self.auth = AuthenticationManager(self.db)
        self.camera_ctrl = CameraController(self.db)
        self.policy_mgr = PolicyManager(self.db)
        self.scheduler = Scheduler(self.db, callback=self._handle_schedule_action)
        self.log_mgr = LoggingManager(self.db)
        self.report_gen = ReportGenerator(self.db)
        self.face_mgr = FaceManager(self.db)
        self.user_mgr = UserManager(self.auth, self.db)
        self.current_view = None
        self.scheduler.start()
        self._face_stop_event = threading.Event()
        self.build_ui()

    def build_ui(self):
        self.sidebar = ctk.CTkFrame(self, fg_color="#1f1f1f", width=AppConfig.SIDEBAR_WIDTH)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        user_label = ctk.CTkLabel(self.sidebar, text=f"  {self.user['username']}",
                                  font=AppConfig.FONT_NORMAL, text_color=AppConfig.COLOR_TEXT)
        user_label.pack(padx=10, pady=(20, 5), anchor="w")

        role_label = ctk.CTkLabel(self.sidebar, text=f"  Role: {self.user['role'].title()}",
                                  font=AppConfig.FONT_SMALL, text_color="#888888")
        role_label.pack(padx=10, pady=(0, 15), anchor="w")

        ctk.CTkFrame(self.sidebar, fg_color="#333333", height=1).pack(fill="x", padx=10)

        self.nav_buttons = {}
        self._add_nav_button("dashboard", "  Dashboard", self.show_dashboard)
        self._add_nav_button("project_info", "  Project Info", self.handle_project_info)
        self._add_nav_button("camera", "  Camera Control", self.show_camera)
        self._add_nav_button("face", "  Face Recognition", self.show_face)
        self._add_nav_button("logs", "  Activity Logs", self.show_logs)
        self._add_nav_button("reports", "  Reports", self.show_reports)

        if self.user['role'] == 'admin':
            self._add_nav_button("users", "  User Management", self.show_users)
            self._add_nav_button("policies", "  Policies", self.show_policies)
            self._add_nav_button("schedules", "  Schedules", self.show_schedules)

        self._add_nav_button("settings", "  Settings", self.show_settings)

        ctk.CTkFrame(self.sidebar, fg_color="#333333", height=1).pack(fill="x", padx=10, pady=10)

        logout_btn = ctk.CTkButton(self.sidebar, text="  Logout", command=self.handle_logout,
                                   fg_color=AppConfig.COLOR_DANGER, font=AppConfig.FONT_SMALL,
                                   corner_radius=8, height=35)
        logout_btn.pack(padx=10, pady=(0, 10), fill="x")

        self.content_frame = ctk.CTkFrame(self, fg_color=AppConfig.COLOR_DARK_BG)
        self.content_frame.pack(side="right", fill="both", expand=True)

        self.show_dashboard()

    def _add_nav_button(self, name: str, text: str, command: Callable):
        btn = ctk.CTkButton(self.sidebar, text=text, command=command,
                            fg_color="#2a2a2a", hover_color="#333333",
                            font=AppConfig.FONT_SMALL, corner_radius=8, height=35, anchor="w")
        btn.pack(padx=10, pady=3, fill="x")
        self.nav_buttons[name] = btn

    def _clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _open_file(self, path: str):
        try:
            if os.name == 'nt':
                os.startfile(path)
            else:
                import subprocess
                opener = 'open' if sys.platform == 'darwin' else 'xdg-open'
                subprocess.Popen([opener, path])
        except Exception as e:
            logger.error(f"Error opening file {path}: {e}")
            messagebox.showerror("Error", f"Could not open file: {e}")

    def _make_header(self, text: str):
        ctk.CTkLabel(self.content_frame, text=text, font=AppConfig.FONT_HEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=30, pady=20)

    def _make_scrollable_list(self):
        scroll = ctk.CTkScrollableFrame(self.content_frame, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=10)
        return scroll

    # ==================== DASHBOARD ====================
    def show_dashboard(self):
        self._clear_content()
        self._make_header("Dashboard")

        stats_frame = ctk.CTkFrame(self.content_frame, fg_color="#1f1f1f", corner_radius=10)
        stats_frame.pack(fill="x", padx=30, pady=10)

        db_stats = self.db.get_database_stats()
        self._add_stat_card(stats_frame, "Users", str(db_stats.get('users', 0)), "\U0001f465",
                            command=self.show_users)
        self._add_stat_card(stats_frame, "Logs", str(db_stats.get('logs', 0)), "\U0001f4cb",
                            command=self.show_logs)
        self._add_stat_card(stats_frame, "Cameras", str(self.camera_ctrl.get_camera_count()), "\U0001f4f9",
                            command=self.show_camera)
        self._add_stat_card(stats_frame, "Intruders", str(db_stats.get('intruder_logs', 0)), "\U0001f6a8",
                            command=self.show_intruders)

        info_frame = ctk.CTkFrame(self.content_frame, fg_color="#1f1f1f", corner_radius=10)
        info_frame.pack(fill="x", padx=30, pady=10)

        ctk.CTkLabel(info_frame, text="System Information", font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 10))

        admin_status = "Yes" if self.camera_ctrl.registry.is_admin else "No (Limited)"
        cam_status = "Detected" if self.camera_ctrl.has_camera() else "None detected"
        info_text = (
            f"Machine: {SystemInfo.get_machine_name()}\n"
            f"IP: {SystemInfo.get_ip_address()}\n"
            f"OS: {SystemInfo.get_os_version()}\n"
            f"Admin Privileges: {admin_status}\n"
            f"Camera Status: {cam_status}\n"
            f"Time: {DateTimeUtils.get_current_timestamp()}"
        )
        ctk.CTkLabel(info_frame, text=info_text, font=AppConfig.FONT_SMALL,
                     text_color="#aaaaaa", justify="left").pack(anchor="w", padx=20, pady=(0, 15))

    def _add_stat_card(self, parent, title, value, icon, command: Callable = None):
        card = ctk.CTkFrame(parent, fg_color="#2a2a2a", corner_radius=8,
                            cursor="hand2" if command else "")
        card.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        widgets = [card]
        widgets.append(ctk.CTkLabel(card, text=icon, font=("Arial", 24)))
        widgets[-1].pack(pady=(10, 0))
        widgets.append(ctk.CTkLabel(card, text=title, font=AppConfig.FONT_SMALL,
                                    text_color="#888888"))
        widgets[-1].pack(pady=5)
        widgets.append(ctk.CTkLabel(card, text=value, font=AppConfig.FONT_HEADING,
                                    text_color=AppConfig.COLOR_PRIMARY))
        widgets[-1].pack(pady=(0, 10))

        if command:
            for w in widgets:
                w.bind("<Button-1>", lambda e: command())
                w.configure(cursor="hand2")

    def handle_project_info(self):
        try:
            self._clear_content()
            self._make_header("Project Information")

            info = get_project_info()

            scroll = self._make_scrollable_list()

            card = ctk.CTkFrame(scroll, fg_color="#1f1f1f", corner_radius=10)
            card.pack(fill="x", padx=10, pady=5)

            ctk.CTkLabel(card, text=info['project_name'], font=AppConfig.FONT_HEADING,
                         text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 5))
            ctk.CTkLabel(card, text=info['project_description'], font=AppConfig.FONT_NORMAL,
                         text_color="#aaaaaa", justify="left", wraplength=700).pack(
                anchor="w", padx=20, pady=(0, 10))
            ctk.CTkLabel(card, text=f"Company: {info['company_name']}",
                         font=AppConfig.FONT_NORMAL, text_color=AppConfig.COLOR_PRIMARY).pack(
                anchor="w", padx=20, pady=(0, 15))

            ctk.CTkLabel(scroll, text="Development Team", font=AppConfig.FONT_HEADING,
                         text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 5))

            for name, dev_id, email in info['developers']:
                row = ctk.CTkFrame(scroll, fg_color="#1f1f1f", corner_radius=8)
                row.pack(fill="x", padx=10, pady=3)
                ctk.CTkLabel(row, text="\U0001f464", font=("Arial", 20), width=40).pack(
                    side="left", padx=10, pady=10)
                text_col = ctk.CTkFrame(row, fg_color="transparent")
                text_col.pack(side="left", padx=10, pady=10, fill="x", expand=True)
                ctk.CTkLabel(text_col, text=name, font=AppConfig.FONT_NORMAL,
                             text_color=AppConfig.COLOR_TEXT, justify="left").pack(anchor="w")
                ctk.CTkLabel(text_col, text=f"{dev_id}   |   {email}",
                             font=AppConfig.FONT_SMALL, text_color="#888888",
                             justify="left").pack(anchor="w")
        except Exception as e:
            logger.error(f"Error showing project info: {e}")
            messagebox.showerror("Error", f"Could not show project info: {e}")

    # ==================== INTRUDERS ====================
    def show_intruders(self):
        self._clear_content()
        self._make_header("Intruders")

        records = self.db.get_intruder_logs(limit=100)
        if not records:
            ctk.CTkLabel(self.content_frame, text="No intruder events recorded.",
                        font=AppConfig.FONT_NORMAL, text_color="#888888").pack(padx=30, pady=10)
            return

        scroll = self._make_scrollable_list()
        for rec in records:
            row = ctk.CTkFrame(scroll, fg_color="#1f1f1f", corner_radius=8)
            row.pack(fill="x", pady=5, padx=5)

            has_image = bool(rec.get('image_path')) and os.path.exists(rec['image_path'])
            if has_image:
                try:
                    from PIL import Image
                    img = ctk.CTkImage(light_image=Image.open(rec['image_path']),
                                       size=(80, 80))
                    ctk.CTkLabel(row, image=img, text="").pack(side="left", padx=10, pady=10)
                except Exception as e:
                    logger.error(f"Error loading intruder snapshot: {e}")
                    has_image = False
            if not has_image:
                ctk.CTkLabel(row, text="\U0001f6a8", font=("Arial", 32),
                            width=80).pack(side="left", padx=10, pady=10)

            info_text = (
                f"Failed attempts: {rec.get('failed_attempts', 1)}   "
                f"Machine: {rec.get('machine_name', 'Unknown')}   "
                f"IP: {rec.get('ip_address', 'Unknown')}\n"
                f"Last attempt: {rec.get('last_attempt', 'Unknown')}"
            )
            if rec.get('reason'):
                info_text += f"\nReason: {rec['reason']}"
            text_col = ctk.CTkFrame(row, fg_color="transparent")
            text_col.pack(side="left", padx=10, pady=10, fill="x", expand=True)
            ctk.CTkLabel(text_col, text=info_text, font=AppConfig.FONT_SMALL,
                        text_color=AppConfig.COLOR_TEXT, justify="left").pack(anchor="w")

            if rec.get('video_path') and os.path.exists(rec['video_path']):
                vpath = rec['video_path']
                ctk.CTkButton(row, text="Play video", width=90, height=28,
                             font=AppConfig.FONT_SMALL, fg_color="#3a3a3a",
                             hover_color="#4a4a4a",
                             command=lambda p=vpath: self._open_file(p)
                             ).pack(side="right", padx=10)

    # ==================== CAMERA CONTROL ====================
    def show_camera(self):
        self._clear_content()
        self._make_header("Camera Control")

        is_admin = self.camera_ctrl.registry.is_admin
        consent_status = self.camera_ctrl.registry.get_device_status()
        is_enabled = consent_status == "enabled"

        # Webcam consent status card
        status_card = ctk.CTkFrame(self.content_frame, fg_color="#1f1f1f", corner_radius=10)
        status_card.pack(fill="x", padx=30, pady=10)

        ctk.CTkLabel(status_card, text="Webcam Privacy Status", font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 5))

        status_color = AppConfig.COLOR_SUCCESS if is_enabled else AppConfig.COLOR_DANGER
        status_text = "ALLOWED (Camera is accessible by apps)" if is_enabled else "DENIED (Camera is blocked for all apps)"
        ctk.CTkLabel(status_card, text=f"Consent: {status_text}", font=AppConfig.FONT_NORMAL,
                     text_color=status_color).pack(anchor="w", padx=20, pady=5)

        ctk.CTkLabel(status_card, text="Registry: HKLM\\...\\CapabilityAccessManager\\ConsentStore\\webcam",
                     font=AppConfig.FONT_SMALL, text_color="#888888").pack(anchor="w", padx=20, pady=(0, 15))

        # Control buttons
        btn_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=30, pady=10)

        btn_state = "normal" if is_admin else "disabled"

        if is_enabled:
            ctk.CTkButton(btn_frame, text="Disable Webcam (Block All Apps)",
                          font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_DANGER,
                          corner_radius=8, height=40,
                          state=btn_state,
                          command=self._disable_all_cameras).pack(side="left", padx=5)
        else:
            ctk.CTkButton(btn_frame, text="Enable Webcam (Allow Apps)",
                          font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_SUCCESS,
                          corner_radius=8, height=40,
                          state=btn_state,
                          command=self._enable_all_cameras).pack(side="left", padx=5)

        if not is_admin:
            info_card = ctk.CTkFrame(self.content_frame, fg_color="#332200", corner_radius=10)
            info_card.pack(fill="x", padx=30, pady=10)
            ctk.CTkLabel(info_card, text="Admin privileges required to change webcam settings.\n"
                         "Please restart the application as administrator.",
                         font=AppConfig.FONT_SMALL,
                         text_color=AppConfig.COLOR_WARNING).pack(padx=15, pady=10)

        # Detected cameras
        self.camera_ctrl.refresh_camera_devices()
        devices = self.camera_ctrl.get_camera_devices()

        ctk.CTkLabel(self.content_frame, text=f"Detected Cameras ({len(devices)})",
                     font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=30, pady=(15, 5))

        if not devices:
            msg_card = ctk.CTkFrame(self.content_frame, fg_color="#2a2a2a", corner_radius=10)
            msg_card.pack(fill="x", padx=30, pady=5)
            ctk.CTkLabel(msg_card, text="No camera devices detected.",
                         font=AppConfig.FONT_NORMAL,
                         text_color="#888888").pack(padx=20, pady=15)
        else:
            scroll = self._make_scrollable_list()
            for device in devices:
                card = ctk.CTkFrame(scroll, fg_color="#2a2a2a", corner_radius=8)
                card.pack(fill="x", padx=10, pady=3)
                name = device.get('friendly_name', 'Unknown Camera')
                desc = device.get('device_desc', '')
                ctk.CTkLabel(card, text=f"  {name}  |  {desc}",
                             font=AppConfig.FONT_SMALL, text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=10, pady=8)

    def _add_camera_card(self, parent, device, is_admin=True):
        card = ctk.CTkFrame(parent, fg_color="#2a2a2a", corner_radius=10)
        card.pack(fill="x", padx=10, pady=5)

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(fill="x", padx=15, pady=10)

        name = device.get('friendly_name', 'Unknown Camera')
        dev_id = device.get('device_id', 'N/A')
        status = self.camera_ctrl.registry.get_device_status(dev_id)
        is_enabled = status == "enabled"

        ctk.CTkLabel(info_frame, text=name, font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w")
        ctk.CTkLabel(info_frame, text=f"ID: {dev_id}",
                     font=AppConfig.FONT_SMALL, text_color="#888888").pack(anchor="w")

        status_color = AppConfig.COLOR_SUCCESS if is_enabled else AppConfig.COLOR_DANGER
        status_text = "ENABLED" if is_enabled else "DISABLED"
        ctk.CTkLabel(info_frame, text=f"Status: {status_text}", font=AppConfig.FONT_SMALL,
                     text_color=status_color).pack(anchor="w")

        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=(0, 10))

        btn_state = "normal" if is_admin else "disabled"
        if is_enabled:
            ctk.CTkButton(btn_frame, text="Disable", font=AppConfig.FONT_SMALL,
                          fg_color=AppConfig.COLOR_DANGER, corner_radius=8, height=30, width=100,
                          state=btn_state,
                          command=lambda d=dev_id: self._toggle_camera(d, False)
                          ).pack(side="right")
        else:
            ctk.CTkButton(btn_frame, text="Enable", font=AppConfig.FONT_SMALL,
                          fg_color=AppConfig.COLOR_SUCCESS, corner_radius=8, height=30, width=100,
                          state=btn_state,
                          command=lambda d=dev_id: self._toggle_camera(d, True)
                          ).pack(side="right")

    def _refresh_cameras(self):
        count = self.camera_ctrl.refresh_camera_devices()
        messagebox.showinfo("Refresh", f"Found {count} camera(s)")
        self.show_camera()

    def _toggle_camera(self, device_id, enable):
        def proceed():
            if enable:
                success, msg = self.camera_ctrl.enable_specific_camera(
                    device_id, self.user['user_id'], self.user['username'])
            else:
                success, msg = self.camera_ctrl.disable_specific_camera(
                    device_id, self.user['user_id'], self.user['username'])
            if success:
                self.show_camera()
            else:
                messagebox.showerror("Error", msg)

        label = "Enable Camera" if enable else "Disable Camera"
        CameraAccessDialog(self, self.auth, self.face_mgr, self.db, self.user, label, proceed)

    def _handle_schedule_action(self, action: str, schedule_name: str):
        """
        Callback invoked by Scheduler's background thread when a schedule's
        time window is active. This is what makes schedules actually do
        something - previously the scheduler ran but had no callback wired
        in, so it only ever logged that it "would" act.
        Runs on the scheduler's background thread, not the GUI thread, so
        this only touches camera_ctrl/db (thread-safe-ish, no widget access)
        rather than any tkinter widgets directly.
        """
        try:
            if action == 'disable':
                success, msg = self.camera_ctrl.disable_all_cameras(
                    self.user['user_id'], self.user['username'])
            elif action == 'enable':
                success, msg = self.camera_ctrl.enable_all_cameras(
                    self.user['user_id'], self.user['username'])
            else:
                logger.warning(f"Unknown schedule action: {action}")
                return

            self.db.add_log(
                self.user['user_id'], self.user['username'], 'schedule_executed', 'info',
                f"Schedule '{schedule_name}' triggered camera {action} - {msg}",
                SystemInfo.get_ip_address(), SystemInfo.get_machine_name()
            )
            logger.info(f"Schedule '{schedule_name}' executed: {action} - {msg}")
        except Exception as e:
            logger.error(f"Error executing schedule action '{action}': {e}", exc_info=True)

    def _disable_all_cameras(self):
        def proceed():
            success, msg = self.camera_ctrl.disable_all_cameras(
                self.user['user_id'], self.user['username'])
            messagebox.showinfo("Camera Control", msg)
            self.show_camera()

        CameraAccessDialog(self, self.auth, self.face_mgr, self.db, self.user,
                           "Disable Webcam (Block All Apps)", proceed)

    def _enable_all_cameras(self):
        def proceed():
            success, msg = self.camera_ctrl.enable_all_cameras(
                self.user['user_id'], self.user['username'])
            messagebox.showinfo("Camera Control", msg)
            self.show_camera()

        CameraAccessDialog(self, self.auth, self.face_mgr, self.db, self.user,
                           "Enable Webcam (Allow Apps)", proceed)

    # ==================== FACE RECOGNITION ====================
    def show_face(self):
        self._clear_content()
        self._make_header("Face Recognition")

        self._face_stop_event = threading.Event()

        top_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=30, pady=10)

        ctk.CTkButton(top_frame, text="Register Face (Camera)", command=self._register_face_camera,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_PRIMARY,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Register Face (File)", command=self._register_face_file,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_PRIMARY,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Live Recognition", command=self._live_face_recognition,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_SUCCESS,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Verify Face (File)", command=self._verify_face_file,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_WARNING,
                      corner_radius=8, height=35).pack(side="left", padx=5)

        stats = self.face_mgr.get_face_statistics()
        stats_card = ctk.CTkFrame(self.content_frame, fg_color="#1f1f1f", corner_radius=10)
        stats_card.pack(fill="x", padx=30, pady=10)

        ctk.CTkLabel(stats_card, text="Face Recognition Statistics", font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 5))

        for key, value in stats.items():
            ctk.CTkLabel(stats_card, text=f"  {key}: {value}", font=AppConfig.FONT_SMALL,
                         text_color="#aaaaaa").pack(anchor="w", padx=20, pady=1)
        ctk.CTkFrame(stats_card, fg_color="transparent", height=10).pack()

        ctk.CTkLabel(self.content_frame, text="Registered Faces", font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=30, pady=(15, 5))

        scroll = self._make_scrollable_list()
        registered = self.face_mgr.get_all_registered_faces()

        if registered:
            for uid, fdata in registered.items():
                card = ctk.CTkFrame(scroll, fg_color="#2a2a2a", corner_radius=8)
                card.pack(fill="x", padx=10, pady=3)
                ctk.CTkLabel(card, text=f"  User: {fdata.get('username', uid)}  |  Registered: {fdata.get('registered_at', 'N/A')}",
                             font=AppConfig.FONT_SMALL, text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=10, pady=8)
        else:
            ctk.CTkLabel(scroll, text="No faces registered yet. Register via Camera or File above.",
                         font=AppConfig.FONT_NORMAL,
                         text_color="#888888").pack(padx=20, pady=20)

    def _register_face_camera(self):
        import cv2
        from PIL import Image, ImageTk

        self._face_stop_event = threading.Event()
        self._clear_content()
        self._make_header("Register Face (Camera)")

        status_label = ctk.CTkLabel(self.content_frame,
                                     text="Camera opening... Look at the camera.",
                                     font=AppConfig.FONT_NORMAL, text_color=AppConfig.COLOR_WARNING)
        status_label.pack(padx=30, pady=5)

        camera_frame = ctk.CTkFrame(self.content_frame, fg_color="#000000", corner_radius=10)
        camera_frame.pack(padx=30, pady=5, fill="both", expand=True)

        camera_label = ctk.CTkLabel(camera_frame, text="")
        camera_label.pack(expand=True, fill="both")

        btn_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        btn_frame.pack(padx=30, pady=10)

        capture_btn = ctk.CTkButton(btn_frame, text="Capture Face",
                                     font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_SUCCESS,
                                     corner_radius=8, height=35, state="disabled")
        capture_btn.pack(side="left", padx=5)

        stop_btn = ctk.CTkButton(btn_frame, text="Back",
                                  font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_DANGER,
                                  corner_radius=8, height=35,
                                  command=lambda: [self._face_stop_event.set(), self.show_face()])
        stop_btn.pack(side="left", padx=5)

        def camera_thread():
            cap = None
            try:
                cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                if not cap.isOpened():
                    cap = cv2.VideoCapture(0)
                if not cap.isOpened():
                    self.after(0, lambda: status_label.configure(text="Failed to open camera"))
                    return

                self.after(0, lambda: status_label.configure(
                    text="Camera active. Position your face in frame, then click 'Capture Face'."))

                captured_frame = [None]

                def on_capture():
                    if captured_frame[0] is not None:
                        self._face_stop_event.set()

                self.after(0, lambda: capture_btn.configure(state="normal", command=on_capture))

                while not self._face_stop_event.is_set():
                    ret, frame = cap.read()
                    if not ret:
                        continue

                    display = frame.copy()
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    faces = self.face_mgr._face_cascade.detectMultiScale(gray, 1.3, 5)
                    for (fx, fy, fw, fh) in faces:
                        cv2.rectangle(display, (fx, fy), (fx+fw, fy+fh), (0, 255, 0), 2)
                        cv2.putText(display, "Face", (fx, fy-10),
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)

                    if not self._face_stop_event.is_set():
                        captured_frame[0] = frame.copy()

                    rgb = cv2.cvtColor(display, cv2.COLOR_BGR2RGB)
                    img = Image.fromarray(rgb)
                    img = img.resize((640, 360), Image.LANCZOS)
                    ctk_img = ImageTk.PhotoImage(img)

                    def update_label(image=ctk_img):
                        camera_label.configure(image=image, text="")
                        camera_label._image = image
                    self.after(0, update_label)

                cap.release()
                cap = None

                if captured_frame[0] is not None:
                    rgb_frame = cv2.cvtColor(captured_frame[0], cv2.COLOR_BGR2RGB)
                    success, msg = self.face_mgr.register_face(
                        self.user['user_id'], image=rgb_frame, username=self.user['username'])
                    self.after(0, lambda: [
                        status_label.configure(text=msg),
                        self.show_face() if success else None
                    ])
                else:
                    self.after(0, lambda: status_label.configure(text="Camera stopped."))

            except Exception as e:
                self.after(0, lambda: status_label.configure(text=f"Error: {e}"))
            finally:
                if cap is not None:
                    cap.release()

        threading.Thread(target=camera_thread, daemon=True).start()

    def _register_face_file(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(
            title="Select Face Image",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
        )
        if not file_path:
            return
        success, msg = self.face_mgr.register_face(
            self.user['user_id'], image_path=file_path, username=self.user['username'])
        messagebox.showinfo("Face Registration", msg)
        self.show_face()

    def _live_face_recognition(self):
        import cv2
        from PIL import Image, ImageTk

        self._face_stop_event = threading.Event()
        self._clear_content()
        self._make_header("Live Face Recognition")

        status_label = ctk.CTkLabel(self.content_frame,
                                     text="Starting live recognition...",
                                     font=AppConfig.FONT_NORMAL, text_color=AppConfig.COLOR_SUCCESS)
        status_label.pack(padx=30, pady=5)

        camera_frame = ctk.CTkFrame(self.content_frame, fg_color="#000000", corner_radius=10)
        camera_frame.pack(padx=30, pady=5, fill="both", expand=True)

        camera_label = ctk.CTkLabel(camera_frame, text="")
        camera_label.pack(expand=True, fill="both")

        result_label = ctk.CTkLabel(self.content_frame,
                                     text="",
                                     font=AppConfig.FONT_HEADING, text_color=AppConfig.COLOR_TEXT)
        result_label.pack(padx=30, pady=5)

        btn_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        btn_frame.pack(padx=30, pady=10)

        stop_btn = ctk.CTkButton(btn_frame, text="Stop & Back",
                                  font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_DANGER,
                                  corner_radius=8, height=35,
                                  command=lambda: [self._face_stop_event.set(), self.show_face()])
        stop_btn.pack(side="left", padx=5)

        def live_thread():
            cap = None
            try:
                cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                if not cap.isOpened():
                    cap = cv2.VideoCapture(0)
                if not cap.isOpened():
                    self.after(0, lambda: status_label.configure(text="Failed to open camera"))
                    return

                registered_faces = self.face_mgr.get_all_registered_faces()
                encodings = {}
                for uid, fdata in registered_faces.items():
                    enc = self.face_mgr.decode_string_to_encoding(fdata.get('encoding', ''))
                    if enc is not None:
                        encodings[uid] = {'encoding': enc, 'username': fdata.get('username', f'User {uid}')}

                self.after(0, lambda: status_label.configure(
                    text=f"Live recognition active. {len(encodings)} face(s) registered. Click 'Stop' to end."))

                while not self._face_stop_event.is_set():
                    ret, frame = cap.read()
                    if not ret:
                        continue

                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    faces = self.face_mgr._face_cascade.detectMultiScale(gray, 1.3, 5)

                    identified_names = []

                    for (fx, fy, fw, fh) in faces:
                        face_encoding = self.face_mgr.get_face_encoding(
                            cv2.cvtColor(frame, cv2.COLOR_BGR2RGB),
                            (fy, fx+fw, fy+fh, fx)
                        )

                        name = "Unknown"
                        color = (0, 0, 255)

                        if face_encoding is not None and encodings:
                            best_match = None
                            best_dist = 1.0
                            for uid, edata in encodings.items():
                                dist = self.face_mgr.compare_faces(edata['encoding'], face_encoding)
                                logger.debug(f"Face comparison: {edata['username']} dist={dist:.4f}")
                                if dist < best_dist:
                                    best_dist = dist
                                    best_match = edata['username']

                            if best_match and best_dist <= self.face_mgr.TOLERANCE:
                                name = best_match
                                color = (0, 255, 0)

                        if name != "Unknown":
                            identified_names.append(name)

                        cv2.rectangle(frame, (fx, fy), (fx+fw, fy+fh), color, 2)
                        cv2.putText(frame, name, (fx, fy-10),
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, color, 2)

                    if identified_names:
                        text = f"Identified: {', '.join(set(identified_names))}"
                        self.after(0, lambda t=text: result_label.configure(
                            text=t, text_color="#00ff00"))
                    else:
                        self.after(0, lambda: result_label.configure(
                            text="No registered faces detected", text_color="#ff4444"))

                    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    img = Image.fromarray(rgb)
                    img = img.resize((640, 360), Image.LANCZOS)
                    ctk_img = ImageTk.PhotoImage(img)

                    def update_label(image=ctk_img):
                        camera_label.configure(image=image, text="")
                        camera_label._image = image
                    self.after(0, update_label)

            except Exception as e:
                self.after(0, lambda: status_label.configure(text=f"Error: {e}"))
            finally:
                if cap is not None:
                    cap.release()
                self.after(0, lambda: status_label.configure(text="Recognition stopped."))

        threading.Thread(target=live_thread, daemon=True).start()

    def _verify_face_file(self):
        from tkinter import filedialog

    def _verify_face_file(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(
            title="Select Image to Verify",
            filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp")]
        )
        if not file_path:
            return
        verified, confidence, msg = self.face_mgr.verify_face(
            self.user['user_id'], image_path=file_path, username=self.user['username'])
        detail = f"{msg}\nConfidence: {confidence:.1%}"
        if verified:
            messagebox.showinfo("Face Verification", detail)
        else:
            messagebox.showwarning("Face Verification", detail)

    # ==================== ACTIVITY LOGS ====================
    def show_logs(self):
        PasswordGateDialog(self, self.auth, self.face_mgr, self.db, self.user,
                           "View Activity Logs", self._render_logs)

    def _render_logs(self):
        self._clear_content()
        self._make_header("Activity Logs")

        top_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=30, pady=10)

        ctk.CTkButton(top_frame, text="Refresh", command=self._render_logs,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_PRIMARY,
                      corner_radius=8, height=30).pack(side="left", padx=5)

        if self.user['role'] == 'admin':
            ctk.CTkButton(top_frame, text="Export JSON", command=self._export_logs_json,
                          font=AppConfig.FONT_SMALL, fg_color="#2a2a2a",
                          corner_radius=8, height=30).pack(side="left", padx=5)
            ctk.CTkButton(top_frame, text="Export CSV", command=self._export_logs_csv,
                          font=AppConfig.FONT_SMALL, fg_color="#2a2a2a",
                          corner_radius=8, height=30).pack(side="left", padx=5)

        if self.user['role'] == 'admin':
            logs = self.db.get_all_logs(limit=100)
        else:
            logs = self.db.get_logs_by_user(self.user['user_id'], limit=100)

        scroll = self._make_scrollable_list()

        if logs:
            for log in logs:
                severity = log.get('severity', 'info')
                sev_color = AppConfig.COLOR_DANGER if severity == 'critical' else \
                    AppConfig.COLOR_WARNING if severity == 'warning' else \
                    AppConfig.COLOR_TEXT

                log_text = f"[{severity.upper()}] {log.get('action', 'N/A')} - {log.get('details', '')} ({log.get('timestamp', '')})"
                ctk.CTkLabel(scroll, text=log_text, font=AppConfig.FONT_SMALL,
                             text_color=sev_color, anchor="w", wraplength=900,
                             justify="left").pack(anchor="w", padx=10, pady=2)
        else:
            ctk.CTkLabel(scroll, text="No activity logs found.",
                         font=AppConfig.FONT_NORMAL, text_color="#888888").pack(padx=20, pady=20)

    def _export_logs_json(self):
        path = self.log_mgr.export_logs_json(
            os.path.join("reports", f"logs_export_{DateTimeUtils.get_current_date()}.json"))
        if path:
            messagebox.showinfo("Export", f"Logs exported to {path}")
        else:
            messagebox.showerror("Export", "Failed to export logs")

    def _export_logs_csv(self):
        path = self.log_mgr.export_logs_csv(
            os.path.join("reports", f"logs_export_{DateTimeUtils.get_current_date()}.csv"))
        if path:
            messagebox.showinfo("Export", f"Logs exported to {path}")
        else:
            messagebox.showerror("Export", "Failed to export logs")

    # ==================== REPORTS ====================
    def show_reports(self):
        self._clear_content()
        self._make_header("Report Generation")

        top_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=30, pady=10)

        ctk.CTkButton(top_frame, text="Activity Report (JSON)", command=lambda: self._gen_report("activity", "json"),
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_PRIMARY,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Security Report (JSON)", command=lambda: self._gen_report("security", "json"),
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_WARNING,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Summary Report (JSON)", command=lambda: self._gen_report("summary", "json"),
                      font=AppConfig.FONT_SMALL, fg_color="#2a2a2a",
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Audit Report (JSON)", command=lambda: self._gen_report("audit", "json"),
                      font=AppConfig.FONT_SMALL, fg_color="#2a2a2a",
                      corner_radius=8, height=35).pack(side="left", padx=5)

        ctk.CTkButton(top_frame, text="Activity Report (PDF)", command=lambda: self._gen_report("activity", "pdf"),
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_DANGER,
                      corner_radius=8, height=35).pack(side="left", padx=5)

        existing = os.listdir("reports") if os.path.exists("reports") else []
        if existing:
            ctk.CTkLabel(self.content_frame, text="Generated Reports", font=AppConfig.FONT_SUBHEADING,
                         text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=30, pady=(20, 5))

            scroll = self._make_scrollable_list()
            for fname in sorted(existing, reverse=True):
                card = ctk.CTkFrame(scroll, fg_color="#2a2a2a", corner_radius=8)
                card.pack(fill="x", padx=10, pady=2)
                ctk.CTkLabel(card, text=f"  {fname}", font=AppConfig.FONT_SMALL,
                             text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=10, pady=6)
        else:
            ctk.CTkLabel(self.content_frame, text="No reports generated yet. Click a button above.",
                         font=AppConfig.FONT_NORMAL, text_color="#888888").pack(padx=30, pady=30)

    def _gen_report(self, report_type, fmt):
        try:
            if report_type == "activity":
                report = self.report_gen.generate_activity_report()
            elif report_type == "security":
                report = self.report_gen.generate_security_report()
            elif report_type == "summary":
                report = self.report_gen.generate_summary_report()
            elif report_type == "audit":
                report = self.report_gen.generate_audit_report(user_id=self.user['user_id'])
            else:
                return

            if fmt == "json":
                path = self.report_gen.export_report_json(report)
            elif fmt == "pdf":
                path = self.report_gen.export_report_pdf(report)
            elif fmt == "csv":
                path = self.report_gen.export_report_csv(report)
            else:
                return

            if path:
                messagebox.showinfo("Report", f"Report generated:\n{path}")
            else:
                messagebox.showwarning("Report", "Report generation returned no file")
        except Exception as e:
            messagebox.showerror("Report Error", str(e))

    # ==================== USER MANAGEMENT (ADMIN) ====================
    def show_users(self):
        self._clear_content()
        if self.user['role'] != 'admin':
            self._make_header("Access Denied")
            ctk.CTkLabel(self.content_frame, text="Admin privileges required.",
                         font=AppConfig.FONT_NORMAL, text_color=AppConfig.COLOR_DANGER).pack(padx=30)
            return

        self._make_header("User Management")

        top_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=30, pady=10)
        ctk.CTkButton(top_frame, text="Create User", command=self._create_user_dialog,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_PRIMARY,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Refresh", command=self.show_users,
                      font=AppConfig.FONT_SMALL, fg_color="#2a2a2a",
                      corner_radius=8, height=35).pack(side="left", padx=5)

        success, users = self.auth.get_all_users(self.user['user_id'])
        if not users:
            ctk.CTkLabel(self.content_frame, text="No users found.",
                         font=AppConfig.FONT_NORMAL, text_color="#888888").pack(padx=30, pady=30)
            return

        scroll = self._make_scrollable_list()

        for u in users:
            card = ctk.CTkFrame(scroll, fg_color="#2a2a2a", corner_radius=8)
            card.pack(fill="x", padx=10, pady=3)

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(fill="x", padx=15, pady=8)

            active_color = AppConfig.COLOR_SUCCESS if u.get('is_active') else AppConfig.COLOR_DANGER
            active_text = "Active" if u.get('is_active') else "Inactive"

            ctk.CTkLabel(info, text=f"{u.get('username', 'N/A')}",
                         font=AppConfig.FONT_SUBHEADING, text_color=AppConfig.COLOR_TEXT).pack(anchor="w")
            ctk.CTkLabel(info, text=f"Email: {u.get('email', 'N/A')}  |  Role: {u.get('role', 'N/A')}  |  {active_text}",
                         font=AppConfig.FONT_SMALL, text_color="#aaaaaa").pack(anchor="w")

            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.pack(fill="x", padx=15, pady=(0, 8))

            if u.get('user_id') != self.user['user_id']:
                if u.get('is_active'):
                    ctk.CTkButton(btn_frame, text="Deactivate", font=AppConfig.FONT_SMALL,
                                  fg_color=AppConfig.COLOR_DANGER, corner_radius=8, height=28, width=90,
                                  command=lambda uid=u['user_id']: self._deactivate_user(uid)).pack(side="right", padx=3)
                else:
                    ctk.CTkButton(btn_frame, text="Activate", font=AppConfig.FONT_SMALL,
                                  fg_color=AppConfig.COLOR_SUCCESS, corner_radius=8, height=28, width=90,
                                  command=lambda uid=u['user_id']: self._activate_user(uid)).pack(side="right", padx=3)
            else:
                ctk.CTkLabel(btn_frame, text="(You)", font=AppConfig.FONT_SMALL,
                             text_color="#666666").pack(side="right")

    def _create_user_dialog(self):
        CreateUserDialog(self, self.auth, self.user, self.show_users)

    def _deactivate_user(self, user_id):
        success, msg = self.user_mgr.deactivate_user(user_id, self.user['user_id'])
        messagebox.showinfo("Deactivate", msg)
        self.show_users()

    def _activate_user(self, user_id):
        success, msg = self.user_mgr.activate_user(user_id, self.user['user_id'])
        messagebox.showinfo("Activate", msg)
        self.show_users()

    # ==================== POLICY MANAGEMENT (ADMIN) ====================
    def show_policies(self):
        self._clear_content()
        if self.user['role'] != 'admin':
            self._make_header("Access Denied")
            ctk.CTkLabel(self.content_frame, text="Admin privileges required.",
                         font=AppConfig.FONT_NORMAL, text_color=AppConfig.COLOR_DANGER).pack(padx=30)
            return

        self._make_header("Policy Management")

        top_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=30, pady=10)
        ctk.CTkButton(top_frame, text="Create Policy", command=self._create_policy_dialog,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_PRIMARY,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Refresh", command=self.show_policies,
                      font=AppConfig.FONT_SMALL, fg_color="#2a2a2a",
                      corner_radius=8, height=35).pack(side="left", padx=5)

        policies = self.policy_mgr.get_all_policies()
        if not policies:
            ctk.CTkLabel(self.content_frame, text="No policies configured.",
                         font=AppConfig.FONT_NORMAL, text_color="#888888").pack(padx=30, pady=30)
            return

        scroll = self._make_scrollable_list()

        for p in policies:
            card = ctk.CTkFrame(scroll, fg_color="#2a2a2a", corner_radius=8)
            card.pack(fill="x", padx=10, pady=3)

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(fill="x", padx=15, pady=8)

            type_color = AppConfig.COLOR_SUCCESS if p.get('policy_type') == 'allow' else AppConfig.COLOR_DANGER
            enabled_text = "Enabled" if p.get('enabled') else "Disabled"
            time_text = f"  |  {p.get('start_time', 'N/A')}-{p.get('end_time', 'N/A')}" if p.get('start_time') else ""

            ctk.CTkLabel(info, text=f"{p.get('name', 'N/A')}",
                         font=AppConfig.FONT_SUBHEADING, text_color=AppConfig.COLOR_TEXT).pack(anchor="w")
            ctk.CTkLabel(info,
                         text=f"Type: {p.get('policy_type', 'N/A').upper()}  |  Scope: {p.get('scope', 'N/A')}  |  {enabled_text}{time_text}",
                         font=AppConfig.FONT_SMALL, text_color="#aaaaaa").pack(anchor="w")
            if p.get('description'):
                ctk.CTkLabel(info, text=f"  {p['description']}", font=AppConfig.FONT_SMALL,
                             text_color="#777777").pack(anchor="w")

            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.pack(fill="x", padx=15, pady=(0, 8))

            pid = p.get('policy_id')
            if p.get('enabled'):
                ctk.CTkButton(btn_frame, text="Disable", font=AppConfig.FONT_SMALL,
                              fg_color=AppConfig.COLOR_WARNING, corner_radius=8, height=28, width=80,
                              command=lambda i=pid: self._toggle_policy(i, False)).pack(side="right", padx=3)
            else:
                ctk.CTkButton(btn_frame, text="Enable", font=AppConfig.FONT_SMALL,
                              fg_color=AppConfig.COLOR_SUCCESS, corner_radius=8, height=28, width=80,
                              command=lambda i=pid: self._toggle_policy(i, True)).pack(side="right", padx=3)
            ctk.CTkButton(btn_frame, text="Delete", font=AppConfig.FONT_SMALL,
                          fg_color=AppConfig.COLOR_DANGER, corner_radius=8, height=28, width=80,
                          command=lambda i=pid: self._delete_policy(i)).pack(side="right", padx=3)

    def _create_policy_dialog(self):
        CreatePolicyDialog(self, self.policy_mgr, self.show_policies)

    def _toggle_policy(self, policy_id, enable):
        self.policy_mgr.update_policy(policy_id, enabled=enable)
        self.show_policies()

    def _delete_policy(self, policy_id):
        if messagebox.askyesno("Delete Policy", "Are you sure you want to delete this policy?"):
            self.policy_mgr.delete_policy(policy_id)
            self.show_policies()

    # ==================== SCHEDULE MANAGEMENT (ADMIN) ====================
    def show_schedules(self):
        self._clear_content()
        if self.user['role'] != 'admin':
            self._make_header("Access Denied")
            return

        self._make_header("Schedule Management")

        top_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        top_frame.pack(fill="x", padx=30, pady=10)
        ctk.CTkButton(top_frame, text="Create Schedule", command=self._create_schedule_dialog,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_PRIMARY,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Start Scheduler", command=self._start_scheduler,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_SUCCESS,
                      corner_radius=8, height=35).pack(side="left", padx=5)
        ctk.CTkButton(top_frame, text="Stop Scheduler", command=self._stop_scheduler,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_DANGER,
                      corner_radius=8, height=35).pack(side="left", padx=5)

        stats = self.scheduler.get_schedule_statistics()
        stats_text = f"Total: {stats.get('total_schedules', 0)}  |  Active: {stats.get('active_schedules', 0)}  |  Running: {stats.get('scheduler_running', False)}"
        ctk.CTkLabel(self.content_frame, text=stats_text, font=AppConfig.FONT_SMALL,
                     text_color="#aaaaaa").pack(anchor="w", padx=30, pady=5)

        schedules = self.scheduler.get_all_schedules()
        if not schedules:
            ctk.CTkLabel(self.content_frame, text="No schedules configured.",
                         font=AppConfig.FONT_NORMAL, text_color="#888888").pack(padx=30, pady=30)
            return

        scroll = self._make_scrollable_list()

        for s in schedules:
            card = ctk.CTkFrame(scroll, fg_color="#2a2a2a", corner_radius=8)
            card.pack(fill="x", padx=10, pady=3)

            active_text = "Active" if s.get('is_active') else "Inactive"

            info_text = (f"Schedule #{s.get('schedule_id', 'N/A')}  |  "
                         f"{s.get('start_time', 'N/A')} - {s.get('end_time', 'N/A')}  |  "
                         f"Action: {s.get('action', 'N/A').upper()}  |  "
                         f"Recurrence: {s.get('recurrence', 'N/A')}  |  {active_text}")

            ctk.CTkLabel(card, text=info_text, font=AppConfig.FONT_SMALL,
                         text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=15, pady=10)

            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.pack(fill="x", padx=15, pady=(0, 8))

            sid = s.get('schedule_id')
            if s.get('is_active'):
                ctk.CTkButton(btn_frame, text="Disable", font=AppConfig.FONT_SMALL,
                              fg_color=AppConfig.COLOR_WARNING, corner_radius=8, height=28, width=80,
                              command=lambda i=sid: self._toggle_schedule(i, False)).pack(side="right", padx=3)
            else:
                ctk.CTkButton(btn_frame, text="Enable", font=AppConfig.FONT_SMALL,
                              fg_color=AppConfig.COLOR_SUCCESS, corner_radius=8, height=28, width=80,
                              command=lambda i=sid: self._toggle_schedule(i, True)).pack(side="right", padx=3)

    def _create_schedule_dialog(self):
        CreateScheduleDialog(self, self.scheduler, self.user, self.show_schedules)

    def _toggle_schedule(self, sid, enable):
        self.scheduler.update_schedule(sid, is_active=enable)
        self.show_schedules()

    def _start_scheduler(self):
        self.scheduler.start()
        messagebox.showinfo("Scheduler", "Background scheduler started")

    def _stop_scheduler(self):
        self.scheduler.stop()
        messagebox.showinfo("Scheduler", "Background scheduler stopped")

    # ==================== SETTINGS ====================
    def show_settings(self):
        self._clear_content()
        self._make_header("Settings")

        card = ctk.CTkFrame(self.content_frame, fg_color="#1f1f1f", corner_radius=10)
        card.pack(fill="x", padx=30, pady=10)

        ctk.CTkLabel(card, text="Change Password", font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 10))

        ctk.CTkButton(card, text="Change Password", command=self._change_password_dialog,
                      font=AppConfig.FONT_SMALL, fg_color=AppConfig.COLOR_PRIMARY,
                      corner_radius=8, height=35, width=200).pack(anchor="w", padx=20, pady=(0, 15))

        info_card = ctk.CTkFrame(self.content_frame, fg_color="#1f1f1f", corner_radius=10)
        info_card.pack(fill="x", padx=30, pady=10)

        ctk.CTkLabel(info_card, text="Application Info", font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 10))

        info_lines = [
            f"Version: 1.0",
            f"Python: {SystemInfo.get_python_version()}",
            f"OS: {SystemInfo.get_os_version()}",
            f"Machine: {SystemInfo.get_machine_name()}",
            f"Admin: {'Yes' if self.camera_ctrl.registry.is_admin else 'No'}",
        ]
        for line in info_lines:
            ctk.CTkLabel(info_card, text=line, font=AppConfig.FONT_SMALL,
                         text_color="#aaaaaa").pack(anchor="w", padx=20, pady=2)

        ctk.CTkFrame(info_card, fg_color="transparent", height=10).pack()

        db_card = ctk.CTkFrame(self.content_frame, fg_color="#1f1f1f", corner_radius=10)
        db_card.pack(fill="x", padx=30, pady=10)

        ctk.CTkLabel(db_card, text="Database", font=AppConfig.FONT_SUBHEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(15, 10))

        stats = self.db.get_database_stats()
        for table, count in stats.items():
            ctk.CTkLabel(db_card, text=f"  {table}: {count} records", font=AppConfig.FONT_SMALL,
                         text_color="#aaaaaa").pack(anchor="w", padx=20, pady=1)

        ctk.CTkFrame(db_card, fg_color="transparent", height=5).pack()

        ctk.CTkButton(db_card, text="Backup Database", command=self._backup_database,
                      font=AppConfig.FONT_SMALL, fg_color="#2a2a2a",
                      corner_radius=8, height=35, width=180).pack(anchor="w", padx=20, pady=(0, 15))

    def _change_password_dialog(self):
        ChangePasswordDialog(self, self.auth, self.user)

    def _backup_database(self):
        try:
            path = self.db.backup_database()
            messagebox.showinfo("Backup", f"Database backed up to:\n{path}")
        except Exception as e:
            messagebox.showerror("Backup Error", str(e))

    # ==================== LOGOUT ====================
    def handle_logout(self):
        self.scheduler.stop()
        self.on_logout()


# ==================== DIALOG CLASSES ====================


class CreateUserDialog(ctk.CTkToplevel):
    def __init__(self, parent, auth, admin_user, refresh_callback):
        super().__init__(parent)
        self.auth = auth
        self.admin_user = admin_user
        self.refresh_callback = refresh_callback
        self.title("Create User")
        self.geometry("420x420")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)
        self.transient(parent)
        self.grab_set()
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(self, text="Create New User", font=AppConfig.FONT_HEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(pady=15)

        card = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=5, fill="both", expand=True)

        ctk.CTkLabel(card, text="Username", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(12, 3))
        self.username_entry = ctk.CTkEntry(card, font=AppConfig.FONT_NORMAL, height=33, corner_radius=8)
        self.username_entry.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkLabel(card, text="Email", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 3))
        self.email_entry = ctk.CTkEntry(card, font=AppConfig.FONT_NORMAL, height=33, corner_radius=8)
        self.email_entry.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkLabel(card, text="Password", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 3))
        self.pass_entry = ctk.CTkEntry(card, show="*", font=AppConfig.FONT_NORMAL, height=33, corner_radius=8)
        self.pass_entry.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkLabel(card, text="Role", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 3))
        self.role_var = ctk.StringVar(value="employee")
        ctk.CTkOptionMenu(card, variable=self.role_var, values=["employee", "admin"],
                          height=33, corner_radius=8).pack(fill="x", padx=20, pady=(0, 12))

        ctk.CTkButton(card, text="Create", command=self._handle_create,
                      fg_color=AppConfig.COLOR_PRIMARY, height=38, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkButton(card, text="Cancel", command=self.destroy,
                      fg_color="transparent", hover_color="#333333",
                      text_color="#888888", height=28, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 12))

        self.status_label = ctk.CTkLabel(card, text="", font=AppConfig.FONT_SMALL,
                                         text_color=AppConfig.COLOR_DANGER)
        self.status_label.pack(pady=(0, 5))

    def _handle_create(self):
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.pass_entry.get()
        role = self.role_var.get()

        if not username or not email or not password:
            self.status_label.configure(text="All fields are required")
            return

        success, msg = self.auth.register_user(username, email, password, role)
        if success:
            messagebox.showinfo("Success", msg)
            self.refresh_callback()
            self.destroy()
        else:
            self.status_label.configure(text=msg)


class CreatePolicyDialog(ctk.CTkToplevel):
    def __init__(self, parent, policy_mgr, refresh_callback):
        super().__init__(parent)
        self.policy_mgr = policy_mgr
        self.refresh_callback = refresh_callback
        self.title("Create Policy")
        self.geometry("420x420")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)
        self.transient(parent)
        self.grab_set()
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(self, text="Create Policy", font=AppConfig.FONT_HEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(pady=15)

        card = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=5, fill="both", expand=True)

        ctk.CTkLabel(card, text="Policy Name", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(12, 3))
        self.name_entry = ctk.CTkEntry(card, font=AppConfig.FONT_NORMAL, height=33, corner_radius=8)
        self.name_entry.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkLabel(card, text="Description", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(anchor="w", padx=20, pady=(0, 3))
        self.desc_entry = ctk.CTkEntry(card, font=AppConfig.FONT_NORMAL, height=33, corner_radius=8)
        self.desc_entry.pack(fill="x", padx=20, pady=(0, 8))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkLabel(row, text="Type", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(side="left")
        self.type_var = ctk.StringVar(value="allow")
        ctk.CTkOptionMenu(row, variable=self.type_var, values=["allow", "deny"],
                          width=120, height=30, corner_radius=8).pack(side="left", padx=10)

        ctk.CTkLabel(row, text="Scope", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(side="left")
        self.scope_var = ctk.StringVar(value="global")
        ctk.CTkOptionMenu(row, variable=self.scope_var, values=["global", "user", "application"],
                          width=120, height=30, corner_radius=8).pack(side="left", padx=10)

        time_row = ctk.CTkFrame(card, fg_color="transparent")
        time_row.pack(fill="x", padx=20, pady=(0, 12))

        ctk.CTkLabel(time_row, text="Start (HH:MM)", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(side="left")
        self.start_entry = ctk.CTkEntry(time_row, width=80, height=30, corner_radius=8,
                                        placeholder_text="09:00")
        self.start_entry.pack(side="left", padx=10)

        ctk.CTkLabel(time_row, text="End (HH:MM)", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(side="left")
        self.end_entry = ctk.CTkEntry(time_row, width=80, height=30, corner_radius=8,
                                      placeholder_text="17:00")
        self.end_entry.pack(side="left", padx=10)

        ctk.CTkButton(card, text="Create", command=self._handle_create,
                      fg_color=AppConfig.COLOR_PRIMARY, height=38, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkButton(card, text="Cancel", command=self.destroy,
                      fg_color="transparent", hover_color="#333333",
                      text_color="#888888", height=28, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 12))

        self.status_label = ctk.CTkLabel(card, text="", font=AppConfig.FONT_SMALL,
                                         text_color=AppConfig.COLOR_DANGER)
        self.status_label.pack(pady=(0, 5))

    def _handle_create(self):
        name = self.name_entry.get().strip()
        desc = self.desc_entry.get().strip()
        ptype = self.type_var.get()
        scope = self.scope_var.get()
        start = self.start_entry.get().strip() or None
        end = self.end_entry.get().strip() or None

        if not name:
            self.status_label.configure(text="Policy name is required")
            return

        pid = self.policy_mgr.create_policy(name, desc, ptype, scope, True, start, end)
        if pid > 0:
            messagebox.showinfo("Success", f"Policy '{name}' created")
            self.refresh_callback()
            self.destroy()
        else:
            self.status_label.configure(text="Failed to create policy")


class CreateScheduleDialog(ctk.CTkToplevel):
    def __init__(self, parent, scheduler, user, refresh_callback):
        super().__init__(parent)
        self.scheduler = scheduler
        self.user = user
        self.refresh_callback = refresh_callback
        self.title("Create Schedule")
        self.geometry("420x380")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)
        self.transient(parent)
        self.grab_set()
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(self, text="Create Schedule", font=AppConfig.FONT_HEADING,
                     text_color=AppConfig.COLOR_TEXT).pack(pady=15)

        card = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=10)
        card.pack(padx=20, pady=5, fill="both", expand=True)

        row1 = ctk.CTkFrame(card, fg_color="transparent")
        row1.pack(fill="x", padx=20, pady=(12, 8))

        ctk.CTkLabel(row1, text="Start (HH:MM)", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(side="left")
        self.start_entry = ctk.CTkEntry(row1, width=80, height=30, corner_radius=8,
                                        placeholder_text="09:00")
        self.start_entry.pack(side="left", padx=10)

        ctk.CTkLabel(row1, text="End (HH:MM)", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(side="left")
        self.end_entry = ctk.CTkEntry(row1, width=80, height=30, corner_radius=8,
                                      placeholder_text="17:00")
        self.end_entry.pack(side="left", padx=10)

        row2 = ctk.CTkFrame(card, fg_color="transparent")
        row2.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkLabel(row2, text="Action", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(side="left")
        self.action_var = ctk.StringVar(value="disable")
        ctk.CTkOptionMenu(row2, variable=self.action_var, values=["enable", "disable"],
                          width=120, height=30, corner_radius=8).pack(side="left", padx=10)

        ctk.CTkLabel(row2, text="Recurrence", font=AppConfig.FONT_SMALL,
                     text_color=AppConfig.COLOR_TEXT).pack(side="left")
        self.recurrence_var = ctk.StringVar(value="daily")
        ctk.CTkOptionMenu(row2, variable=self.recurrence_var,
                          values=["once", "daily", "weekly", "monthly"],
                          width=100, height=30, corner_radius=8).pack(side="left", padx=10)

        ctk.CTkButton(card, text="Create", command=self._handle_create,
                      fg_color=AppConfig.COLOR_PRIMARY, height=38, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(12, 8))

        ctk.CTkButton(card, text="Cancel", command=self.destroy,
                      fg_color="transparent", hover_color="#333333",
                      text_color="#888888", height=28, corner_radius=8
                      ).pack(fill="x", padx=20, pady=(0, 12))

    def _handle_create(self):
        start = self.start_entry.get().strip()
        end = self.end_entry.get().strip()
        action = self.action_var.get()
        recurrence = self.recurrence_var.get()

        if not start or not end:
            messagebox.showerror("Error", "Start and end times are required")
            return

        sid = self.scheduler.create_schedule(
            user_id=self.user['user_id'],
            start_time=start, end_time=end,
            action=action, recurrence=recurrence
        )
        if sid > 0:
            messagebox.showinfo("Success", "Schedule created")
            self.refresh_callback()
            self.destroy()
        else:
            messagebox.showerror("Error", "Failed to create schedule")


# ==================== MAIN APP ====================


class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Webcam Spyware Security")
        self.geometry(f"{AppConfig.WINDOW_WIDTH}x{AppConfig.WINDOW_HEIGHT}")
        self.configure(fg_color=AppConfig.COLOR_DARK_BG)

        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

        self.container = ctk.CTkFrame(self, fg_color=AppConfig.COLOR_DARK_BG)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        self.show_login()

    def show_login(self):
        for frame in self.frames.values():
            frame.grid_forget()
        frame = LoginScreen(self.container, self.on_login_success)
        self.frames['login'] = frame
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()

    def show_dashboard(self, user: Dict, token: str):
        for frame in self.frames.values():
            frame.grid_forget()
        frame = DashboardScreen(self.container, user, token,
                                lambda: self.on_logout_success())
        self.frames['dashboard'] = frame
        frame.grid(row=0, column=0, sticky="nsew")
        frame.tkraise()

    def on_login_success(self, user: Dict, token: str):
        self.show_dashboard(user, token)

    def on_logout_success(self):
        self.show_login()


def main():
    logging.basicConfig(level=logging.INFO)
    app = MainApp()
    app.mainloop()


if __name__ == "__main__":
    main()
