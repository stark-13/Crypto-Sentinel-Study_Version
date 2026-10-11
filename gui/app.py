import tkinter as tk
from tkinter import ttk

from gui.password_tab import PasswordTab
from gui.crypto_tab import CryptoTab


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto Sentinel - Password Analyzer & Symmetric Crypto Tool")
        self.geometry("820x680")
        self.minsize(740, 600)

        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        # Base styling for the score progressbar; individual colors are set later.
        style.configure(
            "Score.Horizontal.TProgressbar",
            troughcolor="#ecf0f1",
            background="#3498db",
            thickness=14,
        )

        self.status_var = tk.StringVar(value="Ready.")
        self._build_ui()
        self._bind_global_shortcuts()

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 4))

        self.password_tab = PasswordTab(notebook, set_status=self.set_status)
        self.crypto_tab = CryptoTab(notebook, set_status=self.set_status)

        notebook.add(self.password_tab, text="  Password Analyzer  ")
        notebook.add(self.crypto_tab, text="  Encryption / Decryption  ")

        status_bar = ttk.Label(
            self,
            textvariable=self.status_var,
            anchor=tk.W,
            relief=tk.SUNKEN,
            padding=(8, 3),
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _bind_global_shortcuts(self):
        self.bind_all("<Control-q>", lambda e: self.destroy())
        self.bind_all("<Control-l>", lambda e: self.password_tab.focus_input())
        self.bind_all("<Control-e>", lambda e: self.crypto_tab.focus_input())

    def set_status(self, message: str):
        self.status_var.set(message)