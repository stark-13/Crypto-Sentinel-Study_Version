import tkinter as tk
from tkinter import ttk

from gui.password_tab import PasswordTab
from gui.crypto_tab import CryptoTab


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Analyzer & Symmetric Crypto Tool")
        self.geometry("780x620")
        self.minsize(700, 560)

        # Use the 'clam' theme for a consistent cross-platform look
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        self._build_ui()

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.password_tab = PasswordTab(notebook)
        self.crypto_tab = CryptoTab(notebook)

        notebook.add(self.password_tab, text="  Password Analyzer  ")
        notebook.add(self.crypto_tab, text="  Encryption / Decryption  ")