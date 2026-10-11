import tkinter as tk
from tkinter import ttk

from core.crypto import encrypt, decrypt


class CryptoTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        # --- Mode selector ---
        mode_frame = ttk.LabelFrame(self, text="Mode", padding=10)
        mode_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.mode_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(
            mode_frame, text="Encrypt", variable=self.mode_var, value="encrypt"
        ).pack(side=tk.LEFT, padx=(0, 15))
        ttk.Radiobutton(
            mode_frame, text="Decrypt", variable=self.mode_var, value="decrypt"
        ).pack(side=tk.LEFT)

        # --- Input ---
        input_frame = ttk.LabelFrame(self, text="Input Text", padding=10)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.input_text = tk.Text(input_frame, wrap=tk.WORD, font=("Consolas", 11), height=7)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        # --- Passphrase ---
        pass_frame = ttk.LabelFrame(self, text="Passphrase", padding=10)
        pass_frame.pack(fill=tk.X, padx=10, pady=5)

        self.pass_var = tk.StringVar()
        self.pass_show_var = tk.BooleanVar(value=False)

        self.pass_entry = ttk.Entry(
            pass_frame, textvariable=self.pass_var, show="*", font=("Consolas", 11)
        )
        self.pass_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        def toggle_pass():
            self.pass_entry.config(show="" if self.pass_show_var.get() else "*")

        ttk.Checkbutton(
            pass_frame, text="Show", variable=self.pass_show_var, command=toggle_pass
        ).pack(side=tk.LEFT)

        # --- Action buttons ---
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="Run", command=self._on_run).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Copy Output", command=self._copy_output).pack(
            side=tk.LEFT, padx=8
        )
        ttk.Button(btn_frame, text="Clear All", command=self._clear_all).pack(side=tk.LEFT)

        # --- Output ---
        output_frame = ttk.LabelFrame(self, text="Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        self.output_text = tk.Text(
            output_frame, wrap=tk.WORD, font=("Consolas", 11), height=7, state=tk.DISABLED
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)

    def _on_run(self):
        mode = self.mode_var.get()
        text = self.input_text.get("1.0", tk.END).strip()
        password = self.pass_var.get()

        if not text:
            self._show_error("Input text is empty.")
            return
        if not password:
            self._show_error("Passphrase is empty.")
            return

        try:
            if mode == "encrypt":
                result = encrypt(text, password)
            else:
                result = decrypt(text, password)
        except ValueError as exc:
            self._show_error(str(exc))
            return

        self._set_output(result)

    def _show_error(self, message: str):
        self._set_output(f"[ERROR] {message}")

    def _set_output(self, content: str):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, content)
        self.output_text.config(state=tk.DISABLED)

    def _copy_output(self):
        content = self.output_text.get("1.0", tk.END).strip()
        if content:
            self.clipboard_clear()
            self.clipboard_append(content)

    def _clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.pass_var.set("")
        self._set_output("")