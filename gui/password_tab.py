import tkinter as tk
from tkinter import ttk

from core.password_strength import (
    analyze_password,
    score_label,
    attack_summary,
)


class PasswordTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        # --- Input section ---
        input_frame = ttk.LabelFrame(self, text="Password Input", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.password_var = tk.StringVar()
        self.show_var = tk.BooleanVar(value=False)

        entry = ttk.Entry(
            input_frame,
            textvariable=self.password_var,
            show="*",
            font=("Consolas", 12),
        )
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        def toggle_show():
            entry.config(show="" if self.show_var.get() else "*")

        ttk.Checkbutton(
            input_frame, text="Show", variable=self.show_var, command=toggle_show
        ).pack(side=tk.LEFT)

        ttk.Button(
            input_frame, text="Analyze", command=self._on_analyze
        ).pack(side=tk.LEFT, padx=(8, 0))

        # --- Score bar ---
        score_frame = ttk.LabelFrame(self, text="Strength Score", padding=10)
        score_frame.pack(fill=tk.X, padx=10, pady=5)

        self.score_var = tk.StringVar(value="—")
        ttk.Label(
            score_frame, textvariable=self.score_var, font=("Segoe UI", 14, "bold")
        ).pack(anchor=tk.W)

        self.progress = ttk.Progressbar(
            score_frame, orient=tk.HORIZONTAL, length=400, mode="determinate", maximum=4
        )
        self.progress.pack(fill=tk.X, pady=(6, 0))

        # --- Results text ---
        result_frame = ttk.LabelFrame(self, text="Analysis Summary", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        self.result_text = tk.Text(
            result_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            state=tk.DISABLED,
            height=16,
        )
        scrollbar = ttk.Scrollbar(result_frame, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)

        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _on_analyze(self):
        password = self.password_var.get()
        result = analyze_password(password)

        # Update score bar
        self.progress["value"] = result.score
        self.score_var.set(
            f"Score: {result.score}/4 — {score_label(result.score)}"
        )

        # Build detailed report
        lines = []
        lines.append(f"Estimated guesses: {result.guesses:,.0f}")
        lines.append(f"Guesses log10:      {result.guesses_log10:.2f}")
        lines.append("")

        if result.feedback_warning:
            lines.append(f"Warning: {result.feedback_warning}")
            lines.append("")

        if result.feedback_suggestions:
            lines.append("Suggestions:")
            for s in result.feedback_suggestions:
                lines.append(f"  • {s}")
            lines.append("")

        lines.append("Crack-time estimates (attacker scenarios):")
        for key, display in result.crack_times_display.items():
            label = key.replace("_", " ").title()
            lines.append(f"  {label}: {display}")

        lines.append("")
        lines.append(attack_summary(result))

        self._set_text("\n".join(lines))

    def _set_text(self, content: str):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, content)
        self.result_text.config(state=tk.DISABLED)