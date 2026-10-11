import tkinter as tk
from tkinter import ttk

from core.password_strength import (
    analyze_password,
    score_label,
    attack_summary,
)


# Colors indexed by zxcvbn score (0-4)
_SCORE_COLORS = {
    0: "#c0392b",  # dark red
    1: "#e74c3c",  # red
    2: "#f39c12",  # orange
    3: "#27ae60",  # green
    4: "#16a085",  # teal-green
}

_SCORE_TEXT_COLORS = {
    0: "#ffffff",
    1: "#ffffff",
    2: "#000000",
    3: "#ffffff",
    4: "#ffffff",
}


class PasswordTab(ttk.Frame):
    def __init__(self, parent, set_status=None):
        super().__init__(parent)
        self._set_status = set_status or (lambda msg: None)
        self._build_ui()

    def _build_ui(self):
        # --- Input section ---
        input_frame = ttk.LabelFrame(self, text="Password Input", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.password_var = tk.StringVar()
        self.show_var = tk.BooleanVar(value=False)

        self.entry = ttk.Entry(
            input_frame,
            textvariable=self.password_var,
            show="*",
            font=("Consolas", 12),
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        self.entry.bind("<Return>", lambda e: (self._on_analyze(), "break")[1])

        def toggle_show():
            self.entry.config(show="" if self.show_var.get() else "*")

        ttk.Checkbutton(
            input_frame, text="Show", variable=self.show_var, command=toggle_show
        ).pack(side=tk.LEFT)

        ttk.Button(input_frame, text="Analyze  (Enter)", command=self._on_analyze).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        # --- Score section ---
        score_frame = ttk.LabelFrame(self, text="Strength Score", padding=10)
        score_frame.pack(fill=tk.X, padx=10, pady=5)

        self.score_label_var = tk.StringVar(value="Score: -/4")
        self.score_label_widget = tk.Label(
            score_frame,
            textvariable=self.score_label_var,
            font=("Segoe UI", 13, "bold"),
            anchor=tk.W,
            padx=8,
            pady=4,
        )
        self.score_label_widget.pack(fill=tk.X)

        self.progress = ttk.Progressbar(
            score_frame,
            style="Score.Horizontal.TProgressbar",
            orient=tk.HORIZONTAL,
            mode="determinate",
            maximum=4,
        )
        self.progress.pack(fill=tk.X, pady=(8, 0))

        # --- Result text ---
        result_frame = ttk.LabelFrame(self, text="Analysis Summary", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        self.result_text = tk.Text(
            result_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            state=tk.DISABLED,
            height=18,
            padx=6,
            pady=6,
        )
        scrollbar = ttk.Scrollbar(result_frame, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def focus_input(self):
        self.entry.focus_set()
        self.entry.select_range(0, tk.END)

    def _on_analyze(self):
        password = self.password_var.get()
        if not password:
            self._set_status("Enter a password first.")
            return

        result = analyze_password(password)

        # Score bar + label
        self.progress["value"] = result.score
        color = _SCORE_COLORS.get(result.score, "#3498db")
        text_color = _SCORE_TEXT_COLORS.get(result.score, "#ffffff")
        self.score_label_var.set(
            f"Score: {result.score}/4 - {score_label(result.score)}"
        )
        self.score_label_widget.configure(bg=color, fg=text_color)

        # Compose report
        lines: list[str] = []
        lines.append(f"Estimated guesses : {result.guesses:,.0f}")
        lines.append(f"Guesses log10     : {result.guesses_log10:.2f}")
        lines.append("")

        if result.feedback_warning:
            lines.append(f"WARNING: {result.feedback_warning}")
            lines.append("")

        if result.feedback_suggestions:
            lines.append("Suggestions:")
            for s in result.feedback_suggestions:
                lines.append(f"  - {s}")
            lines.append("")

        lines.append("Crack-time estimates (attacker scenarios):")
        for key, display in result.crack_times_display.items():
            label = key.replace("_", " ").title()
            lines.append(f"  {label}: {display}")
        lines.append("")

        lines.append(attack_summary(result))

        self._set_text("\n".join(lines))
        self._set_status(f"Analysis complete. Score {result.score}/4.")

    def _set_text(self, content: str):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, content)
        self.result_text.config(state=tk.DISABLED)