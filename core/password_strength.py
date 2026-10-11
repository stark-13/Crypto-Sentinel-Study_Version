"""
Password strength analysis using zxcvbn.
Provides a unified interface for the GUI.
"""

from zxcvbn import zxcvbn
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StrengthResult:
    score: int
    guesses: float
    guesses_log10: float
    feedback_warning: str
    feedback_suggestions: list[str]
    crack_times_seconds: dict
    crack_times_display: dict
    sequence: list[dict] = field(default_factory=list)


def analyze_password(password: str, user_inputs: Optional[list[str]] = None) -> StrengthResult:
    """Analyze a password with zxcvbn and return a StrengthResult."""
    if not password:
        return StrengthResult(
            score=0,
            guesses=0,
            guesses_log10=0,
            feedback_warning="Password is empty.",
            feedback_suggestions=["Enter a password to analyze."],
            crack_times_seconds={},
            crack_times_display={},
            sequence=[],
        )

    result = zxcvbn(password, user_inputs=user_inputs or [])
    feedback = result.get("feedback") or {}

    return StrengthResult(
        score=result["score"],
        guesses=result["guesses"],
        guesses_log10=result["guesses_log10"],
        feedback_warning=feedback.get("warning") or "",
        feedback_suggestions=feedback.get("suggestions") or [],
        crack_times_seconds=result["crack_times_seconds"],
        crack_times_display=result["crack_times_display"],
        sequence=result.get("sequence") or [],
    )


def score_label(score: int) -> str:
    labels = {
        0: "Too guessable",
        1: "Very guessable",
        2: "Somewhat guessable",
        3: "Safely unguessable",
        4: "Very unguessable",
    }
    return labels.get(score, "Unknown")


# ---------------------------------------------------------------------------
# Attack summary
# ---------------------------------------------------------------------------

_VERDICTS = {
    0: "HIGHLY VULNERABLE - will fall to automated attacks within seconds.",
    1: "VULNERABLE - a typical password cracker will break this in minutes.",
    2: "MODERATELY VULNERABLE - offline attacks with consumer GPUs could crack this.",
    3: "RESISTANT - requires significant resources or a targeted effort.",
    4: "STRONG - no practical attack is likely to succeed in the near future.",
}


def attack_summary(result: StrengthResult) -> str:
    """Produce a detailed, pattern-aware attack summary."""
    lines: list[str] = []

    lines.append(f"VERDICT: {_VERDICTS.get(result.score, 'Unknown')}")
    lines.append("")

    lines.append("MOST LIKELY ATTACK VECTORS:")
    for vector in _attack_vectors(result):
        lines.append(f"  - {vector}")
    lines.append("")

    if result.sequence:
        lines.append("DETECTED PATTERNS (how a cracker would decompose this password):")
        for match in result.sequence:
            lines.append(f"  - {_describe_match(match)}")
    else:
        lines.append("No structured patterns detected - the whole string would be treated as random.")

    return "\n".join(lines)


def _attack_vectors(result: StrengthResult) -> list[str]:
    patterns = {m.get("pattern") for m in result.sequence}
    vectors: list[str] = []

    if result.score <= 1:
        vectors.append("Dictionary attack (top-N wordlists) - almost certainly successful")
        vectors.append("Rule-based attack (e.g. hashcat --rules) - very likely successful")
        vectors.append("Credential stuffing - if this password is reused anywhere")
        if "spatial" in patterns:
            vectors.append("Keyboard-walk attack (patterns like 'qwerty' or 'asdfgh')")
        if "date" in patterns:
            vectors.append("Date/pattern attack (birthdays, years)")
        vectors.append("Brute force over a small keyspace")

    elif result.score == 2:
        vectors.append("Targeted dictionary attack with custom rules")
        if "date" in patterns or "sequence" in patterns:
            vectors.append("Pattern-aware attack (dates, sequences, keyboard walks)")
        vectors.append("Offline brute force with consumer GPUs")

    elif result.score == 3:
        vectors.append("Offline brute force with a large GPU cluster - expensive but possible")
        vectors.append("Targeted attack if the password has personal meaning")

    else:
        vectors.append("No practical attack vector at this time")

    return vectors


def _describe_match(match: dict) -> str:
    pattern = match.get("pattern", "unknown")
    token = match.get("token", "")
    guesses = match.get("guesses", 0)
    if guesses >= 1e12:
        guesses_str = f"{guesses:.2e} guesses"
    else:
        guesses_str = f"~{guesses:,.0f} guesses"

    if pattern == "dictionary":
        word = match.get("matched_word", token)
        rank = match.get("rank", "?")
        dictionary = match.get("dictionary_name", "unknown")
        flags = []
        if match.get("reversed"):
            flags.append("reversed")
        if match.get("l33t"):
            flags.append("l33t-speak")
        flags_str = f" ({', '.join(flags)})" if flags else ""
        return (
            f"'{token}' - dictionary word '{word}' "
            f"(rank {rank} in '{dictionary}' list{flags_str}); {guesses_str}"
        )

    if pattern == "spatial":
        graph = match.get("graph", "?")
        turns = match.get("turns", "?")
        shifted = match.get("shifted_count", 0)
        return (
            f"'{token}' - keyboard walk on '{graph}', "
            f"{turns} turn(s), {shifted} shifted char(s); {guesses_str}"
        )

    if pattern == "repeat":
        base = match.get("base_token", "?")
        count = match.get("repeat_count", "?")
        return f"'{token}' - repetition of '{base}' (~{count} times); {guesses_str}"

    if pattern == "sequence":
        name = match.get("sequence_name", "?")
        direction = "ascending" if match.get("ascending", True) else "descending"
        return f"'{token}' - {name} sequence ({direction}); {guesses_str}"

    if pattern == "date":
        year = match.get("year", "?")
        month = match.get("month", "?")
        day = match.get("day", "?")
        return f"'{token}' - date pattern ({year}-{month}-{day}); {guesses_str}"

    if pattern == "regex":
        name = match.get("regex_name", "?")
        return f"'{token}' - regex pattern '{name}'; {guesses_str}"

    if pattern == "bruteforce":
        cardinality = match.get("cardinality", "?")
        return f"'{token}' - brute-force segment (charset ~{cardinality}); {guesses_str}"

    return f"'{token}' - {pattern}; {guesses_str}"