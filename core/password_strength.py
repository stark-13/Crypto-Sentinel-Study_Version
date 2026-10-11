'''
Pasword strength analysis zxcvbn.
Provides a unified interface for the GUI
'''

from zxcvbn import zxcvbn
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class StrengthResult:
    score: int # 0-4
    guesses: float # estimated guesses
    guesses_log10: float
    feedback_warning: str
    feedback_suggestions: list[str]
    crack_times_seconds: dict
    crack_times_display: dict
    sequence: list[dict] = field(default_factory=list)

def analyze_password(password: str, user_inputs: Optional[list[str]]=None) -> StrengthResult:
    '''
    Analyze a password with zxcvbn.

    Args:
        password: The password to analyze.
        user_inputs: Optional list of user-specific strings (name, email, etc.)
                     to add to the dictionary check.

    Returns:
        StrengthResult dataclass with score, guesses, feedback, and crack times.
    '''

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

    return StrengthResult(
        score=result["score"],
        guesses=result["guesses"],
        guesses_log10=result["guesses_log10"],
        feedback_warning=result["feedback"]["warning"],
        feedback_suggestions=result["feedback"]["suggestions"],
        crack_times_seconds=result["crack_times_seconds"],
        crack_times_display=result["crack_times_display"],
        sequence=result.get("sequence", []),
    )


def score_label(score: int) -> str:
    """Return a human-readable label for a zxcvbn score."""
    labels = {
        0: "Too guessable",
        1: "Very guessable",
        2: "Somewhat guessable",
        3: "Safely unguessable",
        4: "Very unguessable",
    }
    return labels.get(score, "Unknown")


def attack_summary(result: StrengthResult) -> str:
    """
    Produce a short summary of which attack types are most likely to succeed.
    This is heuristic and educational, not a guarantee.
    """
    lines = []

    if result.score <= 1:
        lines.append("⚠️  This password is vulnerable to dictionary and rule-based attacks.")
        lines.append("    It may also fall to credential stuffing if reused elsewhere.")
    elif result.score == 2:
        lines.append("⚠️  This password can be cracked by targeted dictionary attacks")
        lines.append("    combined with pattern-based rules.")
    elif result.score == 3:
        lines.append("✅  This password resists dictionary and pattern attacks.")
        lines.append("    Only large-scale brute force with significant resources might succeed.")
    else:
        lines.append("✅  This password is very strong against known attack strategies.")

    # Check for specific weak patterns in the sequence
    patterns_found = set()
    for match in result.sequence:
        pattern = match.get("pattern", "")
        if pattern == "dictionary":
            patterns_found.add("dictionary word")
        elif pattern == "spatial":
            patterns_found.add("keyboard pattern")
        elif pattern == "repeat":
            patterns_found.add("repeated characters")
        elif pattern == "sequence":
            patterns_found.add("sequence")
        elif pattern == "date":
            patterns_found.add("date")
        elif pattern == "bruteforce":
            patterns_found.add("brute-force segment")

    if patterns_found:
        lines.append("")
        lines.append("Patterns detected: " + ", ".join(sorted(patterns_found)))

    return "\n".join(lines)