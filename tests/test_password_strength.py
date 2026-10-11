"""
Tests for core.password_strength - zxcvbn integration and attack summary.
"""

from core.password_strength import (
    analyze_password,
    attack_summary,
    score_label,
)


# --- Basic analysis ---

def test_empty_password_returns_zero():
    r = analyze_password("")
    assert r.score == 0
    assert r.guesses == 0
    assert "empty" in r.feedback_warning.lower()
    assert r.sequence == []


def test_common_password_is_weak():
    r = analyze_password("password")
    assert r.score <= 1


def test_strong_passphrase_scores_high():
    r = analyze_password("correct horse battery staple quantum")
    assert r.score >= 3


def test_sequence_reports_dictionary_match():
    r = analyze_password("password")
    patterns = {m.get("pattern") for m in r.sequence}
    assert "dictionary" in patterns


def test_qwerty_reports_spatial_match():
    r = analyze_password("qwertyuiop")
    patterns = {m.get("pattern") for m in r.sequence}
    assert "spatial" in patterns or "dictionary" in patterns  # zxcvbn may classify either way


# --- Labels ---

def test_score_labels_cover_all_levels():
    assert score_label(0) == "Too guessable"
    assert score_label(1) == "Very guessable"
    assert score_label(2) == "Somewhat guessable"
    assert score_label(3) == "Safely unguessable"
    assert score_label(4) == "Very unguessable"


# --- Attack summary ---

def test_attack_summary_has_verdict_and_vectors():
    r = analyze_password("password")
    text = attack_summary(r)
    assert "VERDICT" in text
    assert "MOST LIKELY ATTACK VECTORS" in text
    assert "DETECTED PATTERNS" in text


def test_attack_summary_mentions_dictionary_for_common_word():
    r = analyze_password("password")
    text = attack_summary(r)
    assert "dictionary" in text.lower()


def test_attack_summary_for_strong_password():
    r = analyze_password("correct horse battery staple quantum")
    text = attack_summary(r)
    # For score >= 3 the summary should not imply trivial dictionary attack success
    assert "VERDICT" in text