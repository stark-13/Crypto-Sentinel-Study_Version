# Crypto Sentinel

A cross-platform desktop tool for **password strength analysis** and
**symmetric text encryption / decryption**, built with Python, Tkinter/ttk,
`zxcvbn`, and `cryptography`.

> Educational project. Do not use it to store real secrets.

## Features

### Password Analyzer
- Realistic strength estimation using **zxcvbn** (pattern-aware, not just entropy).
- Score 0-4 with a color-coded strength bar.
- Estimated guesses and log10 guesses.
- Crack-time estimates for four attacker scenarios:
  - Online throttled (100 guesses/hour)
  - Online unthrottled (10 guesses/second)
  - Offline slow hash (bcrypt/Argon2, ~10^4 guesses/second)
  - Offline fast hash (MD5/SHA1 on GPU, ~10^10 guesses/second)
- Pattern breakdown showing which substrings zxcvbn matched
  (dictionary words, keyboard walks, repeats, sequences, dates, brute-force chunks).
- Attack-vector summary describing which attack types are most likely to succeed.

### Encryption / Decryption
- Symmetric text encryption with **AES-256-GCM** (authenticated).
- Key derivation with **PBKDF2-HMAC-SHA256** and a random 16-byte salt.
- Random 12-byte nonce per encryption.
- Base64 output so the ciphertext is safe to copy as text.
- Detects wrong passphrases and tampered data via the GCM authentication tag.

## Requirements

- Python **3.10+** (tested on 3.12/3.13)
- Linux, Windows, or macOS

## Installation

```bash
git clone <your-repo-url>
cd Crypto-Sentinel
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -r Requirements.txt
