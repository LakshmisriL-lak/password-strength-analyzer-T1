"""
Password Strength Analyzer
--------------------------
Features:
  1. Checks length, complexity (character variety) and uniqueness (common passwords, patterns)
  2. Estimates entropy in bits
  3. Suggests stronger alternatives (uses `secrets`, a cryptographically secure RNG)
  4. Optional: SQLite history that stores only salted PBKDF2 hashes to block password reuse

Run:  python password_analyzer.py
"""
import getpass
import hashlib
import hmac
import math
import os
import re
import secrets
import sqlite3
import string

DB_FILE = "password_history.db"
SYMBOLS = "!@#$%^&*()-_=+?"

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein",
    "admin", "welcome", "iloveyou", "monkey", "dragon", "111111", "123123",
    "password1", "qwerty123", "admin123", "login", "passw0rd", "india123",
}
KEYBOARD_SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm",
]
LEET_MAP = str.maketrans("@$01345", "asoieas")  # undo common substitutions


# ---------------------------------------------------------------- analysis
def charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^A-Za-z0-9]", pw):
        size += 32
    return size


def entropy_bits(pw: str) -> float:
    """Entropy = length * log2(size of the character pool)."""
    return len(pw) * math.log2(charset_size(pw)) if pw else 0.0


def has_sequence(pw: str, n: int = 4) -> bool:
    low = pw.lower()
    for seq in KEYBOARD_SEQUENCES:
        for s in (seq, seq[::-1]):
            if any(s[i:i + n] in low for i in range(len(s) - n + 1)):
                return True
    return False


def is_common(pw: str) -> bool:
    low = pw.lower()
    stripped = low.rstrip("0123456789!@#")          # password123 -> password
    candidates = {low, stripped, low.translate(LEET_MAP), stripped.translate(LEET_MAP)}
    return any(c in COMMON_PASSWORDS for c in candidates)


def analyze(pw: str) -> dict:
    feedback = []
    if not pw:
        return {"score": 0, "label": "Very Weak", "entropy": 0.0, "feedback": ["Empty password."]}

    # Length (max 40 pts)
    score = min(len(pw), 16) / 16 * 40
    if len(pw) < 8:
        feedback.append("Too short - use at least 12 characters.")
    elif len(pw) < 12:
        feedback.append("Okay length, but 12+ characters is much safer.")

    # Complexity (max 40 pts)
    checks = {
        "lowercase letters": r"[a-z]",
        "uppercase letters": r"[A-Z]",
        "digits": r"\d",
        "symbols": r"[^A-Za-z0-9]",
    }
    kinds = 0
    for name, pattern in checks.items():
        if re.search(pattern, pw):
            kinds += 1
        else:
            feedback.append(f"Add {name}.")
    score += kinds * 10

    # Entropy bonus (max 20 pts)
    bits = entropy_bits(pw)
    score += min(bits, 80) / 80 * 20

    # Uniqueness / pattern penalties
    if is_common(pw):
        score = min(score, 5)
        feedback.append("This is a very common password - attackers try it first!")
    if re.search(r"(.)\1{2,}", pw):
        score -= 20
        feedback.append("Avoid repeating the same character (e.g. 'aaa').")
    if has_sequence(pw):
        score -= 15
        feedback.append("Avoid sequences like 'abcd', '1234' or 'qwer'.")

    score = max(0, min(100, round(score)))
    label = ("Very Weak" if score < 30 else "Weak" if score < 50 else
             "Medium" if score < 70 else "Strong" if score < 85 else "Very Strong")
    if not feedback:
        feedback.append("Looks great!")
    return {"score": score, "label": label, "entropy": round(bits, 1), "feedback": feedback}


# ------------------------------------------------------------ suggestions
def generate_password(length: int = 16) -> str:
    """Random password guaranteed to contain all 4 character types."""
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS]
    chars = [secrets.choice(p) for p in pools]
    allchars = "".join(pools)
    chars += [secrets.choice(allchars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def strengthen(pw: str) -> str:
    """Keep the user's word recognisable, but harden it."""
    subs = {"a": "@", "s": "$", "o": "0", "i": "!", "e": "3"}
    out = []
    for ch in pw:
        if ch.lower() in subs and secrets.randbelow(2):
            out.append(subs[ch.lower()])
        else:
            out.append(ch.upper() if secrets.randbelow(2) else ch.lower())
    out.append(secrets.choice(SYMBOLS))
    out.append("".join(secrets.choice(string.digits) for _ in range(3)))
    out.append(secrets.choice(SYMBOLS))
    return "".join(out)


def suggest(pw: str) -> list:
    ideas = [generate_password(16), generate_password(20)]
    if pw and len(pw) >= 4:
        ideas.insert(0, strengthen(pw))
    return ideas


# ------------------------------------------------- password history (SQLite)
def _hash(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)


def _db():
    con = sqlite3.connect(DB_FILE)
    con.execute("CREATE TABLE IF NOT EXISTS history (username TEXT, salt BLOB, hash BLOB)")
    return con


def was_used_before(username: str, pw: str) -> bool:
    with _db() as con:
        rows = con.execute("SELECT salt, hash FROM history WHERE username=?", (username,)).fetchall()
    return any(hmac.compare_digest(_hash(pw, salt), h) for salt, h in rows)


def save_password(username: str, pw: str) -> None:
    salt = os.urandom(16)
    with _db() as con:
        con.execute("INSERT INTO history VALUES (?,?,?)", (username, salt, _hash(pw, salt)))


# -------------------------------------------------------------------- CLI
def main():
    print("=== Password Strength Analyzer ===  (Ctrl+C to quit)\n")
    username = input("Username (press Enter to skip history check): ").strip()
    while True:
        pw = getpass.getpass("\nEnter password to test: ")
        result = analyze(pw)
        print(f"\nStrength : {result['label']} ({result['score']}/100)")
        print(f"Entropy  : {result['entropy']} bits")
        for tip in result["feedback"]:
            print(f"  - {tip}")

        if username and pw and was_used_before(username, pw):
            print("\n[!] You have used this password before. Choose a new one.")
        elif username and pw and result["score"] >= 70:
            save_password(username, pw)
            print("\n[+] Password accepted and saved (as a salted hash) to history.")

        if result["score"] < 85:
            print("\nSuggested stronger passwords:")
            for s in suggest(pw):
                print(f"  {s}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye!")
