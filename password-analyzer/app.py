import re
from flask import Flask, render_template, request, jsonify
from password_analyzer import (analyze, suggest, is_common, has_sequence,
                               was_used_before, save_password)

app = Flask(__name__)


def build_checks(pw):
    return [
        {"name": "At least 12 characters", "ok": len(pw) >= 12},
        {"name": "Lowercase letters", "ok": bool(re.search(r"[a-z]", pw))},
        {"name": "Uppercase letters", "ok": bool(re.search(r"[A-Z]", pw))},
        {"name": "Digits", "ok": bool(re.search(r"\d", pw))},
        {"name": "Symbols (!@#$...)", "ok": bool(re.search(r"[^A-Za-z0-9]", pw))},
        {"name": "Not a common password", "ok": bool(pw) and not is_common(pw)},
        {"name": "No sequences (abcd, 1234)", "ok": bool(pw) and not has_sequence(pw)},
        {"name": "No repeated characters (aaa)", "ok": bool(pw) and not re.search(r"(.)\1{2}", pw)},
    ]


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze_route():
    pw = (request.get_json(silent=True) or {}).get("password", "")[:200]
    result = analyze(pw)
    result["checks"] = build_checks(pw)
    result["suggestions"] = suggest(pw) if result["score"] < 85 else []
    return jsonify(result)


@app.route("/save", methods=["POST"])
def save_route():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")[:200]
    user = data.get("username", "").strip()[:50]
    if not user or not pw:
        return jsonify(ok=False, message="Enter a username and a password."), 400
    if analyze(pw)["score"] < 70:
        return jsonify(ok=False, message="Password is too weak to save (need 70+).")
    if was_used_before(user, pw):
        return jsonify(ok=False, message="You have used this password before. Choose a new one.")
    save_password(user, pw)
    return jsonify(ok=True, message="Saved! (stored only as a salted hash)")


if __name__ == "__main__":
    app.run(debug=True)
