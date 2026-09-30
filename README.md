
# 🔐 Password Strength Analyzer

A web tool that evaluates password strength and suggests stronger alternatives. Built with a **Python (Flask) backend** and an HTML, CSS and JavaScript frontend.

## ✨ Features
- Checks **length, complexity and uniqueness**
- Detects common passwords (including `p@ssw0rd` style variants), sequences (`abcd`, `1234`) and repeated characters
- Live strength score (0-100), entropy in bits, checklist and tips
- Suggests strong passwords using Python's secure `secrets` module
- Optional: password history stored as **salted PBKDF2 hashes** in SQLite to prevent reuse

## 🛠 Tech Stack
Python, Flask, SQLite, HTML, CSS, JavaScript

## 🖼 Screenshots
![Weak](screenshots/weak.png)
![Strong](screenshots/strong.png)

## ▶️ How to Run
```bash
git clone https://github.com/YOUR-USERNAME/password-strength-analyzer.git
cd password-strength-analyzer
pip install -r requirements.txt
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

## 🔒 Concepts Used
- **Entropy:** `length × log2(character pool size)`
- **`secrets` vs `random`:** cryptographically secure random generation
- **Hashing + salt (PBKDF2):** passwords are never stored in plain text
