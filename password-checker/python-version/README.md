# Password Strength Checker (Python)

## 📌 Overview
This is the **Python implementation** of the password strength checker.

### Features
- Loads a small list of **common weak passwords** and rejects them.
- Checks for:
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Symbols
- Calculates:
  - **Shannon entropy** (character randomness)
  - **Pool size entropy** (character set size)
- Gives a **score** and a strength label.
- Provides **advice** for improvement.

### Why Python?
- Very short and **easy to read**.
- Minimal setup — uses only the Python standard library.
- Ideal for quick scripts or small tools.

### How to Run
```bash
python3 main.py
