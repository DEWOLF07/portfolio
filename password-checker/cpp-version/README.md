
---

**`cpp-version/README.md`**
```markdown
# Password Strength Checker (C++)

## 📌 Overview
This is the **C++ implementation** of the password strength checker.

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

### Why C++?
- Shows **low-level control** and performance-oriented coding.
- Demonstrates use of **`unordered_map`** and **`unordered_set`** for O(1) lookups.
- Suitable for integrating into **compiled applications** or security tools.

### How to Run
```bash
g++ -std=c++17 main.cpp -O2 -o pwcheck
./pwcheck
