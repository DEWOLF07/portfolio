# Password Strength Checker (Python + C++)
## 📌 Overview
This repository contains **two separate implementations** of a password strength checker:
- **Python version** → clean, short, and easy to read.
- **C++ version** → more verbose, shows low-level handling and performance-focused design.

Both versions:
- Load a small list of **common weak passwords** and reject them instantly.
- Check for presence of **uppercase**, **lowercase**, **numbers**, and **symbols**.
- Calculate **password entropy** using:
  - **Shannon entropy** (based on character distribution)
  - **Pool size entropy** (based on possible character set size)
- Classify strength from *Very weak* → *Very strong*.
- Give **advice** on how to improve a password.

---

## 🆚 Python vs. C++ in This Project

| Feature              | Python Implementation | C++ Implementation |
|----------------------|-----------------------|--------------------|
| **Code length**      | Short, concise        | Longer, more verbose |
| **Ease of writing**  | Very easy (few lines) | More setup, type handling |
| **Readability**      | Beginner-friendly     | Requires understanding of C++ syntax |
| **Performance**      | Slower for massive checks | Faster for large datasets |
| **Data structure**   | `dict` / `set`        | `unordered_map` / `unordered_set` |
| **Use case**         | Quick scripts, automation | System-level tools, compiled security software |

---

## 🛠️ What I Did
- **Designed** both a Python and C++ version from scratch for comparison.
- **Used dictionaries/sets** for O(1) lookups of weak passwords.
- Implemented **entropy calculations** for a more realistic strength measure.
- Added **scoring rules** as configurable mappings (`dict` in Python, `unordered_map` in C++).
- Kept **functions modular** so they can be reused or expanded.
- Made both versions **self-contained**: each folder has its own code and `weak_passwords.txt`.

---

## 📂 Project Structure
