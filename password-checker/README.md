🔐 Password Strength Checker (Python + C++)
Overview

This repository contains two separate implementations of a password strength checker:

* Python version – concise, beginner-friendly, and easy to modify.

* C++ version – more verbose, demonstrates low-level control and performance-focused design.

Both versions:

* Load a small list of common weak passwords and reject them instantly.

* Check for uppercase, lowercase, numbers, and symbols.

- Calculate password entropy using:

  - Shannon entropy (based on character distribution)

  - Pool size entropy (based on possible character set size)

* Classify password strength from Very Weak → Very Strong.

* Provide actionable advice for improving weak passwords.

---

| Feature             | Python Implementation     | C++ Implementation                    |
| ------------------- | ------------------------- | ------------------------------------- |
| **Code length**     | Short, concise            | Longer, more verbose                  |
| **Ease of writing** | Very easy                 | Requires more setup                   |
| **Readability**     | Beginner-friendly         | Requires C++ knowledge                |
| **Performance**     | Slower for large datasets | Faster for large datasets             |
| **Data structure**  | `dict` / `set`            | `unordered_map` / `unordered_set`     |
| **Use case**        | Quick scripts, automation | System-level tools, compiled software |

---
License

This project is licensed under the MIT License, allowing you to use, modify, and share the code freely with attribution.
