🔐 Password Strength Checker (Python + C++)
📌 Overview

This project contains two standalone implementations of a password strength checker:

Python → concise, beginner-friendly, easy to read.

C++ → more verbose, performance-focused, closer to system-level programming.

Both versions:

Instantly reject passwords from a weak password list (dictionary attack defense).

Check for uppercase, lowercase, numbers, and symbols.

Calculate password entropy using:

Shannon entropy (character distribution randomness)

Pool size entropy (based on possible character set size)

Classify strength from Very Weak → Very Strong.

Give specific improvement advice.

🆚 Python vs C++ in This Project
Feature	Python Implementation	C++ Implementation
Code length	Short, concise	Longer, more verbose
Ease of writing	Very easy	More setup & type handling
Readability	Beginner-friendly	Requires C++ knowledge
Performance	Slower for huge datasets	Faster for large datasets
Data structure	dict / set	unordered_map / unordered_set
Use case	Quick scripts, automation	Compiled security software

📜 License

This project uses the MIT License, meaning you’re free to use, modify, and share it — just give credit and don’t hold me liable.
