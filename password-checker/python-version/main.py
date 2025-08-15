# main.py
# Simple password checker: weak-list lookup, scoring, two entropy estimates (Shannon & pool)
import math
from collections import Counter

WEAK_FILE = "weak_passwords.txt"
SCORING = {'length': 2, 'upper': 1, 'lower': 1, 'digit': 1, 'symbol': 1}

def load_weak(path=WEAK_FILE):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()

def has_upper(s): return any(c.isupper() for c in s)
def has_lower(s): return any(c.islower() for c in s)
def has_digit(s): return any(c.isdigit() for c in s)
def has_symbol(s): return any(not c.isalnum() for c in s)

def shannon_entropy(s):
    if not s: return 0.0
    counts = Counter(s)
    length = len(s)
    H = 0.0
    for cnt in counts.values():
        p = cnt / length
        H -= p * math.log2(p)
    return H * length  # total bits

def pool_entropy(s):
    pool = 0
    if has_lower(s): pool += 26
    if has_upper(s): pool += 26
    if has_digit(s): pool += 10
    if has_symbol(s): pool += 32  # rough symbol count
    if pool == 0: return 0.0
    bits_per_char = math.log2(pool)
    return bits_per_char * len(s)

def classify_entropy(bits):
    if bits < 28: return "Very weak"
    if bits < 36: return "Weak"
    if bits < 60: return "Moderate"
    if bits < 128: return "Strong"
    return "Very strong"

def score_password(s, weak_set):
    if s in weak_set:
        return {'score': 0, 'label': 'Very weak (common password)',
                'entropy_shannon': round(shannon_entropy(s),2),
                'entropy_pool': round(pool_entropy(s),2)}
    score = 0
    if len(s) >= 8: score += SCORING['length']
    if has_upper(s): score += SCORING['upper']
    if has_lower(s): score += SCORING['lower']
    if has_digit(s): score += SCORING['digit']
    if has_symbol(s): score += SCORING['symbol']
    ent_sh = shannon_entropy(s)
    ent_pool = pool_entropy(s)
    ent = max(ent_sh, ent_pool)
    label = classify_entropy(ent)
    return {'score': score, 'label': label,
            'entropy_shannon': round(ent_sh,2), 'entropy_pool': round(ent_pool,2)}

def main():
    weak = load_weak()
    pwd = input("Password to check: ").strip()
    res = score_password(pwd, weak)
    print(f"Score: {res['score']}  Label: {res['label']}")
    print(f"Entropy (shannon): {res['entropy_shannon']} bits")
    print(f"Entropy (pool):    {res['entropy_pool']} bits")
    if pwd in weak:
        print("-> REJECT: password is in the weak list.")
        return
    print("Advice:")
    if len(pwd) < 12:
        print("- Use a longer passphrase (>=12 chars) or 3+ random words.")
    if not has_symbol(pwd):
        print("- Add symbols or punctuation.")
    if not (has_upper(pwd) and has_lower(pwd)):
        print("- Mix upper and lower case.")
    if not has_digit(pwd):
        print("- Add numbers.")

if __name__ == "__main__":
    main()
