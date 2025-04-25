import math
import os
import re
import json

# Load signature patterns from file
def load_signatures():
    file_path = os.path.join(os.path.dirname(__file__), "data", "signatures.json")
    with open(file_path, "r") as f:
        return json.load(f)

SIGNATURES = load_signatures()

def check_sig(domain):
    for sig in SIGNATURES:
        pattern = sig.get("pattern", "")
        desc = sig.get("description", "No description")
        if re.search(pattern, domain, re.IGNORECASE):
            return True, f"[SIGNATURE] {desc}"
    return False, None

def shannon_entropy(s):
    if not s:
        return 0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def check_heuristics(domain):
    parts = domain.split(".")

    # Check for excessive subdomains or long labels
    if any(len(part) > 25 for part in parts):
        return True, "[HEURISTIC] Long subdomain part"
    if len(parts) > 6:
        return True, "[HEURISTIC] Excessive subdomains"

    # Interleaved letters & digits (e.g., jdk3noolehi3)
    if re.search(r"[a-z]{2,}[0-9]{2,}[a-z0-9]*[0-9]{2,}", domain, re.IGNORECASE):
        return True, "[HEURISTIC] Interleaved letters and numbers"

    # Repeating patterns like ababab, xyzxyz
    if re.search(r"([a-z0-9]{3,})\1", domain, re.IGNORECASE):
        return True, "[HEURISTIC] Repeating pattern"

    # High entropy
    name_only = "".join(parts[:-1])
    entropy = shannon_entropy(name_only.lower())
    if entropy > 3.8:
        return True, f"[HEURISTIC] High entropy ({entropy:.2f})"

    # Low vowel-to-consonant ratio
    vowels = sum(1 for c in domain if c in "aeiou")
    consonants = sum(1 for c in domain if c.isalpha() and c not in "aeiou")
    if consonants > 8 and (vowels / (consonants + 1)) < 0.2:
        return True, "[HEURISTIC] Low vowel-consonant ratio"

    # Consecutive consonants (e.g., "jdkrtxv")
    if re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", domain, re.IGNORECASE):
        return True, "[HEURISTIC] Long consonant run"

    return False, None

def inspect_domain(domain):
    sig_match, sig_reason = check_sig(domain)
    if sig_match:
        return True, sig_reason

    heur_match, heur_reason = check_heuristics(domain)
    if heur_match:
        return True, heur_reason

    return False, "domain appears safe"

