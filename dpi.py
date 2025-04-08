import json
import os
import re

def load_signatures():
    file_path = os.path.join(os.path.dirname(__file__),"data","signatures.json")
    with open(file_path,"r") as f:
        return json.load(f)
    
SIGNATURES = load_signatures()

def check_sig(domain):  #signature based detection
    for sig in SIGNATURES:
        pattern = sig.get("pattern","")
        desc = sig.get("description","No description")
        if re.search(pattern, domain):
            return True, f"[SIGNATURE] {desc}"
        return False, None  

def check_heuristics(domain):
    parts = domain.split(".")
    if any(len(part)>25 for part in parts):
        return True, "[HEURISTIC] long subdomain part"
    if len(parts) > 6:
        return True, "[HEURISTIC] Excessive subdomains"

    if re.search(r"[a-z]{4,}[0-9]{4,}", domain) or re.search(r"[0-9]{4,}[a-z]{4,}", domain):
        return True, "[HEURISTIC] Random mix of letters and numbers"

    return False, None
def inspect_domain(domain):
    sig_match, sig_reason = check_sig(domain)
    if sig_match:
        return True, sig_reason
    heur_match, heur_reason = check_heuristics(domain)  
    if heur_match:
        return True, heur_reason
    return False, "domain appears safe"

if __name__ == "__main__":
    test_domains = [
        "malware-check.tk",
        "secure-login.c2server.net",
        "x9a8f3c1dweird.com",
        "deep.deep.sub.domain.structure.example.com",
        "legitdomain.org",
        "google.com",
        "chatgpt.com",
        "game.theinnovationlab.pes"


    ]

    for domain in test_domains:
        malicious, reason = inspect_domain(domain)
        print(f"{domain} --> Malicious: {malicious}, Reason: {reason}\n")