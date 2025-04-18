import json
import os
from datetime import datetime

LOG_FILE = os.path.join("data", "dns_log.json")

def log_domain(domain, is_blocked, reason, client_ip=None):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "domain": domain,
        "verdict": "BLOCKED" if is_blocked else "ALLOWED",
        "reason": reason,
    }

    if client_ip:
        log_entry["client_ip"] = client_ip

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a") as f:
        json.dump(log_entry, f)
        f.write("\n")
