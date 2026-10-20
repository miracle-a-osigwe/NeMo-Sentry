"""
NeMo-Sentry Quota & Access Control Engine.
Protects hosted Nebius Token Factory inference credits from runaway public drain
while providing frictionless VIP access for hackathon judges and zero-storage BYOK.
"""

import time
from typing import Dict, Tuple

# Quota configurations
PUBLIC_MAX_RUNS = 1
JUDGE_MAX_RUNS = 10
JUDGE_VALID_PASSCODES = {"NEBIUS-JUDGE-2026", "NVIDIA-VIP-2026", "DEVPOST-JUDGE-2026"}

# In-memory tracking: { fingerprint_hash: { "runs": int, "tier": str, "last_seen": float } }
# Volatile in-memory only — never persists user data to disk.
_DEVICE_QUOTA_CACHE: Dict[str, dict] = {}

def get_quota_status(fingerprint: str, judge_passcode: str = None, has_byok: bool = False) -> dict:
    """
    Returns current quota balance and tier for a client device fingerprint.
    """
    clean_fp = (fingerprint or "anonymous_device").strip()
    is_judge = bool(judge_passcode and judge_passcode.strip().upper() in JUDGE_VALID_PASSCODES)
    
    if has_byok:
        return {
            "tier": "byok",
            "tier_label": "Bring-Your-Own-Key (BYOK)",
            "allowed": True,
            "remaining_runs": 9999,
            "max_runs": 9999,
            "runs_used": 0,
            "message": "Unlimited runs active via your client-provided Nebius key (Zero-Storage Guarantee)."
        }
        
    device_record = _DEVICE_QUOTA_CACHE.get(clean_fp)
    runs_used = device_record["runs"] if device_record else 0
    
    if is_judge:
        max_runs = JUDGE_MAX_RUNS
        tier = "judge"
        tier_label = "Devpost Judge VIP"
    else:
        max_runs = PUBLIC_MAX_RUNS
        tier = "public"
        tier_label = "Public Demo Sandbox"
        
    remaining = max(0, max_runs - runs_used)
    
    return {
        "tier": tier,
        "tier_label": tier_label,
        "allowed": remaining > 0,
        "remaining_runs": remaining,
        "max_runs": max_runs,
        "runs_used": runs_used,
        "message": f"{remaining} of {max_runs} live cloud runs remaining on this device."
    }

def consume_quota(fingerprint: str, judge_passcode: str = None, has_byok: bool = False) -> Tuple[bool, str, int, str]:
    """
    Attempts to consume 1 run from the client's quota pool.
    Returns (is_allowed, error_message, remaining_runs, tier).
    """
    # 1. BYOK users always pass without depleting hosted credits
    if has_byok:
        return True, "BYOK pass granted", 9999, "byok"
        
    clean_fp = (fingerprint or "anonymous_device").strip()
    is_judge = bool(judge_passcode and judge_passcode.strip().upper() in JUDGE_VALID_PASSCODES)
    
    now = time.time()
    if clean_fp not in _DEVICE_QUOTA_CACHE:
        _DEVICE_QUOTA_CACHE[clean_fp] = {
            "runs": 0,
            "tier": "judge" if is_judge else "public",
            "last_seen": now
        }
        
    record = _DEVICE_QUOTA_CACHE[clean_fp]
    record["last_seen"] = now
    
    # If client upgraded to Judge passcode, upgrade tier
    if is_judge and record["tier"] != "judge":
        record["tier"] = "judge"
        
    max_runs = JUDGE_MAX_RUNS if record["tier"] == "judge" else PUBLIC_MAX_RUNS
    
    if record["runs"] >= max_runs:
        tier_name = "Judge VIP (10 runs)" if record["tier"] == "judge" else "Public Demo (1 run)"
        err_msg = (
            f"Quota limit reached for {tier_name}. "
            "To continue testing, enter your own Nebius API Key in the header "
            "(BYOK - Zero-Storage Guarantee, promo code: NEBIUS-DEVPOST-GLOBAL26) "
            "or enter Judge VIP Passcode: NEBIUS-JUDGE-2026."
        )
        return False, err_msg, 0, record["tier"]
        
    # Consume 1 run
    record["runs"] += 1
    remaining = max(0, max_runs - record["runs"])
    return True, "Quota verified", remaining, record["tier"]
