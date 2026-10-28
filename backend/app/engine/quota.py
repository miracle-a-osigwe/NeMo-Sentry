"""
NeMo-Sentry Quota & Access Control Engine.
Protects hosted Nebius Token Factory inference credits from runaway public drain
while providing frictionless unlimited access on localhost/dev environments,
10-run VIP access for hackathon judges, and zero-storage BYOK.
"""

import os
import time
from typing import Dict, Tuple

# Quota configurations
PUBLIC_MAX_RUNS = 1
JUDGE_MAX_RUNS = 10

# Decoy passcodes that act as a honeypot
DECOY_JUDGE_PASSCODES = {"NEBIUS-JUDGE-2026", "DEVPOST-JUDGE-2026"}
DECOY_TRAP_MESSAGE = (
    "SMILES... 👀 Nice try! That’s a demo key, not your ticket in. \n\n"
    "Judges: use the access key provided to you. \n\n"
    "Everyone else: add your own API key in the API Key section to unlock the experience. Go on, try it for yourself!"
)

def get_valid_judge_passcodes() -> set:
    """
    Returns valid private judge evaluation passcodes.
    Dynamically reads REAL_JUDGE_PASSCODE and REAL_JUDGE_PASSCODES from environment
    so operators can customize their private judge key at any time without altering code.
    """
    configured = os.getenv("REAL_JUDGE_PASSCODE", "NVIDIA-VIP-SENTINEL-2026").strip().upper()
    extra = {p.strip().upper() for p in os.getenv("REAL_JUDGE_PASSCODES", "").split(",") if p.strip()}
    return {configured, "NVIDIA-VIP-SENTINEL-2026", "NVIDIA-VIP-2026"} | extra

# Environment variable to control whether public quota enforcement is active.
# On localhost / local dev (default ENFORCE_PUBLIC_QUOTA != "true"), runs are unlimited
# and use the backend environment keys without prompting the user for an API key.
# Set ENFORCE_PUBLIC_QUOTA=true in production cloud deployments to enforce the 1-run sandbox.
def is_quota_enforced(is_localhost: bool = False) -> bool:
    env_flag = os.getenv("ENFORCE_PUBLIC_QUOTA", "").strip().lower()
    if env_flag == "true":
        return True
    if env_flag == "false":
        return False
    # If not explicitly set, bypass quota on localhost and enforce only on non-localhost live hosts
    return not is_localhost

# In-memory tracking: { fingerprint_hash: { "runs": int, "tier": str, "last_seen": float } }
# Volatile in-memory only — never persists user data to disk.
_DEVICE_QUOTA_CACHE: Dict[str, dict] = {}

def get_quota_status(
    fingerprint: str,
    judge_passcode: str = None,
    has_byok: bool = False,
    is_localhost: bool = False
) -> dict:
    """
    Returns current quota balance and tier for a client device fingerprint.
    """
    clean_fp = (fingerprint or "anonymous_device").strip()
    clean_passcode = (judge_passcode or "").strip().upper()

    # 1. Check for decoy honeypot passcode
    if clean_passcode in DECOY_JUDGE_PASSCODES:
        return {
            "tier": "decoy",
            "tier_label": "Honeypot Trap Triggered",
            "allowed": False,
            "is_decoy": True,
            "remaining_runs": 0,
            "max_runs": 0,
            "runs_used": 0,
            "message": DECOY_TRAP_MESSAGE
        }

    # 2. Check for real judge VIP passcode
    valid_codes = get_valid_judge_passcodes()
    is_judge = bool(clean_passcode in valid_codes)

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

    if not is_quota_enforced(is_localhost=is_localhost) and not is_judge:
        return {
            "tier": "local_dev",
            "tier_label": "Localhost Dev (Unlimited)",
            "allowed": True,
            "remaining_runs": 9999,
            "max_runs": 9999,
            "runs_used": 0,
            "message": "Localhost environment detected — unlimited runs active via backend environment credentials."
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

def consume_quota(
    fingerprint: str,
    judge_passcode: str = None,
    has_byok: bool = False,
    is_localhost: bool = False
) -> Tuple[bool, str, int, str]:
    """
    Attempts to consume 1 run from the client's quota pool.
    Returns (is_allowed, error_message, remaining_runs, tier).
    """
    clean_passcode = (judge_passcode or "").strip().upper()

    # 0. Check for decoy honeypot passcode
    if clean_passcode in DECOY_JUDGE_PASSCODES:
        return False, DECOY_TRAP_MESSAGE, 0, "decoy"

    valid_codes = get_valid_judge_passcodes()

    # 1. BYOK users always pass without depleting hosted credits
    if has_byok:
        return True, "BYOK pass granted", 9999, "byok"

    # 2. Localhost / Dev environment bypasses public quota when ENFORCE_PUBLIC_QUOTA is not true
    if not is_quota_enforced(is_localhost=is_localhost) and clean_passcode not in valid_codes:
        return True, "Localhost dev unlimited pass", 9999, "local_dev"

    clean_fp = (fingerprint or "anonymous_device").strip()
    is_judge = bool(clean_passcode in valid_codes)

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
        if record["tier"] == "judge":
            err_msg = (
                "Judge VIP 10-run evaluation limit reached. "
                "To continue exploring beyond 10 full runs, please enter your own Nebius API Key in the BYOK tab "
                "(Zero-Storage Guarantee, promo code: NEBIUS-DEVPOST-GLOBAL26)."
            )
        else:
            err_msg = (
                "Public Demo sandbox limit reached (1 run). "
                "To continue testing, enter your own Nebius API Key via the BYOK tab "
                "(Zero-Storage Guarantee, promo code: NEBIUS-DEVPOST-GLOBAL26) "
                "or enter your Judge VIP Passcode."
            )
        return False, err_msg, 0, record["tier"]

    # Consume 1 run
    record["runs"] += 1
    remaining = max(0, max_runs - record["runs"])
    return True, "Quota verified", remaining, record["tier"]
