from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import os

from app.engine.taxonomy import ATTACK_TAXONOMY
from app.engine.targets import PRESET_TARGETS
from app.engine.fuzzer import run_fuzzing_barrage, test_single_probe_playground
from app.engine.guardrails import synthesize_guardrails, verify_guardrails, generate_repo_patch_artifacts
from app.engine.quota import consume_quota, get_quota_status
from app.clients.tavily_client import get_latest_threat_intel

app = FastAPI(
    title="NeMo-Sentry API",
    description="Autonomous AI Red-Teaming & NeMo Guardrail Synthesis Studio",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FuzzRequest(BaseModel):
    target_id_or_url: str = Field(default="customer_support", description="Preset ID or external HTTP URL")
    attack_vectors: List[str] = Field(
        default=["prompt_injection", "system_prompt_leakage", "pii_data_leakage"],
        description="List of attack vectors to test"
    )
    num_probes: int = Field(default=8, ge=2, le=30, description="Total number of probes to fire")
    target_api_key: Optional[str] = Field(default=None, description="Optional bearer token for external target")
    nebius_api_key: Optional[str] = Field(default=None, description="Optional ephemeral Nebius API key (BYOK - zero storage)")
    client_fingerprint: Optional[str] = Field(default=None, description="Client device hardware fingerprint")
    judge_passcode: Optional[str] = Field(default=None, description="VIP Judge Access Passcode")

class SingleProbeRequest(BaseModel):
    target_id_or_url: str = Field(default="customer_support", description="Target ID or URL")
    prompt: str = Field(..., description="Custom attack probe prompt to test")
    target_api_key: Optional[str] = Field(default=None, description="Optional bearer token")

class SynthesizeRequest(BaseModel):
    fuzz_results: dict

class VerifyRequest(BaseModel):
    fuzz_results: dict
    guardrails: dict

@app.get("/")
def read_root():
    return {
        "service": "NeMo-Sentry",
        "status": "online",
        "version": "1.2.0",
        "description": "Autonomous AI Red-Teaming & Guardrail Synthesis Studio",
        "infrastructure": "Nebius Token Factory & NVIDIA Nemotron-3",
        "threat_intel_engine": "Tavily AI Search",
        "access_control": "1-Run Public Demo / 10-Run Judge VIP / Unlimited BYOK (Zero Storage)"
    }

@app.get("/api/v1/quota-status")
def check_quota(
    fingerprint: Optional[str] = None,
    passcode: Optional[str] = None,
    has_byok: bool = False
):
    """Returns real-time device quota balance and tier status"""
    return get_quota_status(fingerprint, passcode, has_byok)

@app.get("/api/v1/targets")
def get_preset_targets():
    """Returns list of preset enterprise testbed targets with hardening metadata"""
    return [
        {
            "id": k,
            "name": v["name"],
            "industry": v["industry"],
            "vulnerabilities": v["vulnerabilities"],
            "hardening_level": v.get("hardening_level", "High"),
            "system_prompt_preview": v["system_prompt"][:140] + "..."
        }
        for k, v in PRESET_TARGETS.items()
    ]

@app.get("/api/v1/taxonomy")
def get_attack_taxonomy():
    """Returns the OWASP LLM attack vector taxonomy with exploit techniques"""
    return ATTACK_TAXONOMY

@app.get("/api/v1/threat-intel")
async def fetch_threat_intel(query: str = "Latest LLM prompt injection and jailbreak techniques 2026"):
    """Fetches real-time web threat intelligence using Tavily"""
    intel = await get_latest_threat_intel(query)
    return intel

@app.post("/api/v1/fuzz")
async def execute_fuzzing(
    req: FuzzRequest,
    x_nebius_api_key: Optional[str] = Header(None),
    x_client_fingerprint: Optional[str] = Header(None),
    x_judge_passcode: Optional[str] = Header(None)
):
    """
    Executes high-throughput concurrent fuzzing barrage powered by
    Nemotron-3 on Nebius Token Factory, grounded in Tavily threat intelligence.
    Enforces device quota (1 run public, 10 runs for Judge Passcode, unlimited BYOK).
    """
    # Prefer header if provided, fallback to request body
    effective_nebius_key = x_nebius_api_key or req.nebius_api_key
    effective_fingerprint = x_client_fingerprint or req.client_fingerprint or "anonymous_device"
    effective_passcode = x_judge_passcode or req.judge_passcode
    
    # 1. Enforce Quota & Access Control (protects hosted Nebius credits)
    allowed, err_msg, remaining, tier = consume_quota(
        fingerprint=effective_fingerprint,
        judge_passcode=effective_passcode,
        has_byok=bool(effective_nebius_key and effective_nebius_key.strip())
    )
    
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "QUOTA_EXCEEDED",
                "message": err_msg,
                "tier": tier,
                "remaining_runs": 0
            }
        )

    try:
        results = await run_fuzzing_barrage(
            target_id_or_url=req.target_id_or_url,
            vectors=req.attack_vectors,
            total_probes=req.num_probes,
            target_api_key=req.target_api_key,
            nebius_api_key=effective_nebius_key
        )
        
        # Attach quota status to response payload
        results["quota_info"] = {
            "tier": tier,
            "remaining_runs": remaining,
            "has_byok": bool(effective_nebius_key)
        }
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fuzzing engine error: {str(e)}")

@app.post("/api/v1/test-single-probe")
async def execute_single_probe_test(req: SingleProbeRequest):
    """
    Executes interactive side-by-side test of a single custom prompt
    (Unguarded vs NeMo Shielded).
    """
    try:
        result = await test_single_probe_playground(
            target_id_or_url=req.target_id_or_url,
            custom_prompt=req.prompt,
            target_api_key=req.target_api_key
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Playground test error: {str(e)}")

@app.post("/api/v1/synthesize")
async def execute_guardrail_synthesis(req: SynthesizeRequest):
    """
    Synthesizes production-ready Colang 2.0 and config.yml policies using Nemotron-3-Ultra.
    """
    try:
        guardrails = await synthesize_guardrails(req.fuzz_results)
        return guardrails
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Synthesis error: {str(e)}")

@app.post("/api/v1/verify")
async def execute_guardrail_verification(req: VerifyRequest):
    """
    Mathematically verifies that synthesized guardrails eliminate 100% of discovered breaches.
    """
    try:
        verification = await verify_guardrails(req.fuzz_results, req.guardrails)
        return verification
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification error: {str(e)}")

@app.post("/api/v1/generate-patch")
async def execute_repo_patch_generation(req: VerifyRequest):
    """
    Generates actionable repository patch artifacts:
    1. Unified Git patch (`nemo_guardrails.patch`)
    2. GitHub Actions CI/CD workflow (`nemo_sentry_ci.yml`)
    3. Standalone production proxy server (`server.py`)
    """
    try:
        patch_artifacts = generate_repo_patch_artifacts(req.fuzz_results, req.guardrails)
        return patch_artifacts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Patch generation error: {str(e)}")
