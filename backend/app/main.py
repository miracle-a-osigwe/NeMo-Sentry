import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional

from app.engine.taxonomy import ATTACK_TAXONOMY
from app.engine.targets import PRESET_TARGETS
from app.engine.fuzzer import run_fuzzing_barrage, test_single_probe_playground
from app.engine.guardrails import synthesize_guardrails, verify_guardrails, generate_repo_patch_artifacts
from app.clients.tavily_client import get_latest_threat_intel

app = FastAPI(
    title="NeMo-Sentry API",
    description="Autonomous LLM Red-Teaming & NVIDIA NeMo Guardrails Synthesizer on Nebius Token Factory",
    version="1.1.0"
)

# Enable CORS for local Vite development and deployed frontends
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
    nebius_api_key: Optional[str] = Field(default=None, description="Optional Nebius Token Factory API key override")

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
        "version": "1.1.0",
        "description": "Autonomous AI Red-Teaming & Guardrail Synthesis Studio",
        "infrastructure": "Nebius Token Factory & NVIDIA Nemotron-3",
        "threat_intel_engine": "Tavily AI Search"
    }

@app.get("/api/v1/targets")
def get_preset_targets():
    """Returns list of preset enterprise testbed targets"""
    return [
        {
            "id": k,
            "name": v["name"],
            "industry": v["industry"],
            "vulnerabilities": v["vulnerabilities"],
            "system_prompt_preview": v["system_prompt"][:120] + "..."
        }
        for k, v in PRESET_TARGETS.items()
    ]

@app.get("/api/v1/taxonomy")
def get_attack_taxonomy():
    """Returns the OWASP LLM attack vector taxonomy"""
    return ATTACK_TAXONOMY

@app.get("/api/v1/threat-intel")
async def fetch_threat_intel(query: str = "Latest LLM prompt injection and jailbreak techniques 2026"):
    """Fetches real-time web threat intelligence using Tavily"""
    intel = await get_latest_threat_intel(query)
    return intel

@app.post("/api/v1/fuzz")
async def execute_fuzzing(req: FuzzRequest):
    """
    Executes high-throughput concurrent fuzzing barrage powered by
    Nemotron-3 on Nebius Token Factory, grounded in Tavily threat intelligence.
    """
    try:
        results = await run_fuzzing_barrage(
            target_id_or_url=req.target_id_or_url,
            vectors=req.attack_vectors,
            total_probes=req.num_probes,
            target_api_key=req.target_api_key,
            nebius_api_key=req.nebius_api_key
        )
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
