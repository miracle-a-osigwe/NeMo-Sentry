from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="NeMo-Sentry API", description="Autonomous LLM Red-Teaming & Guardrail Synthesis Studio")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FuzzRequest(BaseModel):
    target_endpoint: str
    target_type: str = "openai_compatible"
    attack_vectors: list[str] = ["prompt_injection", "jailbreak", "data_leakage"]
    num_probes: int = 10

@app.get("/")
def read_root():
    return {"status": "ok", "message": "NeMo-Sentry API is running"}

@app.post("/api/v1/fuzz")
async def start_fuzzing(req: FuzzRequest):
    from app.engine.fuzzer import run_fuzzing_job
    from app.engine.guardrails import synthesize_guardrails
    from app.clients.tavily_client import get_latest_threat_intel
    
    # 1. Fetch latest threats using Tavily
    latest_threats = await get_latest_threat_intel("Latest LLM jailbreaks and CVEs")
    
    # 2. Run the fuzzing barrage (simulated)
    fuzz_results = await run_fuzzing_job(
        target_endpoint=req.target_endpoint,
        vectors=req.attack_vectors,
        num_probes=req.num_probes
    )
    
    # 3. Synthesize Guardrails for any breaches
    guardrails_code = await synthesize_guardrails(fuzz_results)
    
    return {
        "status": "completed",
        "threat_intel_used": latest_threats[:200] + "...",
        "fuzz_results": fuzz_results,
        "synthesized_colang": guardrails_code
    }
