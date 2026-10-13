from app.clients.nebius import generate_completion, NEMOTRON_ULTRA

async def synthesize_guardrails(fuzz_results: list[dict]):
    """
    Analyzes the successful breaches and synthesizes NVIDIA NeMo Guardrails
    (.co files and config.yml) to patch them.
    """
    # Filter for successful attacks
    breaches = [res["prompt"] for res in fuzz_results if res["success"]]
    
    if not breaches:
        return "No vulnerabilities found. System is secure."
        
    prompt = f"""
    Based on the following successful jailbreak prompts, generate NVIDIA NeMo Guardrails Colang code to prevent them.
    
    Breaches:
    {breaches}
    
    Output valid Colang code (.co).
    """
    
    colang_code = await generate_completion(
        prompt=prompt,
        model=NEMOTRON_ULTRA,
        system_prompt="You are a security engineer specializing in NVIDIA NeMo Guardrails (Colang). Write Colang specs.",
        temperature=0.2
    )
    
    return colang_code
