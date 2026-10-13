import os
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

# We configure the OpenAI client to point to the Nebius Token Factory
NEBIUS_API_KEY = os.getenv("NEBIUS_API_KEY", "")
NEBIUS_BASE_URL = "https://api.nebius.ai/v1/"

nebius_client = AsyncOpenAI(
    base_url=NEBIUS_BASE_URL,
    api_key=NEBIUS_API_KEY,
)

# Models defined for the hackathon
NEMOTRON_ULTRA = "nvidia/nemotron-3-ultra"
NEMOTRON_SUPER = "nvidia/nemotron-3-super"
NEMOTRON_NANO = "nvidia/nemotron-3-nano"

async def generate_completion(prompt: str, model: str = NEMOTRON_NANO, system_prompt: str = "You are an AI assistant.", temperature: float = 0.7):
    """
    Wrapper for querying Nemotron models on Nebius Token Factory.
    """
    response = await nebius_client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        temperature=temperature,
        max_tokens=2048,
    )
    return response.choices[0].message.content
