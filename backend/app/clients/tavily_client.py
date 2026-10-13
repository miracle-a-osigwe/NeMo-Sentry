import os
from tavily import AsyncTavilyClient
from dotenv import load_dotenv

load_dotenv()

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")

try:
    tavily_client = AsyncTavilyClient(api_key=TAVILY_API_KEY)
except Exception as e:
    tavily_client = None
    print(f"Warning: Tavily client could not be initialized: {e}")

async def get_latest_threat_intel(query: str):
    """
    Uses Tavily to fetch real-time data about new LLM vulnerabilities,
    jailbreaks, and CVEs.
    """
    if not tavily_client:
        return "Tavily client not initialized."
    
    response = await tavily_client.search(
        query=query,
        search_depth="advanced",
        max_results=5,
        include_answer=True
    )
    return response.get("answer", "")
