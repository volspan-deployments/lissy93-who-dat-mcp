from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
from typing import Optional, List
from dotenv import load_dotenv

load_dotenv()

mcp = FastMCP("Who-Dat WHOIS Server")

BASE_URL = "https://who-dat.as93.net"


def _get_auth_headers(api_key: Optional[str] = None) -> dict:
    """Build authorization headers from env var or provided key."""
    key = api_key or os.environ.get("AUTH_KEY", "")
    if not key:
        return {}
    # Strip existing Bearer prefix if present to normalize
    if key.lower().startswith("bearer "):
        key = key[7:]
    return {"Authorization": f"Bearer {key}"}


@mcp.tool()
async def check_health() -> dict:
    """Ping the WHOIS API server to verify it is online and reachable. Use this before making other calls if you are unsure whether the service is available, or to diagnose connectivity issues."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{BASE_URL}/ping", timeout=10.0)
            return {
                "status_code": response.status_code,
                "response": response.text,
                "online": response.status_code == 200 and response.text.strip() == "pong"
            }
        except httpx.RequestError as e:
            return {
                "status_code": None,
                "response": str(e),
                "online": False
            }


@mcp.tool()
async def lookup_domain(domain: str, api_key: Optional[str] = None) -> dict:
    """Retrieve full WHOIS registration information for a single domain name, including registrar, registration/expiration dates, nameservers, and registrant contact details. Use this when you need detailed WHOIS data for one specific domain.

    Args:
        domain: The fully qualified domain name to look up, e.g. 'example.com' or 'google.co.uk'.
        api_key: API key for authentication. Required only if the server is configured with an AUTH_KEY. Can be a raw key or a Bearer token.
    """
    headers = _get_auth_headers(api_key)
    url = f"{BASE_URL}/{domain}"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=15.0)
            if response.status_code == 200:
                try:
                    return response.json()
                except Exception:
                    return {"raw": response.text, "status_code": response.status_code}
            else:
                return {
                    "error": response.text,
                    "status_code": response.status_code
                }
        except httpx.RequestError as e:
            return {
                "error": str(e),
                "status_code": None
            }


@mcp.tool()
async def lookup_multiple_domains(domains: List[str], api_key: Optional[str] = None) -> dict:
    """Retrieve WHOIS information for several domains concurrently in a single request with a 2-second timeout. Use this when you need to compare registration details or check ownership/expiry across multiple domains at once, rather than making separate individual lookups.

    Args:
        domains: List of domain names to look up simultaneously, e.g. ['example.com', 'google.com', 'github.io']. Will be sent as a comma-separated query parameter.
        api_key: API key for authentication. Required only if the server is configured with an AUTH_KEY. Can be a raw key or a Bearer token.
    """
    if not domains:
        return {"error": "No domains provided", "status_code": 400}

    headers = _get_auth_headers(api_key)
    domains_param = ",".join(domains)
    url = f"{BASE_URL}/multi"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                url,
                params={"domains": domains_param},
                headers=headers,
                timeout=15.0
            )
            if response.status_code == 200:
                try:
                    return response.json()
                except Exception:
                    return {"raw": response.text, "status_code": response.status_code}
            else:
                return {
                    "error": response.text,
                    "status_code": response.status_code
                }
        except httpx.RequestError as e:
            return {
                "error": str(e),
                "status_code": None
            }




_SERVER_SLUG = "lissy93-who-dat"

def _track(tool_name: str, ua: str = ""):
    try:
        import urllib.request, json as _json
        data = _json.dumps({"slug": _SERVER_SLUG, "event": "tool_call", "tool": tool_name, "user_agent": ua}).encode()
        req = urllib.request.Request("https://www.volspan.dev/api/analytics/event", data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass

async def health(request):
    return JSONResponse({"status": "ok", "server": mcp.name})

async def tools(request):
    registered = await mcp.list_tools()
    tool_list = [{"name": t.name, "description": t.description or ""} for t in registered]
    return JSONResponse({"tools": tool_list, "count": len(tool_list)})

sse_app = mcp.http_app(transport="sse")

app = Starlette(
    routes=[
        Route("/health", health),
        Route("/tools", tools),
        Mount("/", sse_app),
    ],
    lifespan=sse_app.lifespan,
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
