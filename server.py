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

mcp = FastMCP("Who-Dat WHOIS Lookup")

BASE_URL = "https://who-dat.as93.net"
DEFAULT_AUTH_KEY = os.environ.get("AUTH_KEY", "")


def _build_headers(api_key: Optional[str] = None) -> dict:
    """Build request headers, adding Bearer auth if an API key is available."""
    headers = {}
    key = api_key or DEFAULT_AUTH_KEY
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


@mcp.tool()
async def whois_lookup(domain: str, api_key: Optional[str] = None) -> dict:
    """
    Look up WHOIS information for a single domain. Use this when the user wants
    to find registration details, expiry dates, registrar info, nameservers, or
    ownership information for one specific domain.

    Args:
        domain: The fully qualified domain name to look up (e.g., 'example.com', 'google.com').
        api_key: Optional API key for authentication. Will be sent as a Bearer token.
    """
    headers = _build_headers(api_key)
    url = f"{BASE_URL}/{domain}"

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)

    if response.status_code == 403:
        return {"error": "Authentication required or invalid API key.", "status_code": 403}
    if response.status_code == 400:
        return {"error": "Bad request. Please provide a valid domain name.", "status_code": 400}
    if not response.is_success:
        return {
            "error": f"Request failed with status {response.status_code}",
            "status_code": response.status_code,
            "detail": response.text,
        }

    try:
        return response.json()
    except Exception:
        return {"raw": response.text}


@mcp.tool()
async def whois_lookup_multi(domains: List[str], api_key: Optional[str] = None) -> dict:
    """
    Look up WHOIS information for multiple domains in a single request. Use this
    when the user wants to compare or batch-check registration details for several
    domains at once. Note: subject to a 2-second server-side timeout, so keep
    the list reasonably short.

    Args:
        domains: List of domain names to look up (e.g., ['example.com', 'google.com']).
        api_key: Optional API key for authentication. Will be sent as a Bearer token.
    """
    if not domains:
        return {"error": "No domains provided. Please supply at least one domain."}

    headers = _build_headers(api_key)
    domains_param = ",".join(d.strip() for d in domains)
    url = f"{BASE_URL}/multi"
    params = {"domains": domains_param}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers, params=params)

    if response.status_code == 403:
        return {"error": "Authentication required or invalid API key.", "status_code": 403}
    if response.status_code == 400:
        return {"error": "Bad request. Please provide valid domain names.", "status_code": 400}
    if not response.is_success:
        return {
            "error": f"Request failed with status {response.status_code}",
            "status_code": response.status_code,
            "detail": response.text,
        }

    try:
        return response.json()
    except Exception:
        return {"raw": response.text}


@mcp.tool()
async def health_check() -> dict:
    """
    Check if the WHOIS API server is reachable and healthy. Use this to verify
    connectivity before making other requests, or when the user asks if the
    service is up.
    """
    url = f"{BASE_URL}/ping"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)

        if response.is_success and response.text.strip().lower() == "pong":
            return {"status": "healthy", "message": "API is reachable and responding correctly.", "response": response.text.strip()}
        else:
            return {
                "status": "unhealthy",
                "message": f"Unexpected response from API.",
                "status_code": response.status_code,
                "response": response.text.strip(),
            }
    except httpx.ConnectError:
        return {"status": "unreachable", "message": "Could not connect to the WHOIS API server."}
    except httpx.TimeoutException:
        return {"status": "timeout", "message": "Connection to the WHOIS API server timed out."}
    except Exception as e:
        return {"status": "error", "message": str(e)}




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
