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

mcp = FastMCP("Who-Dat")

BASE_URL = "https://who-dat.as93.net"
AUTH_KEY = os.environ.get("AUTH_KEY", "")


def _build_headers(api_key: Optional[str] = None) -> dict:
    """Build the authorization headers for the request."""
    headers = {}
    key = api_key or AUTH_KEY
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


@mcp.tool()
async def whois_lookup(domain: str, api_key: Optional[str] = None) -> dict:
    """Look up WHOIS information for a single domain name. Use this when you need registration details, expiry dates, registrar info, name servers, or ownership data for one specific domain."""
    headers = _build_headers(api_key)
    url = f"{BASE_URL}/{domain}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            try:
                return response.json()
            except Exception:
                return {"raw": response.text}
        else:
            return {
                "error": True,
                "status_code": response.status_code,
                "message": response.text
            }


@mcp.tool()
async def whois_lookup_multi(domains: List[str], api_key: Optional[str] = None) -> dict:
    """Look up WHOIS information for multiple domains in a single request. Use this when you need to compare registration details across several domains at once. Note: subject to a 2-second timeout, so results for some domains may be missing if lookups are slow."""
    headers = _build_headers(api_key)
    domains_param = ",".join(domains)
    url = f"{BASE_URL}/multi"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers, params={"domains": domains_param})
        if response.status_code == 200:
            try:
                return response.json()
            except Exception:
                return {"raw": response.text}
        else:
            return {
                "error": True,
                "status_code": response.status_code,
                "message": response.text
            }


@mcp.tool()
async def health_check() -> dict:
    """Check if the WHOIS API server is up and reachable. Use this to verify connectivity before making other requests, or to diagnose issues when lookups are failing."""
    url = f"{BASE_URL}/ping"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(url)
            if response.status_code == 200 and response.text.strip() == "pong":
                return {"status": "ok", "message": "API server is online and healthy", "response": response.text.strip()}
            else:
                return {
                    "status": "degraded",
                    "message": "API server responded but with unexpected content",
                    "status_code": response.status_code,
                    "response": response.text
                }
        except httpx.ConnectError as e:
            return {"status": "unreachable", "message": f"Could not connect to API server: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"status": "timeout", "message": f"API server timed out: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"Unexpected error: {str(e)}"}




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
