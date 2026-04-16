from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
from typing import Optional, List

mcp = FastMCP("Who-Dat")

BASE_URL = "https://who-dat.as93.net"
AUTH_KEY = os.environ.get("AUTH_KEY", "")


def _get_headers(api_key: Optional[str] = None) -> dict:
    """Build authorization headers, preferring tool-provided key over env var."""
    key = api_key or AUTH_KEY
    if not key:
        return {}
    # Strip existing Bearer prefix if present
    if key.lower().startswith("bearer "):
        key = key[7:]
    return {"Authorization": f"Bearer {key}"}


@mcp.tool()
async def check_health() -> dict:
    """Check if the Who-Dat WHOIS API service is up and running. Use this to verify connectivity before making domain lookups, or to diagnose service availability issues."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"{BASE_URL}/ping")
            return {
                "status": "ok" if response.status_code == 200 else "error",
                "status_code": response.status_code,
                "response": response.text
            }
        except httpx.RequestError as e:
            return {
                "status": "error",
                "error": str(e)
            }


@mcp.tool()
async def lookup_domain(domain: str, api_key: Optional[str] = None) -> dict:
    """Retrieve WHOIS information for a single domain name, including registrar, registration dates, nameservers, and registrant details. Use this when the user wants to look up ownership or registration info for one specific domain."""
    headers = _get_headers(api_key)
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                f"{BASE_URL}/{domain}",
                headers=headers
            )
            if response.status_code == 403:
                return {
                    "error": "Authentication required or invalid API key.",
                    "status_code": 403
                }
            if response.status_code != 200:
                return {
                    "error": f"Request failed with status {response.status_code}",
                    "status_code": response.status_code,
                    "detail": response.text
                }
            return response.json()
        except httpx.RequestError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}


@mcp.tool()
async def lookup_domains_bulk(domains: List[str], api_key: Optional[str] = None) -> dict:
    """Retrieve WHOIS information for multiple domains concurrently in a single request. Use this when the user wants to compare registration details across several domains or check availability/ownership of multiple domains at once. Results are returned with a 2-second timeout per batch."""
    if not domains:
        return {"error": "No domains provided."}
    headers = _get_headers(api_key)
    domains_query = ",".join(domains)
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(
                f"{BASE_URL}/multi",
                params={"domains": domains_query},
                headers=headers
            )
            if response.status_code == 403:
                return {
                    "error": "Authentication required or invalid API key.",
                    "status_code": 403
                }
            if response.status_code != 200:
                return {
                    "error": f"Request failed with status {response.status_code}",
                    "status_code": response.status_code,
                    "detail": response.text
                }
            return response.json()
        except httpx.RequestError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}




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
