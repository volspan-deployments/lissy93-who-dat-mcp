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
AUTH_KEY = os.environ.get("AUTH_KEY", "")


def build_headers(api_key: Optional[str] = None) -> dict:
    """Build authorization headers."""
    headers = {}
    key = api_key or AUTH_KEY
    if key:
        # Strip existing Bearer prefix if present to normalize
        if key.lower().startswith("bearer "):
            key = key[7:]
        headers["Authorization"] = f"Bearer {key}"
    return headers


@mcp.tool()
async def check_health() -> dict:
    """Check if the WHOIS API service is alive and responding. Use this before making other requests to verify the service is up, or when troubleshooting connectivity issues."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{BASE_URL}/ping", timeout=10.0)
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
    """Look up WHOIS information for a single domain name. Returns registration details including registrar, creation date, expiration date, name servers, and registrant information. Use this when you need detailed WHOIS data for one specific domain.

    Args:
        domain: The fully qualified domain name to look up (e.g. 'example.com', 'google.co.uk')
        api_key: API key for authentication, required only if the server is configured with AUTH_KEY. Can be a raw key or Bearer token.
    """
    headers = build_headers(api_key)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{BASE_URL}/{domain}",
                headers=headers,
                timeout=15.0
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "error": response.text,
                    "status_code": response.status_code,
                    "domain": domain
                }
        except httpx.RequestError as e:
            return {
                "error": str(e),
                "domain": domain
            }


@mcp.tool()
async def lookup_multiple_domains(domains: List[str], api_key: Optional[str] = None) -> dict:
    """Look up WHOIS information for multiple domains in a single request. More efficient than calling lookup_domain repeatedly. Has a 2-second timeout, so use for reasonably sized batches. Use this when comparing domain registrations or checking ownership across a list of domains.

    Args:
        domains: List of domain names to look up (e.g. ['example.com', 'google.com', 'github.com']). Will be sent as a comma-separated query parameter.
        api_key: API key for authentication, required only if the server is configured with AUTH_KEY. Can be a raw key or Bearer token.
    """
    if not domains:
        return {"error": "No domains provided"}

    headers = build_headers(api_key)
    domains_param = ",".join(domains)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{BASE_URL}/multi",
                params={"domains": domains_param},
                headers=headers,
                timeout=10.0
            )
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "error": response.text,
                    "status_code": response.status_code,
                    "domains": domains
                }
        except httpx.TimeoutException:
            return {
                "error": "Request timed out. The multi-domain endpoint has a 2-second server-side timeout. Try fewer domains.",
                "domains": domains
            }
        except httpx.RequestError as e:
            return {
                "error": str(e),
                "domains": domains
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
