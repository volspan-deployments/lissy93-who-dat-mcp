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


def get_auth_headers(authorization: Optional[str] = None) -> dict:
    """Build authentication headers."""
    headers = {}
    if authorization:
        # Use the provided authorization header as-is
        headers["Authorization"] = authorization
    elif AUTH_KEY:
        headers["Authorization"] = f"Bearer {AUTH_KEY}"
    return headers


@mcp.tool()
async def check_health() -> dict:
    """Ping the API to verify it is running and reachable. Use this before making other requests to confirm the service is available, or to diagnose connectivity issues."""
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
                "message": str(e)
            }


@mcp.tool()
async def get_whois(
    domain: str,
    authorization: Optional[str] = None
) -> dict:
    """Fetch WHOIS registration information for a single domain name. Use this to look up ownership, registrar, creation/expiration dates, nameservers, and other domain metadata for one specific domain."""
    if not domain:
        return {"error": "Domain parameter is required"}

    # Strip protocol if present
    domain = domain.replace("http://", "").replace("https://", "").strip("/")

    headers = get_auth_headers(authorization)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{BASE_URL}/{domain}",
                headers=headers,
                timeout=30.0
            )
            if response.status_code == 200:
                try:
                    return response.json()
                except Exception:
                    return {"response": response.text}
            else:
                return {
                    "error": f"Request failed with status {response.status_code}",
                    "detail": response.text
                }
        except httpx.RequestError as e:
            return {"error": str(e)}


@mcp.tool()
async def get_whois_multi(
    domains: List[str],
    authorization: Optional[str] = None
) -> dict:
    """Fetch WHOIS information for multiple domains in a single request. Use this when you need to look up and compare registration details for several domains at once. Results are returned within a 2-second timeout."""
    if not domains:
        return {"error": "At least one domain is required"}

    # Strip protocols from all domains
    cleaned_domains = [
        d.replace("http://", "").replace("https://", "").strip("/")
        for d in domains
    ]

    domains_param = ",".join(cleaned_domains)
    headers = get_auth_headers(authorization)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{BASE_URL}/multi",
                params={"domains": domains_param},
                headers=headers,
                timeout=30.0
            )
            if response.status_code == 200:
                try:
                    return response.json()
                except Exception:
                    return {"response": response.text}
            else:
                return {
                    "error": f"Request failed with status {response.status_code}",
                    "detail": response.text
                }
        except httpx.RequestError as e:
            return {"error": str(e)}




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
