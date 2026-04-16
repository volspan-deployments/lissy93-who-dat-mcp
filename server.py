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
    """Build authorization headers from env var or provided key."""
    headers = {}
    key = api_key or AUTH_KEY
    if key:
        if key.lower().startswith("bearer "):
            headers["Authorization"] = key
        else:
            headers["Authorization"] = f"Bearer {key}"
    return headers


@mcp.tool()
async def check_health() -> dict:
    """Ping the WHOIS API server to verify it is reachable and healthy. Use this before making other requests to confirm the service is up, or when diagnosing connectivity issues."""
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
                "message": f"Request failed: {str(e)}"
            }


@mcp.tool()
async def lookup_domain(
    domain: str,
    api_key: Optional[str] = None
) -> dict:
    """Retrieve WHOIS registration information for a single domain name. Returns registrar details, registration/expiry dates, nameservers, registrant contact info, and domain status. Use this when the user wants to look up ownership, expiry, or registration details for one specific domain.

    Args:
        domain: The fully-qualified domain name to look up (e.g. 'example.com', 'google.co.uk'). Do not include protocol prefixes like 'http://'.
        api_key: Authentication API key to include in the Authorization header. Required only when the server has AUTH_KEY configured. Can be a raw key or a Bearer token.
    """
    # Strip any protocol prefix just in case
    domain = domain.strip()
    for prefix in ["https://", "http://"]:
        if domain.lower().startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")

    headers = _build_headers(api_key)

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
                    return {"status_code": response.status_code, "response": response.text}
            else:
                return {
                    "status_code": response.status_code,
                    "error": response.text
                }
        except httpx.RequestError as e:
            return {
                "status": "error",
                "message": f"Request failed: {str(e)}"
            }


@mcp.tool()
async def lookup_multiple_domains(
    domains: List[str],
    api_key: Optional[str] = None
) -> dict:
    """Retrieve WHOIS information for multiple domains in a single batch request. Useful when the user wants to compare registration details, check expiry dates, or audit ownership across a list of domains. Note: subject to a 2-second server-side timeout, so keep the list reasonably short (under 10 domains recommended).

    Args:
        domains: List of domain names to look up (e.g. ['example.com', 'google.com', 'github.com']). Each should be a fully-qualified domain without protocol prefixes.
        api_key: Authentication API key to include in the Authorization header. Required only when the server has AUTH_KEY configured.
    """
    # Clean domains
    cleaned = []
    for d in domains:
        d = d.strip()
        for prefix in ["https://", "http://"]:
            if d.lower().startswith(prefix):
                d = d[len(prefix):]
        d = d.rstrip("/")
        if d:
            cleaned.append(d)

    if not cleaned:
        return {"error": "No valid domains provided"}

    domains_param = ",".join(cleaned)
    headers = _build_headers(api_key)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{BASE_URL}/multi",
                params={"domains": domains_param},
                headers=headers,
                timeout=15.0
            )
            if response.status_code == 200:
                try:
                    return response.json()
                except Exception:
                    return {"status_code": response.status_code, "response": response.text}
            else:
                return {
                    "status_code": response.status_code,
                    "error": response.text
                }
        except httpx.RequestError as e:
            return {
                "status": "error",
                "message": f"Request failed: {str(e)}"
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
