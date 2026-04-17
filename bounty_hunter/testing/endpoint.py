"""HTTP security checks — CORS, headers, auth, methods, info leak."""

import httpx

# Security headers that should be present
EXPECTED_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Headers that leak information
RISKY_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Debug",
    "X-Debug-Token",
    "X-Runtime",
]


async def _check_cors(url: str, client: httpx.AsyncClient) -> dict:
    """Check CORS configuration via OPTIONS preflight."""
    result = {"tested": True}

    try:
        # Send preflight with evil origin
        resp = await client.options(
            url,
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")
        acam = resp.headers.get("Access-Control-Allow-Methods", "")

        result["allow_origin"] = acao
        result["credentials"] = acac.lower() == "true"
        result["allow_headers"] = acah
        result["allow_methods"] = acam
        result["reflects_origin"] = acao == "https://evil.example.com"
        result["wildcard"] = acao == "*"

        # Determine exploitability
        result["exploitable"] = (
            (result["reflects_origin"] or result["wildcard"])
            and (result["credentials"] or "authorization" in acah.lower())
        )

    except Exception as e:
        result["error"] = str(e)

    return result


async def _check_headers(url: str, client: httpx.AsyncClient) -> dict:
    """Check security headers."""
    result = {"tested": True}

    try:
        resp = await client.head(url)
        headers = dict(resp.headers)

        present = [h for h in EXPECTED_HEADERS if h.lower() in {k.lower() for k in headers}]
        missing = [h for h in EXPECTED_HEADERS if h.lower() not in {k.lower() for k in headers}]
        risky = []
        for h in RISKY_HEADERS:
            for k, v in headers.items():
                if k.lower() == h.lower():
                    risky.append(f"{k}: {v}")

        result["present"] = present
        result["missing"] = missing
        result["risky"] = risky

    except Exception as e:
        result["error"] = str(e)

    return result


async def _check_auth(url: str, client: httpx.AsyncClient, auth_header: str | None) -> dict:
    """Check if endpoint requires authentication."""
    result = {"tested": True}

    try:
        # Request without auth
        resp_no_auth = await client.get(url)
        result["status_without_auth"] = resp_no_auth.status_code

        # Request with auth if provided
        if auth_header:
            resp_with_auth = await client.get(
                url, headers={"Authorization": auth_header}
            )
            result["status_with_auth"] = resp_with_auth.status_code

        result["accessible_without_auth"] = resp_no_auth.status_code < 400
        result["bypass_possible"] = (
            resp_no_auth.status_code == 200
            and auth_header is not None
        )

    except Exception as e:
        result["error"] = str(e)

    return result


async def _check_methods(url: str, client: httpx.AsyncClient) -> dict:
    """Enumerate allowed HTTP methods."""
    result = {"tested": True}
    allowed = []

    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
        try:
            resp = await client.request(method, url)
            if resp.status_code != 405:
                allowed.append(method)
        except Exception:
            pass

    result["allowed"] = allowed
    return result


async def _check_info_leak(url: str, client: httpx.AsyncClient) -> dict:
    """Check for information leakage in headers."""
    result = {"tested": True}

    try:
        resp = await client.get(url)
        headers = dict(resp.headers)

        result["server"] = headers.get("Server", headers.get("server", ""))
        result["powered_by"] = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        result["version"] = ""

        # Check for version info in Server header
        server = result["server"]
        if server:
            import re
            version_match = re.search(r"[\d]+\.[\d]+", server)
            if version_match:
                result["version"] = version_match.group()

        # Check for debug headers
        debug_headers = []
        for k, v in headers.items():
            k_lower = k.lower()
            if any(dh in k_lower for dh in ["debug", "trace", "x-request-id", "x-runtime"]):
                debug_headers.append(f"{k}: {v}")

        result["debug_headers"] = debug_headers

    except Exception as e:
        result["error"] = str(e)

    return result


async def run_checks(
    url: str,
    checks: list[str],
    mode: str = "passive",
    auth_header: str | None = None,
) -> dict:
    """Run selected security checks against a URL."""
    results = {"url": url, "mode": mode}

    async with httpx.AsyncClient(
        timeout=15,
        follow_redirects=True,
        verify=False,  # Allow self-signed certs for internal targets
    ) as client:
        # Passive checks (safe — HEAD/OPTIONS only)
        if "cors" in checks:
            results["cors"] = await _check_cors(url, client)

        if "headers" in checks:
            results["headers"] = await _check_headers(url, client)

        if "info_leak" in checks:
            results["info_leak"] = await _check_info_leak(url, client)

        # Active checks (sends real requests — may trigger WAFs)
        if mode == "active":
            if "auth" in checks:
                results["auth"] = await _check_auth(url, client, auth_header)

            if "methods" in checks:
                results["methods"] = await _check_methods(url, client)
        elif "auth" in checks or "methods" in checks:
            active_requested = [c for c in checks if c in ("auth", "methods")]
            results["warning"] = (
                f"Checks {active_requested} require mode='active'. "
                "Currently in passive mode (safe). Set mode='active' to enable."
            )

    return results
