"""SSRF callback catcher — local HTTP server + interactsh integration."""

import asyncio
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that records incoming requests."""

    callbacks: list[dict] = []

    def do_GET(self):
        self._record("GET")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore") if content_length else ""
        self._record("POST", body)

    def do_PUT(self):
        self._record("PUT")

    def do_HEAD(self):
        self._record("HEAD")

    def _record(self, method: str, body: str = ""):
        _CallbackHandler.callbacks.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "source_ip": self.client_address[0],
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body[:500] if body else "",
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # Suppress default logging


def _get_local_ip() -> str:
    """Get the machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _find_free_port() -> int:
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


async def catch_ssrf(timeout_seconds: int = 15) -> dict:
    """Start an SSRF callback listener and wait for interactions.

    Returns a callback URL and any interactions received within the timeout.
    For remote targets, use the interactsh URL. For local targets, use the
    local listener URL.
    """
    # Try interactsh first (works for remote targets)
    try:
        return await _catch_ssrf_interactsh(timeout_seconds)
    except Exception:
        pass

    # Fallback: local HTTP listener (only works for localhost/network targets)
    return await _catch_ssrf_local(timeout_seconds)


async def _catch_ssrf_interactsh(timeout_seconds: int) -> dict:
    """Use interactsh for public OOB callback detection."""
    try:
        from pyinteractsh import Client

        client = Client()
        url = client.get_url()

        # Poll for interactions
        await asyncio.sleep(timeout_seconds)
        interactions = client.poll()

        results = []
        if interactions:
            for interaction in interactions:
                results.append({
                    "timestamp": interaction.get("timestamp", ""),
                    "source_ip": interaction.get("remote-address", ""),
                    "type": interaction.get("protocol", ""),
                    "raw_request": interaction.get("raw-request", "")[:500],
                })

        client.close()

        return {
            "method": "interactsh",
            "callback_url": url,
            "timeout_seconds": timeout_seconds,
            "interactions": results,
            "note": "This URL works for remote targets. Inject it into SSRF-susceptible parameters.",
        }

    except ImportError:
        raise RuntimeError("pyinteractsh not installed")


async def _catch_ssrf_local(timeout_seconds: int) -> dict:
    """Fallback: local HTTP server as callback catcher."""
    port = _find_free_port()
    local_ip = _get_local_ip()

    _CallbackHandler.callbacks = []

    server = HTTPServer(("0.0.0.0", port), _CallbackHandler)
    server.timeout = 1

    # Run server in a thread
    def serve():
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            server.handle_request()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    callback_url = f"http://{local_ip}:{port}/ssrf-callback"

    # Wait for the listener period
    await asyncio.sleep(timeout_seconds + 1)
    thread.join(timeout=2)
    server.server_close()

    return {
        "method": "local_listener",
        "callback_url": callback_url,
        "timeout_seconds": timeout_seconds,
        "interactions": _CallbackHandler.callbacks,
        "note": (
            "Local listener — only works if the target can reach your IP. "
            "For remote targets, install pyinteractsh: uv add pyinteractsh"
        ),
    }
