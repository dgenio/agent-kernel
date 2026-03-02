"""http_driver_demo.py — Local mini HTTP server + HTTPDriver (no internet needed).

Starts a tiny HTTP server on localhost, registers it with an HTTPDriver,
and runs a full invoke → explain flow.

Run with: python examples/http_driver_demo.py
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ.setdefault("AGENT_KERNEL_SECRET", "example-secret-do-not-use-in-prod")

from agent_kernel import (
    Capability,
    CapabilityRegistry,
    HMACTokenProvider,
    Kernel,
    Principal,
    SafetyClass,
    StaticRouter,
)
from agent_kernel.drivers.http import HTTPDriver, HTTPEndpoint
from agent_kernel.models import CapabilityRequest

# ── Tiny HTTP server ────────────────────────────────────────────────────────────

_PRODUCTS = [{"id": i, "name": f"Product {i}", "price": round(i * 9.99, 2)} for i in range(1, 11)]


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/products"):
            body = json.dumps(_PRODUCTS).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # suppress request logging


def _start_server(port: int) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ── Demo ────────────────────────────────────────────────────────────────────────


async def main() -> None:
    port = 18765
    server = _start_server(port)

    try:
        registry = CapabilityRegistry()
        registry.register(
            Capability(
                capability_id="catalog.list_products",
                name="List Products",
                description="List all products in the catalog",
                safety_class=SafetyClass.READ,
                tags=["catalog", "products", "list"],
            )
        )

        http_driver = HTTPDriver(driver_id="catalog_api")
        http_driver.register_endpoint(
            "catalog.list_products",
            HTTPEndpoint(url=f"http://127.0.0.1:{port}/products", method="GET"),
        )

        router = StaticRouter(routes={"catalog.list_products": ["catalog_api"]})
        token_provider = HMACTokenProvider(secret="example-secret-do-not-use-in-prod")

        kernel = Kernel(registry=registry, router=router, token_provider=token_provider)
        kernel.register_driver(http_driver)

        principal = Principal(principal_id="demo-user-001", roles=["reader"])

        print("=== HTTP Driver Demo ===\n")

        print("--- Discovering capabilities ---")
        requests = kernel.request_capabilities("list products in catalog")
        for req in requests:
            print(f"  - {req.capability_id}")

        print("\n--- Invoking catalog.list_products ---")
        token = kernel.get_token(
            CapabilityRequest(capability_id="catalog.list_products", goal="list products"),
            principal,
            justification="",
        )
        frame = await kernel.invoke(
            token,
            principal=principal,
            args={"operation": "catalog.list_products"},
            response_mode="summary",
        )
        print(f"  Mode: {frame.response_mode}")
        print("  Facts:")
        for fact in frame.facts:
            print(f"    • {fact}")

        print("\n--- Expanding first 3 products ---")
        if frame.handle:
            expanded = kernel.expand(
                frame.handle,
                query={"limit": 3, "fields": ["id", "name", "price"]},
            )
            for row in expanded.table_preview:
                print(f"  {row}")

        print("\n--- Explain ---")
        trace = kernel.explain(frame.action_id)
        print(f"  Driver: {trace.driver_id}")
        print(f"  At:     {trace.invoked_at.isoformat()}")

        print("\n✓ http_driver_demo.py complete.")
    finally:
        server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
