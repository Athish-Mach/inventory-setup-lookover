"""Shared Supabase client configuration with safe read retries."""

from __future__ import annotations

import time

import httpx
from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions


class SafeReadRetryTransport(httpx.BaseTransport):
    """Retry interrupted idempotent reads, never retry writes automatically."""

    def __init__(self, attempts: int = 3) -> None:
        self.attempts = attempts
        self.transport = httpx.HTTPTransport(http2=False, retries=0)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        can_retry = request.method in {"GET", "HEAD"}
        max_attempts = self.attempts if can_retry else 1
        for attempt in range(max_attempts):
            try:
                return self.transport.handle_request(request)
            except httpx.TransportError:
                if attempt + 1 >= max_attempts:
                    raise
                time.sleep(0.15 * (2**attempt))
        raise RuntimeError("Transport retry loop ended unexpectedly")

    def close(self) -> None:
        self.transport.close()


def create_resilient_client(url: str, key: str) -> Client:
    """Build a thread-safe client using HTTP/1.1 and bounded safe-read retries."""
    http_client = httpx.Client(
        transport=SafeReadRetryTransport(),
        timeout=httpx.Timeout(30),
        follow_redirects=True,
    )
    return create_client(
        url,
        key,
        options=SyncClientOptions(
            httpx_client=http_client,
            postgrest_client_timeout=30,
        ),
    )
