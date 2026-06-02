"""
Target HTTP client + VAMPI auth bootstrap.

Wraps requests with timing capture and the small multi-step flows the attack
drivers need (register / login / authenticated calls). Evidence (method, url,
status, elapsed, body excerpt) is recorded for the Result Analyser.
"""
from __future__ import annotations
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class Exchange:
    method: str
    url: str
    status: int
    elapsed_ms: float
    request_body: Any = None
    response_excerpt: str = ""

    def as_text(self) -> str:
        body = f" req={self.request_body}" if self.request_body is not None else ""
        return (f"{self.method} {self.url} -> {self.status} "
                f"({self.elapsed_ms:.0f} ms){body}\n   resp: {self.response_excerpt}")


@dataclass
class Target:
    base_url: str
    timeout: int = 30
    exchanges: list[Exchange] = field(default_factory=list)

    def _record(self, r: requests.Response, method: str, body: Any = None) -> Exchange:
        ex = Exchange(
            method=method, url=r.url, status=r.status_code,
            elapsed_ms=r.elapsed.total_seconds() * 1000,
            request_body=body,
            response_excerpt=(r.text or "")[:500],
        )
        self.exchanges.append(ex)
        return ex

    # raw request with explicit timing (used by ReDoS / rate-limit drivers)
    def request(self, method: str, path: str, *, token: str | None = None,
                json_body: Any = None, raw_path: bool = False,
                timeout: int | None = None) -> tuple[requests.Response, Exchange]:
        url = self.base_url.rstrip("/") + path             # caller encodes path segments
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        start = time.time()
        r = requests.request(method, url, headers=headers, json=json_body,
                             timeout=timeout or self.timeout)
        # requests' r.elapsed is reliable; keep start as backup for streamed cases
        ex = self._record(r, method, json_body)
        ex.elapsed_ms = (time.time() - start) * 1000
        self.exchanges[-1] = ex
        return r, ex

    @staticmethod
    def enc(segment: str) -> str:
        """Percent-encode a single path segment (for injection payloads)."""
        return urllib.parse.quote(segment, safe="")

    # -- VAMPI bootstrap helpers --------------------------------------------
    def seed_db(self) -> None:
        try:
            self.request("GET", "/createdb")
        except requests.RequestException:
            pass

    def register(self, username: str, password: str, email: str,
                 extra: dict | None = None) -> Exchange:
        body = {"username": username, "password": password, "email": email}
        if extra:
            body.update(extra)
        _, ex = self.request("POST", "/users/v1/register", json_body=body)
        return ex

    def login(self, username: str, password: str) -> tuple[str | None, Exchange]:
        r, ex = self.request("POST", "/users/v1/login",
                             json_body={"username": username, "password": password})
        token = None
        try:
            token = r.json().get("auth_token")
        except Exception:
            token = None
        return token, ex
