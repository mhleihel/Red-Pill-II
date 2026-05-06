"""
Direct HTTP session — thin wrapper over requests.Session.
Drop-in replacement for BurpSession; same interface used by all playbooks.
"""
from __future__ import annotations

import re
import time
from typing import Optional

import requests
from requests import Response




class DirectResponse:
    """Wraps requests.Response with the extra methods playbooks expect."""

    def __init__(self, resp: Optional[Response], taint_id: str = ""):
        self._resp = resp
        # Use `is not None` — requests.Response.__bool__ returns False for 4xx/5xx
        # so `if resp` would incorrectly evaluate error responses as falsy.
        has = resp is not None
        self.status_code: int = resp.status_code if has else 0
        self.text: str = resp.text if has else ""
        self.headers: dict = {k.lower(): v for k, v in resp.headers.items()} if has else {}
        self.cookies: dict = dict(resp.cookies) if has else {}
        self.taint_reflected: bool = bool(taint_id and taint_id in self.text)

    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def contains(self, value: str) -> bool:
        return bool(value) and value in self.text

    def form_key(self) -> Optional[str]:
        for pat in [
            r'name="form_key"[^>]*value="([^"]+)"',
            r'value="([^"]+)"[^>]*name="form_key"',
            r'"form_key"\s*[=:]\s*"([^"]+)"',
        ]:
            m = re.search(pat, self.text)
            if m:
                return m.group(1)
        return None

    def json(self):
        if self._resp is None:
            return None
        try:
            return self._resp.json()
        except Exception:
            return None

    def __bool__(self) -> bool:
        return self.status_code > 0

    def __repr__(self) -> str:
        return f"<DirectResponse {self.status_code}>"


class DirectSession:
    """
    Cookie-aware HTTP session using requests.Session directly.
    Same interface as BurpSession so all existing playbooks work unchanged.
    """

    def __init__(self, base_url: str = "http://localhost:8082",
                 timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Use a plain requests.Session but manage cookies manually via a
        # dict, bypassing http.cookiejar which silently drops cookies for
        # single-word hostnames like 'localhost' (RFC 2965 restriction).
        self._session = requests.Session()
        self._manual_cookies: dict = {}
        self._last_form_key: str = ""  # updated from every HTML response
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Booyah-Taint/1.0; compatible)",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.log: list[dict] = []
        # Expose _host/_port/_cookies so BasePlaybook can read them
        from urllib.parse import urlparse
        p = urlparse(self.base_url)
        self._host = p.hostname
        self._port = p.port or (443 if p.scheme == "https" else 80)

    def _update_cookies(self, resp: Response) -> None:
        """Extract Set-Cookie headers and store in our manual cookie dict."""
        for header in resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, 'getlist') else []:
            self._parse_set_cookie(header)
        # Also capture from requests' own (partially working) cookie jar
        for name, value in resp.cookies.items():
            self._manual_cookies[name] = value

    def _parse_set_cookie(self, header: str) -> None:
        """Parse a Set-Cookie header line and update _manual_cookies."""
        parts = [p.strip() for p in header.split(";")]
        if parts:
            kv = parts[0].split("=", 1)
            if len(kv) == 2:
                self._manual_cookies[kv[0].strip()] = kv[1].strip()

    def _cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self._manual_cookies.items())

    @property
    def _cookies(self) -> dict:
        return dict(self._manual_cookies)

    def form_key(self) -> str:
        """Return the most recently seen HTML form_key for this session."""
        return self._last_form_key

    def _record(self, method: str, path: str, resp: DirectResponse,
                elapsed_ms: int, taint_id: str) -> None:
        # Keep form_key current — update from every HTML response
        fk = resp.form_key()
        if fk:
            self._last_form_key = fk
        self.log.append({
            "method": method,
            "path": path.split("?")[0],
            "status": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "taint_reflected": resp.taint_reflected,
            "taint_id": taint_id,
        })

    def _make_headers(self, extra: Optional[dict] = None) -> dict:
        h = {}
        if extra:
            h.update(extra)
        cookie_str = self._cookie_header()
        if cookie_str:
            h["Cookie"] = cookie_str
        return h

    def _capture(self, r: Response) -> None:
        """Capture Set-Cookie from response into manual cookie dict."""
        raw = r.raw
        # requests stores all Set-Cookie lines in response.headers (multi-value)
        # Use _store to get all values for the same header name
        if hasattr(r.headers, '_store'):
            for key, (orig_key, val) in r.headers._store.items():
                if key.lower() == 'set-cookie':
                    self._parse_set_cookie(val)
        else:
            # Fallback: iterate raw headers if available
            for name, val in (raw.headers.items() if raw and hasattr(raw, 'headers') else []):
                if name.lower() == 'set-cookie':
                    self._parse_set_cookie(val)
        # Also capture from requests' cookie jar (catches non-localhost cookies)
        for name, value in r.cookies.items():
            self._manual_cookies[name] = value

    def get(self, path: str, params: Optional[dict] = None,
            headers: Optional[dict] = None,
            taint_id: str = "") -> DirectResponse:
        url = self.base_url + path
        t0 = time.time()
        try:
            r = self._session.get(url, params=params,
                                  headers=self._make_headers(headers),
                                  timeout=self.timeout, allow_redirects=True)
            self._capture(r)
            resp = DirectResponse(r, taint_id)
        except Exception as e:
            print(f"    [!] GET {path}: {e}")
            resp = DirectResponse(None, taint_id)
        elapsed = int((time.time() - t0) * 1000)
        self._record("GET", path, resp, elapsed, taint_id)
        return resp

    def post(self, path: str,
             data: Optional[dict] = None,
             json_body=None,
             params: Optional[dict] = None,
             headers: Optional[dict] = None,
             taint_id: str = "") -> DirectResponse:
        url = self.base_url + path
        h = self._make_headers(headers)
        t0 = time.time()
        try:
            if json_body is not None:
                r = self._session.post(url, json=json_body, params=params,
                                       headers=h, timeout=self.timeout,
                                       allow_redirects=True)
            else:
                r = self._session.post(url, data=data, params=params,
                                       headers=h, timeout=self.timeout,
                                       allow_redirects=True)
            self._capture(r)
            resp = DirectResponse(r, taint_id)
        except Exception as e:
            print(f"    [!] POST {path}: {e}")
            resp = DirectResponse(None, taint_id)
        elapsed = int((time.time() - t0) * 1000)
        self._record("POST", path, resp, elapsed, taint_id)
        return resp

    def post_json(self, path: str, payload: dict,
                  extra_headers: Optional[dict] = None,
                  taint_id: str = "") -> DirectResponse:
        return self.post(path, json_body=payload, headers=extra_headers or {},
                         taint_id=taint_id)
