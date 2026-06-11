"""E2ETestClient — transparent AES-256-CBC wrapper around httpx TestClient.

Encrypts POST/PUT/PATCH request bodies and decrypts every response so that
test code can work with plain Python dicts, exactly as before.  The session
key and session-id are set at login time and attached for the lifetime of the
client object.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from app.shared.crypto import aes_decrypt, aes_encrypt


class E2ETestClient:
    """Wraps ``fastapi.testclient.TestClient`` to transparently handle E2E sessions.

    Attributes:
        account: the raw account dict (id, email, account_type, …) from conftest.
    """

    def __init__(
        self,
        raw,  # TestClient
        session_id: str,
        session_key: bytes,
        account: dict[str, Any],
    ) -> None:
        self._raw = raw
        self.session_id = session_id
        self.session_key = session_key
        self.account = account

    # ── internal helpers ──────────────────────────────────────────────────────

    def _session_headers(self, extra: dict | None = None) -> dict:
        h: dict = {"X-Session-ID": self.session_id}
        if extra:
            h.update(extra)
        return h

    def _encrypt(self, data: Any) -> dict:
        plaintext = json.dumps(data).encode()
        ct, iv = aes_encrypt(plaintext, self.session_key)
        return {
            "payload": base64.b64encode(ct).decode(),
            "iv": base64.b64encode(iv).decode(),
        }

    def _decrypt(self, response: Any) -> Any:
        """Decrypt the response body in-place when it matches the E2E envelope."""
        try:
            envelope = json.loads(response.content)
            if "payload" in envelope and "iv" in envelope:
                ct = base64.b64decode(envelope["payload"])
                iv = base64.b64decode(envelope["iv"])
                plaintext = aes_decrypt(ct, self.session_key, iv)
                response._content = plaintext
        except Exception:
            pass
        return response

    # ── HTTP verbs ────────────────────────────────────────────────────────────

    def get(self, url: str, *, headers: dict | None = None, **kwargs: Any) -> Any:
        r = self._raw.get(url, headers=self._session_headers(headers), **kwargs)
        return self._decrypt(r)

    def post(
        self,
        url: str,
        *,
        json: Any = None,
        headers: dict | None = None,
        **kwargs: Any,
    ) -> Any:
        body = self._encrypt(json) if json is not None else None
        r = self._raw.post(
            url, json=body, headers=self._session_headers(headers), **kwargs
        )
        return self._decrypt(r)

    def put(
        self,
        url: str,
        *,
        json: Any = None,
        headers: dict | None = None,
        **kwargs: Any,
    ) -> Any:
        body = self._encrypt(json) if json is not None else None
        r = self._raw.put(
            url, json=body, headers=self._session_headers(headers), **kwargs
        )
        return self._decrypt(r)

    def patch(
        self,
        url: str,
        *,
        json: Any = None,
        headers: dict | None = None,
        **kwargs: Any,
    ) -> Any:
        body = self._encrypt(json) if json is not None else None
        r = self._raw.patch(
            url, json=body, headers=self._session_headers(headers), **kwargs
        )
        return self._decrypt(r)

    def delete(self, url: str, *, headers: dict | None = None, **kwargs: Any) -> Any:
        r = self._raw.delete(url, headers=self._session_headers(headers), **kwargs)
        return self._decrypt(r)
