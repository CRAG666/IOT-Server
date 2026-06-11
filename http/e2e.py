#!/usr/bin/env python3
"""IoTmx API — E2E session client and test runner.

Handles the AES-256-GCM + HKDF-SHA256 handshake, transparently encrypts /
decrypts all request and response bodies, and can execute .http test files
with assertions and response chaining.

Requirements:
    pip install cryptography   (present in the project venv)

Session commands:
    python http/e2e.py login <email> <password> [--url URL]
    python http/e2e.py logout

Request commands:
    python http/e2e.py get    <path>
    python http/e2e.py post   <path> <json_body>
    python http/e2e.py put    <path> <json_body>
    python http/e2e.py patch  <path> <json_body>
    python http/e2e.py delete <path>

Test runner:
    python http/e2e.py run http/tests/01_ops.http http/tests/02_auth.http ...
    python http/e2e.py run http/tests/*.http

Test file format (.http):
    ### Test name
    # @expect 201            expected HTTP status code (any 2xx if omitted)
    # @capture var $.path    save response field to a variable
    # @assert $.path value   fail if response field != value
    # @public                send without X-Session-ID (public endpoints)
    # @skip reason           skip this test
    # @login email pass [url] perform login handshake (no HTTP request)
    METHOD /path/{{var}}

    {"field": "{{var}}"}

Environment variables:
    IOTMX_URL   Base URL (default: http://localhost:8000)

Session is persisted to .e2e_session.json in the current directory.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_URL: str = os.environ.get("IOTMX_URL", "http://localhost:8000")
SESSION_FILE: Path = Path(".e2e_session.json")

_COLOR = sys.stdout.isatty() and os.name != "nt"
_GREEN  = "\033[32m" if _COLOR else ""
_RED    = "\033[31m" if _COLOR else ""
_YELLOW = "\033[33m" if _COLOR else ""
_RESET  = "\033[0m"  if _COLOR else ""

# Compiled once; used in every _jpath call and every line of every test block.
_SEG_RE    = re.compile(r"\[(-?\d+)\]|([^.\[\]]+)")
_VAR_RE    = re.compile(r"\{\{(\w+)\}\}")
_METHOD_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE)\s+")
_BLOCK_RE  = re.compile(r"(?m)^###[ \t]*(.*)\n?")


# ── Crypto primitives (mirrors app/shared/crypto.py) ──────────────────────────

def _sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    iv = os.urandom(12)
    return AESGCM(key).encrypt(iv, plaintext, None), iv


def _aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(iv, ciphertext, None)


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _http(
    method: str,
    url: str,
    body: dict | None = None,
    extra_headers: dict | None = None,
) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("Content-Type", "application/json")
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        print(f"Connection error: {e.reason}", file=sys.stderr)
        print(f"Is the server running at {url}?", file=sys.stderr)
        sys.exit(1)


# ── Session persistence ────────────────────────────────────────────────────────

def _load_session() -> dict | None:
    if not SESSION_FILE.exists():
        return None
    return json.loads(SESSION_FILE.read_text())


def _require_session() -> dict:
    """Load session or exit with a user-facing error (for REPL commands)."""
    sess = _load_session()
    if sess is None:
        print(
            f"No active session. Run:\n  python {__file__} login <email> <password>",
            file=sys.stderr,
        )
        sys.exit(1)
    return sess


def _save_session(session_id: str, session_key: bytes, base_url: str) -> None:
    SESSION_FILE.write_text(
        json.dumps(
            {"session_id": session_id, "session_key": session_key.hex(), "base_url": base_url},
            indent=2,
        )
    )


def _clear_session() -> None:
    SESSION_FILE.unlink(missing_ok=True)


def _base_url() -> str:
    sess = _load_session()
    return sess.get("base_url", DEFAULT_URL) if sess else DEFAULT_URL


# ── Response helpers ───────────────────────────────────────────────────────────

def _decode_response(raw: bytes, session_key: bytes | None) -> tuple[object, str | None]:
    """Decrypt (if needed) and parse response. Returns (parsed, error_str)."""
    if not raw:
        return None, None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None, raw.decode(errors="replace")
    if session_key and isinstance(parsed, dict) and "payload" in parsed and "iv" in parsed:
        try:
            ct = base64.b64decode(parsed["payload"])
            iv = base64.b64decode(parsed["iv"])
            plaintext = _aes_decrypt(ct, session_key, iv)
            return (json.loads(plaintext) if plaintext else None), None
        except Exception as exc:
            return None, f"decryption failed: {exc}"
    return parsed, None


def _print_response(status: int, raw: bytes, session_key: bytes | None = None) -> None:
    parsed, err = _decode_response(raw, session_key)
    if err:
        print(f"[{status}] (raw: {err})")
    elif parsed is None:
        print(f"[{status}] (no content)")
    else:
        print(f"[{status}]")
        print(json.dumps(parsed, indent=2, ensure_ascii=False))


# ── Login / logout ─────────────────────────────────────────────────────────────

def cmd_login(email: str, password: str, base_url: str) -> None:
    status, raw = _http("GET", f"{base_url}/api/v1/auth/challenge?email={email}")
    if status != 200:
        print(f"Challenge failed [{status}]: {json.loads(raw)}", file=sys.stderr)
        sys.exit(1)
    salt: str = json.loads(raw)["salt"]

    inner_sha256 = _sha256_hex(password)
    salted_hash  = _sha256_hex(salt + inner_sha256)
    random_hex   = secrets.token_hex(16)
    random2      = secrets.token_hex(32)
    temp_key = _hkdf(
        ikm=(salted_hash + random_hex).encode(), salt=salt.encode(), info=b"iotmx-temp-key-v2"
    )

    ct, iv = _aes_encrypt(json.dumps({"random2": random2}).encode(), temp_key)
    status, raw = _http("POST", f"{base_url}/api/v1/auth/login", body={
        "username": email,
        "payload":  base64.b64encode(ct).decode(),
        "random":   random_hex,
        "iv":       base64.b64encode(iv).decode(),
    })
    if status != 200:
        print(f"Login failed [{status}]: {json.loads(raw)}", file=sys.stderr)
        sys.exit(1)

    resp   = json.loads(raw)
    inner  = json.loads(
        _aes_decrypt(base64.b64decode(resp["payload"]), temp_key, base64.b64decode(resp["iv"]))
    )
    session_id:  str   = inner["session-id"]
    session_key: bytes = _hkdf(
        ikm=(random2 + inner["random3"]).encode(), salt=None, info=b"iotmx-session-key-v2"
    )
    _save_session(session_id, session_key, base_url)
    print(f"Logged in as: {email}  session: {session_id[:20]}…")


def cmd_logout() -> None:
    sess        = _require_session()
    session_key = bytes.fromhex(sess["session_key"])
    status, raw = _http(
        "POST", f"{sess['base_url']}/api/v1/auth/logout",
        body={}, extra_headers={"X-Session-ID": sess["session_id"]},
    )
    _print_response(status, raw, session_key)
    _clear_session()
    print("Session cleared.")


# ── Single authenticated request ───────────────────────────────────────────────

def cmd_request(method: str, path: str, body_json: str | None = None) -> None:
    sess        = _require_session()
    session_key = bytes.fromhex(sess["session_key"])
    url         = f"{sess['base_url']}{path}"
    req_body: dict | None = None
    if method in {"POST", "PUT", "PATCH"} and body_json:
        ct, iv   = _aes_encrypt(body_json.encode(), session_key)
        req_body = {"payload": base64.b64encode(ct).decode(), "iv": base64.b64encode(iv).decode()}
    status, raw = _http(method, url, body=req_body, extra_headers={"X-Session-ID": sess["session_id"]})
    _print_response(status, raw, session_key)


# ── Test runner ────────────────────────────────────────────────────────────────

@dataclasses.dataclass(slots=True)
class TestBlock:
    name:       str
    method:     str | None                  = None
    path:       str | None                  = None
    body:       str                         = ""
    expect:     int | None                  = None
    captures:   list[tuple[str, str]]       = dataclasses.field(default_factory=list)
    assertions: list[tuple[str, str]]       = dataclasses.field(default_factory=list)
    public:     bool                        = False
    skip:       str | None                  = None
    login:      dict[str, str] | None       = None


def _jpath(obj: object, path: str) -> object:
    """Evaluate a simple JSON path: $.field, $.data[0].id, $.items[-1].name"""
    if not path.startswith("$"):
        raise ValueError(f"Path must start with $: {path!r}")
    for idx_s, key in _SEG_RE.findall(path[1:]):
        obj = obj[int(idx_s)] if idx_s else obj[key]  # type: ignore[index]
    return obj


def _substitute(text: str, variables: dict[str, str]) -> str:
    """Replace {{var}} tokens in a single O(n) pass; unknown vars are left as-is."""
    return _VAR_RE.sub(lambda m: variables.get(m.group(1), m.group(0)), text)


def _parse_blocks(content: str) -> list[tuple[str, str]]:
    """Split .http content into (name, raw_body) pairs on ### separators."""
    parts = _BLOCK_RE.split(content)
    it    = iter(parts[1:])  # first element is text before the opening ###
    return [
        (name.strip(), body)
        for name, body in zip(it, it)
        if name.strip()
    ]


def _apply_directive(block: TestBlock, s: str) -> None:
    """Mutate block in-place based on a single # @directive line."""
    parts     = s.split()
    directive = parts[1] if len(parts) > 1 else ""
    match directive:
        case "@login" if len(parts) >= 4:
            block.login = {
                "email":    parts[2],
                "password": parts[3],
                "url":      parts[4] if len(parts) > 4 else "",
            }
        case "@expect" if len(parts) >= 3:
            block.expect = int(parts[2])
        case "@capture" if len(parts) >= 4:
            block.captures.append((parts[2], parts[3]))
        case "@assert" if len(parts) >= 4:
            # join tail so "# @assert $.x foo bar" compares against "foo bar"
            block.assertions.append((parts[2], " ".join(parts[3:])))
        case "@public":
            block.public = True
        case "@skip":
            block.skip = " ".join(parts[2:]) or "marked skip"


def _parse_block(name: str, body: str) -> TestBlock:
    """Parse directives, HTTP method/path, and JSON body out of a raw block."""
    block = TestBlock(name=name)
    lines = iter(body.splitlines())

    for line in lines:
        s = line.strip()
        if not s:
            if block.method:   # first blank line after the request line ends headers
                break
            continue
        if s.startswith("#"):
            _apply_directive(block, s)
        elif not block.method and _METHOD_RE.match(s):
            parts        = s.split(None, 1)
            block.method = parts[0]
            block.path   = parts[1].strip() if len(parts) > 1 else ""
        # else: HTTP header line (Content-Type, Accept …) — ignored

    block.body = "\n".join(lines).strip()
    return block


def _send(
    block: TestBlock, variables: dict[str, str]
) -> tuple[int, bytes, bytes | None] | None:
    """Build and fire the HTTP request.

    Returns (status, raw_body, session_key_or_None), or None when no active
    session exists and the block is not marked @public.
    """
    path      = _substitute(block.path or "", variables)
    body_text = _substitute(block.body, variables)

    if block.public:
        req_body = json.loads(body_text) if body_text and block.method in {"POST", "PUT", "PATCH"} else None
        status, raw = _http(block.method, f"{_base_url()}{path}", body=req_body)
        return status, raw, None

    sess = _load_session()
    if sess is None:
        return None

    session_key  = bytes.fromhex(sess["session_key"])
    req_body     = None
    if body_text and block.method in {"POST", "PUT", "PATCH"}:
        ct, iv   = _aes_encrypt(body_text.encode(), session_key)
        req_body = {"payload": base64.b64encode(ct).decode(), "iv": base64.b64encode(iv).decode()}

    status, raw = _http(
        block.method, f"{sess['base_url']}{path}",
        body=req_body, extra_headers={"X-Session-ID": sess["session_id"]},
    )
    return status, raw, session_key


def _execute_block(block: TestBlock, variables: dict[str, str]) -> tuple[str, str]:
    """Execute one test block. Returns ("OK" | "FAIL" | "SKIP", detail)."""
    if block.login is not None:
        url = block.login.get("url") or _base_url()
        try:
            cmd_login(block.login["email"], block.login["password"], url)
        except SystemExit:
            return "FAIL", "login failed"
        return "OK", ""

    if block.skip:
        return "SKIP", block.skip
    if not block.method:
        return "SKIP", "no request line"

    result = _send(block, variables)
    if result is None:
        return "FAIL", "no session — run: python e2e.py login <email> <password>"
    status, raw, session_key = result

    resp, _ = _decode_response(raw, session_key)

    if block.expect is not None and status != block.expect:
        detail = f" — {resp.get('detail', json.dumps(resp))}" if isinstance(resp, dict) else ""
        return "FAIL", f"expected {block.expect}, got {status}{detail}"

    for var_name, jpath in block.captures:
        if resp is None:
            return "FAIL", f"capture {var_name!r}: empty response"
        try:
            variables[var_name] = str(_jpath(resp, jpath))
        except Exception as exc:
            return "FAIL", f"capture {var_name!r} at {jpath!r}: {exc}"

    for jpath, expected in block.assertions:
        if resp is None:
            return "FAIL", f"assert {jpath!r}: empty response"
        expected_val = _substitute(expected, variables).strip("\"'")
        try:
            actual = _jpath(resp, jpath)
            if str(actual).lower() != expected_val.lower():
                return "FAIL", f"assert {jpath}: expected {expected_val!r}, got {actual!r}"
        except Exception as exc:
            return "FAIL", f"assert {jpath!r}: {exc}"

    return "OK", f"[{status}]"


def cmd_run(*test_files: str) -> None:
    """Execute .http test files in order; variables are shared across all files."""
    variables: dict[str, str] = {}
    passed = failed = skipped = total = 0

    for test_file in test_files:
        try:
            content = Path(test_file).read_text()
        except FileNotFoundError:
            print(f"{_RED}ERROR{_RESET}: file not found: {test_file}", file=sys.stderr)
            sys.exit(1)

        label = Path(test_file).name
        print(f"\n{label}")
        print("─" * len(label))

        for name, body in _parse_blocks(content):
            block  = _parse_block(name, body)
            total += 1
            result, detail = _execute_block(block, variables)

            if result == "OK":
                colour = _GREEN
                passed += 1
            elif result == "SKIP":
                colour = _YELLOW
                skipped += 1
            else:
                colour = _RED
                failed += 1

            detail_str = f"  ({detail})" if detail else ""
            print(f"  {colour}{result}{_RESET}  {name}{detail_str}")

    width = 42
    print(f"\n{'═' * width}")
    print(
        f"  {_GREEN}{passed} passed{_RESET}  "
        f"{_RED}{failed} failed{_RESET}  "
        f"{_YELLOW}{skipped} skipped{_RESET}  "
        f"/ {total} total"
    )
    print(f"{'═' * width}")

    if failed:
        sys.exit(1)


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__)
        return

    cmd, *rest = args

    match cmd:
        case "login":
            if len(rest) < 2:
                print("Usage: python e2e.py login <email> <password> [--url URL]")
                sys.exit(1)
            email, password = rest[0], rest[1]
            url = DEFAULT_URL
            flag_it = iter(rest[2:])
            for flag in flag_it:
                if flag == "--url":
                    url = next(flag_it, DEFAULT_URL)
                elif flag.startswith("--url="):
                    url = flag.split("=", 1)[1]
            cmd_login(email, password, url)

        case "logout":
            cmd_logout()

        case "get" | "post" | "put" | "patch" | "delete":
            if not rest:
                print(f"Usage: python e2e.py {cmd} /api/v1/path [json_body]")
                sys.exit(1)
            cmd_request(cmd.upper(), rest[0], rest[1] if len(rest) > 1 else None)

        case "run":
            if not rest:
                print("Usage: python e2e.py run <file.http> [file2.http ...]")
                sys.exit(1)
            cmd_run(*rest)

        case _:
            print(f"Unknown command: {cmd!r}")
            print(__doc__)
            sys.exit(1)


if __name__ == "__main__":
    main()
