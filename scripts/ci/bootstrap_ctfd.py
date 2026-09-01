#!/usr/bin/env python3
"""Create deterministic player data in a fresh CTFd container for CI.

This deliberately uses CTFd's own setup UI and authenticated admin API.  The
compatibility job therefore catches changes in the real setup, session, CSRF,
and normal-player flows instead of depending on a bespoke database fixture.
Only Python's standard library is used so the GitHub runner needs no extra
bootstrap dependency.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar


BASE_URL = os.environ.get("CTFD_SMOKE_URL", "").rstrip("/")
PLAYER_NAME = os.environ.get("CTFD_SMOKE_USERNAME", "")
PLAYER_PASSWORD = os.environ.get("CTFD_SMOKE_PASSWORD", "")
PLAYER_EMAIL = "ctfd-mcp-player@example.invalid"
ADMIN_NAME = "ctfd-mcp-admin"
ADMIN_PASSWORD = "ctfd-mcp-admin-password"
ADMIN_EMAIL = "ctfd-mcp-admin@example.invalid"
CHALLENGE_NAME = "ctfd-mcp live smoke"
FLAG = "flag{ctfd_mcp_live_smoke}"

CSRF_PATTERNS = (
    re.compile(r"['\"]csrfNonce['\"]\s*:\s*['\"]([0-9a-fA-F]{16,})['\"]"),
    re.compile(r"name=['\"]nonce['\"]\s+value=['\"]([0-9a-fA-F]{16,})['\"]"),
    re.compile(r"value=['\"]([0-9a-fA-F]{16,})['\"]\s+name=['\"]nonce['\"]"),
)


def fail(message: str) -> None:
    print(f"bootstrap_ctfd.py: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_environment() -> None:
    if not BASE_URL.startswith(("http://", "https://")):
        fail("CTFD_SMOKE_URL must be an http(s) URL")
    if not PLAYER_NAME or not PLAYER_PASSWORD:
        fail("CTFD_SMOKE_USERNAME and CTFD_SMOKE_PASSWORD are required")


def read_response(response: object) -> tuple[int, bytes]:
    # urllib response objects expose .status on current Python, while older
    # versions use getcode(). Supporting both makes this script portable.
    status = getattr(response, "status", response.getcode())
    return status, response.read()


def request(
    opener: urllib.request.OpenerDirector,
    path: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    req = urllib.request.Request(
        f"{BASE_URL}{path}", data=data, headers=headers or {}, method=method
    )
    try:
        with opener.open(req, timeout=10) as response:
            return read_response(response)
    except urllib.error.HTTPError as error:
        body = error.read()
        summary = body.decode("utf-8", "replace")[:500].replace("\n", " ")
        fail(f"{method} {path} returned HTTP {error.code}: {summary}")
    except urllib.error.URLError as error:
        fail(f"{method} {path} failed: {error.reason}")
    raise AssertionError("unreachable")


def wait_for_setup(opener: urllib.request.OpenerDirector) -> bytes:
    deadline = time.monotonic() + 120
    last_error = "not started"
    while time.monotonic() < deadline:
        try:
            with opener.open(f"{BASE_URL}/setup", timeout=5) as response:
                status, body = read_response(response)
                if status == 200:
                    return body
                last_error = f"HTTP {status}"
        except (OSError, urllib.error.HTTPError, urllib.error.URLError) as error:
            # Connection errors and a transient reverse-proxy response are
            # normal while a freshly started CTFd image is initializing.
            last_error = str(error.reason if hasattr(error, "reason") else error)
        time.sleep(2)
    fail(f"CTFd did not serve /setup within two minutes ({last_error})")


def extract_nonce(page: bytes) -> str:
    text = page.decode("utf-8", "replace")
    for pattern in CSRF_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    fail("could not find a CSRF nonce in a CTFd page")
    raise AssertionError("unreachable")


def post_form(
    opener: urllib.request.OpenerDirector, path: str, values: dict[str, str]
) -> tuple[int, bytes]:
    encoded = urllib.parse.urlencode(values).encode("utf-8")
    return request(
        opener,
        path,
        method="POST",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def post_json(
    opener: urllib.request.OpenerDirector, path: str, nonce: str, values: dict[str, object]
) -> dict[str, object]:
    status, raw = request(
        opener,
        path,
        method="POST",
        data=json.dumps(values).encode("utf-8"),
        headers={"Content-Type": "application/json", "CSRF-Token": nonce},
    )
    if status < 200 or status >= 300:
        fail(f"{path} returned unexpected HTTP {status}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"{path} returned invalid JSON: {error}")
    if payload.get("success") is not True:
        fail(f"{path} reported failure: {payload}")
    data = payload.get("data")
    if not isinstance(data, dict):
        fail(f"{path} returned no object data: {payload}")
    return data


def require_id(data: dict[str, object], what: str) -> int:
    value = data.get("id")
    if not isinstance(value, int) or value <= 0:
        fail(f"CTFd did not return a valid {what} id: {data}")
    return value


def write_output(name: str, value: int) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as output:
            output.write(f"{name}={value}\n")


def main() -> None:
    require_environment()
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    setup_page = wait_for_setup(opener)
    nonce = extract_nonce(setup_page)
    post_form(
        opener,
        "/setup",
        {
            "nonce": nonce,
            "ctf_name": "ctfd-mcp CI",
            "ctf_description": "Temporary CI fixture",
            "user_mode": "users",
            # The smoke player must be inside the CTF window, while the dates
            # remain stable regardless of when CI runs.
            "start": "2000-01-01T00:00:00",
            "end": "2100-01-01T00:00:00",
            "challenge_visibility": "public",
            "account_visibility": "public",
            "score_visibility": "public",
            "registration_visibility": "public",
            "name": ADMIN_NAME,
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD,
        },
    )

    _, challenges_page = request(opener, "/challenges")
    csrf_nonce = extract_nonce(challenges_page)

    post_json(
        opener,
        "/api/v1/users",
        csrf_nonce,
        {"name": PLAYER_NAME, "email": PLAYER_EMAIL, "password": PLAYER_PASSWORD},
    )
    challenge = post_json(
        opener,
        "/api/v1/challenges",
        csrf_nonce,
        {
            "name": CHALLENGE_NAME,
            "category": "ci",
            "description": "This challenge is created only for ctfd-mcp CI.",
            "value": 100,
            "type": "standard",
            "state": "visible",
        },
    )
    challenge_id = require_id(challenge, "challenge")
    post_json(
        opener,
        "/api/v1/flags",
        csrf_nonce,
        {
            "challenge_id": challenge_id,
            "type": "static",
            "content": FLAG,
            "data": "case_insensitive",
        },
    )

    write_output("challenge_id", challenge_id)
    print(f"Created player {PLAYER_NAME!r} and challenge {challenge_id}.")


if __name__ == "__main__":
    main()
