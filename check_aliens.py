"""Monitor http://aliens.gov/ and https://aliens.gov/ for going live.

Alerting rule:
- Alert ONLY when a target transitions from a "not live" state (404, 5xx,
  SSL errors, timeouts, connection errors, etc.) to a "live" state
  (HTTP 2xx or 3xx).
- Do NOT alert on:
    * SSL / TLS errors appearing or changing flavor
    * 404 -> SSL error, error -> different error
    * Body/hash changes on 404 pages (these often contain timestamps
      or request IDs and produce noise)
    * Live -> not-live transitions (site going down is not the event
      we care about right now)

Writes:
- state_http_status.txt  / state_http_hash.txt
- state_https_status.txt / state_https_hash.txt
- changed.txt: created only when a target goes live
- error.txt:   diagnostic log of fetch failures (workflow does not notify
  from this file)

Notes:
- HTTP and HTTPS are tracked independently.
- Redirects are not followed, so a redirect to a real site shows up as
  a 3xx and counts as "live".
- TLS/network failures are recorded as state, not raised.
"""

import hashlib
from pathlib import Path

import requests

TIMEOUT_SECONDS = 30

TARGETS = [
    {
        "name": "http",
        "url": "http://aliens.gov/",
        "status_file": Path("state_http_status.txt"),
        "hash_file": Path("state_http_hash.txt"),
    },
    {
        "name": "https",
        "url": "https://aliens.gov/",
        "status_file": Path("state_https_status.txt"),
        "hash_file": Path("state_https_hash.txt"),
    },
]

CHANGED_FILE = Path("changed.txt")
ERROR_FILE = Path("error.txt")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def sha256_text(value: str) -> str:
    """Return a SHA-256 hash for a text string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_state_from_response(response: requests.Response) -> tuple[str, str]:
    """Return a (status, hash) pair for a normal HTTP response."""
    status = str(response.status_code)
    location = response.headers.get("Location", "")

    hash_input = b"\n".join(
        [
            f"status:{status}".encode("utf-8"),
            f"url:{response.url}".encode("utf-8"),
            f"location:{location}".encode("utf-8"),
            b"body:",
            response.content,
        ]
    )

    return status, hashlib.sha256(hash_input).hexdigest()


def build_state_from_error(error: requests.exceptions.RequestException) -> tuple[str, str]:
    """Return a stable (status, hash) pair for network/TLS failures.

    Status is kept broad (e.g. ``ERROR:SSLError``) so flavor changes in the
    underlying error message do not by themselves count as state changes.
    """
    error_type = type(error).__name__
    status = f"ERROR:{error_type}"
    digest = sha256_text(f"{error_type}:{error}")
    return status, digest


def is_live(status: str | None) -> bool:
    """True iff the status indicates the site is serving content.

    Live = HTTP 2xx or 3xx (a real response, including redirects to the
    actual site). Everything else — 4xx, 5xx, SSL errors, timeouts,
    connection errors, no prior state — counts as "not live".
    """
    if not status or status.startswith("ERROR:"):
        return False
    try:
        code = int(status)
    except ValueError:
        return False
    return 200 <= code < 400


def check_target(target: dict) -> tuple[str | None, str | None]:
    """Check one URL. Return (change_message, error_message)."""
    name = target["name"]
    url = target["url"]
    status_file = target["status_file"]
    hash_file = target["hash_file"]

    old_status = status_file.read_text().strip() if status_file.exists() else None
    old_hash = hash_file.read_text().strip() if hash_file.exists() else None
    first_run = old_status is None and old_hash is None

    error_message = None

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT_SECONDS,
            headers=HEADERS,
            allow_redirects=False,
        )
        status, new_hash = build_state_from_response(response)
        location = response.headers.get("Location", "")

        print(f"Checked: {url}")
        print(f"Status: {status}")
        if location:
            print(f"Redirect location: {location}")
        print(f"Hash: {new_hash}")

    except requests.exceptions.RequestException as e:
        status, new_hash = build_state_from_error(e)
        error_message = f"{name.upper()} fetch issue for {url}: {type(e).__name__}: {e}"

        print(f"Checked: {url}")
        print(error_message)
        print(f"State status: {status}")
        print(f"Hash: {new_hash}")

    change_message = None

    if first_run:
        print(f"{name.upper()} first run: initialized state, no alert sent.")
    elif is_live(status) and not is_live(old_status):
        change_message = (
            f"{name.upper()} {url} appears LIVE: {old_status} -> {status}"
        )

    status_file.write_text(status + "\n")
    hash_file.write_text(new_hash + "\n")

    if change_message:
        print(f"Change detected: {change_message}")
    else:
        print(f"No live transition for {name.upper()}.")

    return change_message, error_message


def main() -> None:
    for f in (CHANGED_FILE, ERROR_FILE):
        if f.exists():
            f.unlink()

    changes = []
    errors = []

    for target in TARGETS:
        change_message, error_message = check_target(target)
        if change_message:
            changes.append(change_message)
        if error_message:
            errors.append(error_message)

    if changes:
        CHANGED_FILE.write_text("\n\n".join(changes) + "\n")

    # Diagnostic log only — the workflow does not notify from this file.
    if errors:
        ERROR_FILE.write_text("\n\n".join(errors) + "\n")


if __name__ == "__main__":
    main()
