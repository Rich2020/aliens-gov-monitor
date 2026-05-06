"""Monitor http://aliens.gov/ and https://aliens.gov/ for changes.

Writes:
- state_http_status.txt / state_http_hash.txt
- state_https_status.txt / state_https_hash.txt
- changed.txt: created only when:
  1. HTTPS state changes, e.g. ERROR:SSLError -> 200
  2. HTTP response changes, including body/status/redirect target
- error.txt: written for debugging/logging only; the workflow should not notify from it

Notes:
- HTTP and HTTPS are monitored separately.
- Redirects are not followed, so redirect behavior can be detected directly.
- HTTPS certificate failures are recorded as state, not allowed to crash the run.
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
    """Return a status string and hash string for a normal HTTP response."""
    status = str(response.status_code)
    location = response.headers.get("Location", "")

    # Include status, redirect target, final URL, and raw body bytes in hash.
    # For HTTP, this means we detect body changes, status changes, and redirect changes.
    # For HTTPS, we only use the status for alerting, but still store the hash for logs/state.
    hash_input = b"\n".join(
        [
            f"status:{status}".encode("utf-8"),
            f"url:{response.url}".encode("utf-8"),
            f"location:{location}".encode("utf-8"),
            b"body:",
            response.content,
        ]
    )

    digest = hashlib.sha256(hash_input).hexdigest()
    return status, digest


def build_state_from_error(error: requests.exceptions.RequestException) -> tuple[str, str]:
    """Return a stable status/hash pair for network/TLS failures."""
    error_type = type(error).__name__
    error_text = str(error)

    # Keep status broad/readable, e.g. ERROR:SSLError.
    # This avoids false alerts from tiny changes in the full SSL error text.
    status = f"ERROR:{error_type}"

    # Store the full error hash for debugging/state, but HTTPS alerting only uses status.
    digest = sha256_text(f"{error_type}:{error_text}")
    return status, digest


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
    else:
        if name == "https":
            # HTTPS: only alert when the high-level state changes.
            # Examples:
            # - ERROR:SSLError -> 200
            # - ERROR:SSLError -> 301
            # - 404 -> 200
            # - 200 -> ERROR:SSLError
            #
            # Do not alert merely because the detailed SSL error text/hash changes.
            if old_status != status:
                change_message = (
                    f"HTTPS state changed for {url}: {old_status} -> {status}"
                )

        elif name == "http":
            # HTTP: alert when the response state changes.
            # The hash includes status, redirect target, final URL, and body.
            # So this catches HTML changes, status changes, and redirect changes.
            if old_hash != new_hash:
                change_message = (
                    f"HTTP response changed for {url}.\n"
                    f"Status: {status}\n"
                    f"Old hash: {old_hash}\n"
                    f"New hash: {new_hash}"
                )

    status_file.write_text(status + "\n")
    hash_file.write_text(new_hash + "\n")

    if change_message:
        print(f"Change detected: {change_message}")
    else:
        print(f"No change for {name.upper()}.")

    return change_message, error_message


def main() -> None:
    # Clear stale files from previous runs.
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

    # Debug/logging only. Your workflow should not send notifications from error.txt.
    if errors:
        ERROR_FILE.write_text("\n\n".join(errors) + "\n")


if __name__ == "__main__":
    main()