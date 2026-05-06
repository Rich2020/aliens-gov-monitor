"""Monitor http://aliens.gov/ for changes.

Writes:
- last_status.txt / last_hash.txt: state carried between runs.
- changed.txt: created when a meaningful change is detected (status flip,
  or HTML hash change while the response was successful).
- error.txt: created only on network-level failures (timeout, DNS, etc.).
"""

import hashlib
from pathlib import Path

import requests

URL = "http://aliens.gov/"
TIMEOUT_SECONDS = 30

HASH_FILE = Path("last_hash.txt")
STATUS_FILE = Path("last_status.txt")
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


def main() -> None:
    # Clear stale alert files from a previous run so we never re-fire old alerts.
    for f in (CHANGED_FILE, ERROR_FILE):
        if f.exists():
            f.unlink()

    # Only treat network-level problems as errors; HTTP 4xx/5xx are still
    # "successful" fetches that should update status/hash and may trigger
    # a status-change alert.
    try:
        response = requests.get(URL, timeout=TIMEOUT_SECONDS, headers=HEADERS)
    except requests.exceptions.RequestException as e:
        msg = f"Fetch failed for {URL}: {type(e).__name__}: {e}"
        ERROR_FILE.write_text(msg + "\n")
        print(msg)
        return

    status = str(response.status_code)
    html = response.text
    new_hash = hashlib.sha256(html.encode("utf-8")).hexdigest()

    old_status = STATUS_FILE.read_text().strip() if STATUS_FILE.exists() else None
    old_hash = HASH_FILE.read_text().strip() if HASH_FILE.exists() else None

    first_run = old_status is None and old_hash is None
    change_reason = None

    if not first_run:
        # Alert on:
        # 1. HTTP status code change (e.g. 502 -> 200, or 200 -> 404).
        # 2. HTML body change while the response was successful (2xx).
        #    We skip body-change alerts on error pages because their HTML
        #    often varies (timestamps, request IDs) and would be noisy.
        if old_status != status:
            change_reason = (
                f"Status changed for {URL}: {old_status} -> {status}"
            )
        elif response.ok and old_hash != new_hash:
            change_reason = (
                f"HTML changed for {URL} (status {status}).\n"
                f"Old hash: {old_hash}\nNew hash: {new_hash}"
            )

    if change_reason:
        CHANGED_FILE.write_text(change_reason + "\n")

    STATUS_FILE.write_text(status + "\n")
    HASH_FILE.write_text(new_hash + "\n")

    print(f"Checked: {URL}")
    print(f"HTTP status: {status}")
    print(f"Hash: {new_hash}")
    if first_run:
        print("First run: initialized state, no alert sent.")
    elif change_reason:
        print(f"Change detected: {change_reason}")
    else:
        print("No change.")


if __name__ == "__main__":
    main()
