"""Read-only client for the Cursor Admin API (https://api.cursor.com)."""
import logging
import time
from collections.abc import Iterator

import requests
import truststore

truststore.inject_into_ssl()  # trust the Windows/OS cert store (corporate TLS inspection); never disable verification

BASE_URL = "https://api.cursor.com"
log = logging.getLogger(__name__)


class CursorAdminClient:
    def __init__(self, api_key: str):
        if not api_key:
            raise RuntimeError("CURSOR_ADMIN_API_KEY is not set (see .env.example)")
        self.session = requests.Session()
        self.cycle_start_ms: int | None = None   # from /teams/spend
        self.session.auth = (api_key, "")

    def _request(self, method: str, path: str, **kwargs):
        for attempt in range(6):
            resp = self.session.request(method, BASE_URL + path, timeout=120, **kwargs)
            if resp.status_code == 429 or resp.status_code >= 500:
                wait = int(resp.headers.get("Retry-After", 0) or 0) or min(60, 5 * 2 ** attempt)
                log.warning("%s on %s, retrying in %ss", resp.status_code, path, wait)
                time.sleep(wait)
                continue
            if not resp.ok:
                raise RuntimeError(f"{method} {path} -> {resp.status_code}: {resp.text[:500]}")
            return resp.json()
        raise RuntimeError(f"{method} {path} failed after retries")

    def members(self) -> list[dict]:
        return self._request("GET", "/teams/members")["teamMembers"]

    def spend(self) -> list[dict]:
        rows, page = [], 1
        while True:
            resp = self._request("POST", "/teams/spend", json={"page": page, "pageSize": 100})
            self.cycle_start_ms = resp.get("subscriptionCycleStart")
            rows.extend(resp["teamMemberSpend"])
            if page >= resp.get("totalPages", 1):
                return rows
            page += 1

    def usage_events(self, start_ms: int, end_ms: int) -> Iterator[dict]:
        """All usage events with start_ms <= timestamp <= end_ms (both inclusive)."""
        page = 1
        while True:
            resp = self._request("POST", "/teams/filtered-usage-events",
                                 json={"startDate": start_ms, "endDate": end_ms, "page": page, "pageSize": 1000})
            yield from resp.get("usageEvents", [])
            if not resp.get("pagination", {}).get("hasNextPage"):
                return
            page += 1
