from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(10.0)
MAX_RETRIES = 3


async def fetch_json(
    client: httpx.AsyncClient,
    url: str,
    headers: Optional[dict[str, str]] = None,
) -> Optional[Any]:
    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.get(url, headers=headers or {}, timeout=TIMEOUT)
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                await asyncio.sleep(retry_after)
                continue
            if resp.status_code == 403:
                raise httpx.HTTPStatusError(
                    f"403 Forbidden: {url}", request=resp.request, response=resp
                )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                raise
            if attempt == MAX_RETRIES - 1:
                log.debug("HTTP error fetching %s: %s", url, exc)
                return None
            await asyncio.sleep(2 ** attempt)
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            if attempt == MAX_RETRIES - 1:
                log.debug("Request error fetching %s: %s", url, exc)
                return None
            await asyncio.sleep(2 ** attempt)
    return None
