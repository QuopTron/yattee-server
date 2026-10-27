"""Staleness tracking for YouTube account cookies.

Rotated account cookies don't fail loudly: YouTube treats the jar as logged
out and yt-dlp / InnerTube quietly return degraded results (360p-only). This
module detects that state and marks the credential row stale so
get_enabled_sites() skips it and every consumer falls back to anonymous
access. Two signals feed it:

- explicit: yt-dlp's "cookies are no longer valid" warning on stderr, or a
  direct probe of youtube.com that reads ytcfg LOGGED_IN with the jar;
- outcome-based: get_video_info retries without credentials when the cookie
  run fails/degrades; a retry that succeeds counts as one failure, and
  STALE_THRESHOLD failures within STALE_WINDOW seconds flip the row.

A periodic probe (and the admin "Validate" button) re-checks every jar so a
stale row recovers on its own when the session comes back.
"""

import asyncio
import logging
import re
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Deque, Dict, Iterable, List, Optional

import httpx
from cryptography.fernet import InvalidToken

import database
import encryption

logger = logging.getLogger(__name__)

PROBE_INTERVAL = 3600  # seconds between periodic re-validation runs
STALE_THRESHOLD = 3  # outcome-based failures needed to mark a jar stale…
STALE_WINDOW = 600  # …within this many seconds

PROBE_URL = "https://www.youtube.com/"
PROBE_TIMEOUT = 15

# Substring of yt-dlp's warning (yt_dlp/extractor/youtube/_base.py) emitted
# when YouTube clears LOGIN_INFO on a request made with rotated cookies.
COOKIE_INVALID_MARKER = "account cookies are no longer valid"

_LOGGED_IN_RE = re.compile(r'"LOGGED_IN"\s*:\s*(true|false)')

# credential id -> timestamps of recent outcome-based failures
_failures: Dict[int, Deque[float]] = {}
_probe_task: Optional[asyncio.Task] = None


@dataclass
class ProbeResult:
    logged_in: Optional[bool]  # None = indeterminate (anonymous jar, consent wall, network error)
    has_auth_cookies: bool
    error: Optional[str] = None


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _has_auth_cookies(cookies: Dict[str, str]) -> bool:
    # Same rule as yt-dlp's _has_auth_cookies: LOGIN_INFO is cleared on rotation
    # while the *SAPISID family survives, so both are required.
    sapisid = cookies.get("SAPISID") or cookies.get("__Secure-1PAPISID") or cookies.get("__Secure-3PAPISID")
    return bool(cookies.get("LOGIN_INFO") and sapisid)


def parse_logged_in(html: str) -> Optional[bool]:
    """Extract ytcfg LOGGED_IN from a YouTube page. None if not present."""
    m = _LOGGED_IN_RE.search(html)
    if not m:
        return None
    return m.group(1) == "true"


async def probe_jar(netscape_text: str) -> ProbeResult:
    """GET youtube.com with the jar and read ytcfg LOGGED_IN.

    Goes through innertube's shared httpx client so the egress proxy / IP
    family apply, but deliberately not through innertube_post(): that path
    requires innertube_enabled and merges every jar into one Cookie header.
    """
    from innertube._client import _format_cookie_header, _load_cookies_from_netscape, get_client

    cookies = _load_cookies_from_netscape(netscape_text)
    if not _has_auth_cookies(cookies):
        return ProbeResult(logged_in=None, has_auth_cookies=False, error="no account cookies (LOGIN_INFO/SAPISID)")

    try:
        client = await get_client()
        response = await client.get(
            PROBE_URL, headers={"Cookie": _format_cookie_header(cookies)}, timeout=PROBE_TIMEOUT
        )
    except (httpx.HTTPError, OSError) as e:
        logger.warning(f"[CookieHealth] Probe request failed: {e}")
        return ProbeResult(logged_in=None, has_auth_cookies=True, error=f"probe request failed: {e}")

    logged_in = parse_logged_in(response.text)
    if logged_in is None:
        logger.warning(
            f"[CookieHealth] Probe indeterminate: HTTP {response.status_code}, final URL {response.url}, "
            f"no LOGGED_IN in ytcfg"
        )
        return ProbeResult(
            logged_in=None, has_auth_cookies=True, error=f"no LOGGED_IN in response (HTTP {response.status_code})"
        )
    return ProbeResult(logged_in=logged_in, has_auth_cookies=True)


def _invalidate_video_caches() -> None:
    """Drop cached video results so a degraded (360p) entry doesn't outlive the jar."""
    import ytdlp_wrapper
    from innertube import _video as innertube_video

    ytdlp_wrapper.get_video_cache().clear()
    innertube_video.reset_cache()


def mark_stale(credential_id: int, reason: str) -> None:
    cred = database.get_credential(credential_id)
    if not cred:
        return
    if cred.get("status") == "stale":
        logger.debug(f"[CookieHealth] Credential {credential_id} already stale ({reason})")
        return
    database.update_credential_status(
        credential_id,
        status="stale",
        stale_since=_now(),
        last_validated_at=cred.get("last_validated_at"),
        last_error=reason,
    )
    _failures.pop(credential_id, None)
    _invalidate_video_caches()
    logger.warning(f"[CookieHealth] Credential {credential_id} marked STALE: {reason}")


def mark_ok(credential_id: int) -> None:
    cred = database.get_credential(credential_id)
    if not cred:
        return
    was_stale = cred.get("status") == "stale"
    database.update_credential_status(credential_id, status="ok", last_validated_at=_now())
    _failures.pop(credential_id, None)
    if was_stale:
        _invalidate_video_caches()
        logger.info(f"[CookieHealth] Credential {credential_id} recovered: session is logged in again")
    else:
        logger.info(f"[CookieHealth] Credential {credential_id} validated: logged in")


def record_failure(credential_ids: Iterable[int], reason: str) -> None:
    """Count one outcome-based failure per jar; mark stale past the threshold."""
    now = time.monotonic()
    for cred_id in credential_ids:
        window = _failures.setdefault(cred_id, deque())
        window.append(now)
        while window and now - window[0] > STALE_WINDOW:
            window.popleft()
        logger.info(f"[CookieHealth] Credential {cred_id}: {len(window)}/{STALE_THRESHOLD} failures ({reason})")
        if len(window) >= STALE_THRESHOLD:
            mark_stale(cred_id, f"{STALE_THRESHOLD} anonymous-retry successes in {STALE_WINDOW}s; last: {reason}")


def reset_failures() -> None:
    _failures.clear()


def inspect_ytdlp_stderr(stderr: str, credential_ids: Iterable[int]) -> None:
    """Mark jars stale when yt-dlp itself reports the cookies as rotated."""
    if not stderr or COOKIE_INVALID_MARKER not in stderr:
        return
    for cred_id in credential_ids:
        mark_stale(cred_id, "yt-dlp: account cookies are no longer valid (rotated)")


async def validate_credential(cred: dict) -> ProbeResult:
    """Probe one cookies_file credential row and persist the outcome."""
    cred_id = cred["id"]
    value = cred["value"]
    if cred.get("is_encrypted"):
        try:
            value = encryption.decrypt(value)
        except InvalidToken as e:
            logger.error(f"[CookieHealth] Credential {cred_id}: cannot decrypt: {e}")
            return ProbeResult(logged_in=None, has_auth_cookies=False, error="cannot decrypt")

    result = await probe_jar(value)
    if result.logged_in is True:
        mark_ok(cred_id)
    elif result.logged_in is False:
        # NO se marca stale por esto. La prueba es un GET a youtube.com desde la
        # IP del servidor y desde un datacenter da falsos negativos: se vio un
        # jar que extraía 11 formatos de audio con yt-dlp y que la prueba daba
        # por deslogueado, dejando el canal sin cookies sin motivo. La rotación
        # real se detecta con la advertencia de yt-dlp
        # (`inspect_ytdlp_stderr`) y con los reintentos anónimos exitosos
        # (`record_failure`), que sí son evidencia de uso.
        logger.warning(
            f"[CookieHealth] Credential {cred_id}: probe says logged out; se deja el estado "
            "como está (la prueba no es confiable desde esta IP)"
        )
        database.update_credential_status(
            cred_id,
            status=cred.get("status") or "ok",
            stale_since=cred.get("stale_since"),
            last_validated_at=_now(),
            last_error=None,
        )
    else:
        # Indeterminate: keep status, just note the attempt
        database.update_credential_status(
            cred_id,
            status=cred.get("status") or "ok",
            stale_since=cred.get("stale_since"),
            last_validated_at=_now(),
            last_error=result.error if cred.get("status") == "stale" else cred.get("last_error"),
        )
        logger.info(f"[CookieHealth] Credential {cred_id}: probe indeterminate ({result.error})")
    return result


def _is_youtube(cred: dict) -> bool:
    return (cred.get("extractor_pattern") or "").lower() == "youtube"


async def validate_all(site_id: Optional[int] = None) -> List[dict]:
    """Probe every YouTube cookies_file credential (optionally one site's)."""
    results = []
    for cred in database.get_cookie_credentials(site_id):
        if not _is_youtube(cred):
            continue
        result = await validate_credential(cred)
        results.append(
            {
                "credential_id": cred["id"],
                "site_id": cred["site_id"],
                "logged_in": result.logged_in,
                # `logged_in: false` se reporta, pero no cambia el estado: ver el
                # comentario de `validate_credential` (la prueba da falsos
                # negativos desde una IP de datacenter).
                "status": "ok" if result.logged_in else cred["status"],
                "error": result.error,
            }
        )
    return results


def status_summary() -> dict:
    """Aggregate over YouTube cookies_file rows for /info."""
    rows = [c for c in database.get_cookie_credentials() if _is_youtube(c) and c.get("site_enabled")]
    if not rows:
        return {"status": "none", "stale_since": None, "last_validated_at": None, "last_error": None}
    stale = [c for c in rows if c.get("status") == "stale"]
    if stale:
        first = min(stale, key=lambda c: c.get("stale_since") or "")
        return {
            "status": "stale",
            "stale_since": first.get("stale_since"),
            "last_validated_at": first.get("last_validated_at"),
            "last_error": first.get("last_error"),
        }
    latest = max((c.get("last_validated_at") or "" for c in rows), default="") or None
    return {"status": "ok", "stale_since": None, "last_validated_at": latest, "last_error": None}


async def _probe_loop() -> None:
    while True:
        try:
            results = await validate_all()
            if results:
                logger.info(f"[CookieHealth] Periodic validation: {results}")
        except Exception as e:
            logger.error(f"[CookieHealth] Periodic validation failed: {e}", exc_info=True)
        await asyncio.sleep(PROBE_INTERVAL)


def start_task() -> None:
    """Start the periodic probe; the first run happens immediately (covers restart)."""
    global _probe_task
    if _probe_task is None or _probe_task.done():
        _probe_task = asyncio.create_task(_probe_loop())


def stop_task() -> None:
    global _probe_task
    if _probe_task and not _probe_task.done():
        _probe_task.cancel()
    _probe_task = None
