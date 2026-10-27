"""Tests for stale YouTube cookie detection (cookie_health) and its integrations."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import cookie_health
import database
from tests.conftest import MockProcess

AUTH_JAR = (
    "# Netscape HTTP Cookie File\n"
    ".youtube.com\tTRUE\t/\tTRUE\t2000000000\tLOGIN_INFO\tabc\n"
    ".youtube.com\tTRUE\t/\tTRUE\t2000000000\tSAPISID\tsapisid-value\n"
    ".youtube.com\tTRUE\t/\tTRUE\t2000000000\tSID\tsid-value\n"
)
ANON_JAR = ".youtube.com\tTRUE\t/\tTRUE\t2000000000\tSOCS\tconsent\n"


@pytest.fixture(autouse=True)
def _reset_failures():
    cookie_health.reset_failures()
    yield
    cookie_health.reset_failures()


@pytest.fixture
def youtube_cookie_cred(test_db):
    """A YouTube site (id=1 from migrations) with one plaintext cookies_file credential."""
    cred_id = database.add_credential(1, "cookies_file", AUTH_JAR)
    return cred_id


def _mock_client(html: str, status: int = 200):
    response = MagicMock()
    response.status_code = status
    response.text = html
    response.url = "https://www.youtube.com/"
    client = MagicMock()
    client.get = AsyncMock(return_value=response)
    return client


# =============================================================================
# Probe
# =============================================================================


class TestProbe:
    def test_parse_logged_in(self):
        assert cookie_health.parse_logged_in('ytcfg.set({"LOGGED_IN":true,"X":1});') is True
        assert cookie_health.parse_logged_in('ytcfg.set({"LOGGED_IN": false});') is False
        assert cookie_health.parse_logged_in("<html>consent</html>") is None

    async def test_anonymous_jar_is_indeterminate_without_request(self):
        with patch("innertube._client.get_client", new_callable=AsyncMock) as get_client:
            result = await cookie_health.probe_jar(ANON_JAR)
        assert result.logged_in is None
        assert result.has_auth_cookies is False
        get_client.assert_not_called()

    async def test_logged_out_detected(self):
        client = _mock_client('ytcfg.set({"LOGGED_IN":false});')
        with patch("innertube._client.get_client", AsyncMock(return_value=client)):
            result = await cookie_health.probe_jar(AUTH_JAR)
        assert result.logged_in is False
        assert result.has_auth_cookies is True
        sent_cookie = client.get.call_args.kwargs["headers"]["Cookie"]
        assert "SAPISID=sapisid-value" in sent_cookie

    async def test_logged_in_detected(self):
        client = _mock_client('ytcfg.set({"LOGGED_IN":true});')
        with patch("innertube._client.get_client", AsyncMock(return_value=client)):
            result = await cookie_health.probe_jar(AUTH_JAR)
        assert result.logged_in is True

    async def test_network_error_is_indeterminate(self):
        import httpx

        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        with patch("innertube._client.get_client", AsyncMock(return_value=client)):
            result = await cookie_health.probe_jar(AUTH_JAR)
        assert result.logged_in is None
        assert "probe request failed" in result.error


# =============================================================================
# Marking / filtering
# =============================================================================


class TestMarking:
    def test_mark_stale_hides_from_enabled_sites_but_not_admin_view(self, youtube_cookie_cred):
        cookie_health.mark_stale(youtube_cookie_cred, "test")

        cred = database.get_credential(youtube_cookie_cred)
        assert cred["status"] == "stale"
        assert cred["stale_since"]
        assert cred["last_error"] == "test"

        enabled = [s for s in database.get_enabled_sites() if s["id"] == 1][0]
        assert enabled["credentials"] == []
        with_stale = [s for s in database.get_enabled_sites(include_stale=True) if s["id"] == 1][0]
        assert [c["id"] for c in with_stale["credentials"]] == [youtube_cookie_cred]
        assert [c["id"] for c in database.get_site(1)["credentials"]] == [youtube_cookie_cred]

    def test_mark_ok_recovers(self, youtube_cookie_cred):
        cookie_health.mark_stale(youtube_cookie_cred, "test")
        cookie_health.mark_ok(youtube_cookie_cred)
        cred = database.get_credential(youtube_cookie_cred)
        assert cred["status"] == "ok"
        assert cred["stale_since"] is None
        assert cred["last_validated_at"]
        assert cred["last_error"] is None

    def test_record_failure_threshold(self, youtube_cookie_cred):
        for _ in range(cookie_health.STALE_THRESHOLD - 1):
            cookie_health.record_failure([youtube_cookie_cred], "degraded")
        assert database.get_credential(youtube_cookie_cred)["status"] == "ok"
        cookie_health.record_failure([youtube_cookie_cred], "degraded")
        assert database.get_credential(youtube_cookie_cred)["status"] == "stale"

    def test_record_failure_window_expires(self, youtube_cookie_cred, monkeypatch):
        now = [1000.0]
        monkeypatch.setattr(cookie_health.time, "monotonic", lambda: now[0])
        for _ in range(cookie_health.STALE_THRESHOLD - 1):
            cookie_health.record_failure([youtube_cookie_cred], "degraded")
        now[0] += cookie_health.STALE_WINDOW + 1
        cookie_health.record_failure([youtube_cookie_cred], "degraded")
        assert database.get_credential(youtube_cookie_cred)["status"] == "ok"

    def test_inspect_ytdlp_stderr(self, youtube_cookie_cred):
        cookie_health.inspect_ytdlp_stderr("WARNING: [youtube] all good", [youtube_cookie_cred])
        assert database.get_credential(youtube_cookie_cred)["status"] == "ok"
        cookie_health.inspect_ytdlp_stderr(
            "WARNING: [youtube] The provided YouTube account cookies are no longer valid.", [youtube_cookie_cred]
        )
        assert database.get_credential(youtube_cookie_cred)["status"] == "stale"

    async def test_validate_all_reports_probe_but_does_not_flip(self, youtube_cookie_cred):
        """La prueba de GET se reporta, pero no degrada un jar que sí extrae.

        Desde la IP del servidor (datacenter) youtube.com contestó
        LOGGED_IN=false para un jar con el que yt-dlp extraía once formatos: si
        eso marcara stale, el canal se quedaba sin cookies sin motivo.
        """
        with patch("innertube._client.get_client", AsyncMock(return_value=_mock_client('"LOGGED_IN":false'))):
            results = await cookie_health.validate_all()
        assert results[0]["credential_id"] == youtube_cookie_cred
        assert results[0]["logged_in"] is False
        assert results[0]["status"] == "ok"
        assert database.get_credential(youtube_cookie_cred)["status"] == "ok"

        with patch("innertube._client.get_client", AsyncMock(return_value=_mock_client('"LOGGED_IN":true'))):
            results = await cookie_health.validate_all(site_id=1)
        assert results[0]["status"] == "ok"
        assert database.get_credential(youtube_cookie_cred)["status"] == "ok"

    async def test_indeterminate_probe_keeps_status(self, youtube_cookie_cred):
        cookie_health.mark_stale(youtube_cookie_cred, "test")
        with patch("innertube._client.get_client", AsyncMock(return_value=_mock_client("<html/>"))):
            await cookie_health.validate_all()
        assert database.get_credential(youtube_cookie_cred)["status"] == "stale"

    def test_status_summary(self, youtube_cookie_cred):
        assert cookie_health.status_summary()["status"] == "ok"
        cookie_health.mark_stale(youtube_cookie_cred, "rotated")
        summary = cookie_health.status_summary()
        assert summary["status"] == "stale"
        assert summary["last_error"] == "rotated"
        database.delete_credential(youtube_cookie_cred)
        assert cookie_health.status_summary()["status"] == "none"


# =============================================================================
# yt-dlp integration
# =============================================================================


def _formats(adaptive: bool):
    formats = [{"format_id": "18", "ext": "mp4", "vcodec": "avc1", "acodec": "mp4a", "height": 360}]
    if adaptive:
        formats.append({"format_id": "313", "ext": "webm", "vcodec": "vp9", "acodec": "none", "height": 2160})
    return formats


class TestYtdlpIntegration:
    async def test_run_ytdlp_ex_strips_no_warnings_only_with_cookies(self, youtube_cookie_cred, test_settings):
        from ytdlp_wrapper import run_ytdlp_ex

        calls = []

        async def fake_exec(*args, **kwargs):
            calls.append(args)
            return MockProcess(stdout="{}")

        with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            run = await run_ytdlp_ex("-j", "--no-warnings", "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
            assert run.cookie_ids == [youtube_cookie_cred]
            assert "--no-warnings" not in calls[-1]
            assert "--cookies" in calls[-1]

            run = await run_ytdlp_ex(
                "-j", "--no-warnings", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", use_credentials=False
            )
            assert run.cookie_ids == []
            assert "--no-warnings" in calls[-1]
            assert "--cookies" not in calls[-1]

    async def test_stderr_warning_marks_stale(self, youtube_cookie_cred, test_settings):
        from ytdlp_wrapper import run_ytdlp_ex

        async def fake_exec(*args, **kwargs):
            return MockProcess(
                stdout="{}", stderr="WARNING: [youtube] The provided YouTube account cookies are no longer valid."
            )

        with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            await run_ytdlp_ex("-j", "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        assert database.get_credential(youtube_cookie_cred)["status"] == "stale"

    async def test_get_video_info_retries_anonymously_when_degraded(self, youtube_cookie_cred, test_settings):
        from ytdlp_wrapper import get_video_info, reset_caches

        reset_caches()
        calls = []

        async def fake_exec(*args, **kwargs):
            calls.append(args)
            degraded = "--cookies" in args
            return MockProcess(stdout=json.dumps({"id": "dQw4w9WgXcQ", "formats": _formats(adaptive=not degraded)}))

        with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            info = await get_video_info("dQw4w9WgXcQ", use_cache=False)

        assert len(calls) == 2
        assert "--cookies" in calls[0] and "--cookies" not in calls[1]
        assert any(f["format_id"] == "313" for f in info["formats"])
        assert len(cookie_health._failures[youtube_cookie_cred]) == 1

    async def test_get_video_info_no_retry_without_cookies(self, test_db, test_settings):
        from ytdlp_wrapper import get_video_info, reset_caches

        reset_caches()
        calls = []

        async def fake_exec(*args, **kwargs):
            calls.append(args)
            return MockProcess(stdout=json.dumps({"id": "dQw4w9WgXcQ", "formats": _formats(adaptive=False)}))

        with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            await get_video_info("dQw4w9WgXcQ", use_cache=False)
        assert len(calls) == 1

    async def test_get_video_info_retries_on_sign_in_error(self, youtube_cookie_cred, test_settings):
        from ytdlp_wrapper import get_video_info, reset_caches

        reset_caches()

        async def fake_exec(*args, **kwargs):
            if "--cookies" in args:
                return MockProcess(stdout="", stderr="ERROR: Sign in to confirm you're not a bot", returncode=1)
            return MockProcess(stdout=json.dumps({"id": "dQw4w9WgXcQ", "formats": _formats(adaptive=True)}))

        with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            info = await get_video_info("dQw4w9WgXcQ", use_cache=False)
        assert info["id"] == "dQw4w9WgXcQ"
        assert len(cookie_health._failures[youtube_cookie_cred]) == 1

    async def test_get_video_info_reraises_original_when_retry_fails(self, youtube_cookie_cred, test_settings):
        from ytdlp_wrapper import YtDlpError, get_video_info, reset_caches

        reset_caches()

        async def fake_exec(*args, **kwargs):
            msg = "Sign in to confirm" if "--cookies" in args else "Video unavailable"
            return MockProcess(stdout="", stderr=f"ERROR: {msg}", returncode=1)

        with patch("asyncio.create_subprocess_exec", side_effect=fake_exec):
            with pytest.raises(YtDlpError, match="Sign in to confirm"):
                await get_video_info("dQw4w9WgXcQ", use_cache=False)
        assert youtube_cookie_cred not in cookie_health._failures


# =============================================================================
# Admin API / info
# =============================================================================


class TestAdminApi:
    def test_upload_rejects_logged_out_jar(self, admin_client):
        probe = cookie_health.ProbeResult(logged_in=False, has_auth_cookies=True)
        with patch("cookie_health.probe_jar", AsyncMock(return_value=probe)):
            response = admin_client.post(
                "/api/sites/1/credentials", json={"credential_type": "cookies_file", "value": AUTH_JAR}
            )
        assert response.status_code == 400
        assert "logged out" in response.json()["detail"]
        assert database.get_site(1)["credentials"] == []

    def test_upload_accepts_valid_jar_and_records_validation(self, admin_client):
        probe = cookie_health.ProbeResult(logged_in=True, has_auth_cookies=True)
        with patch("cookie_health.probe_jar", AsyncMock(return_value=probe)):
            response = admin_client.post(
                "/api/sites/1/credentials", json={"credential_type": "cookies_file", "value": AUTH_JAR}
            )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["last_validated_at"]

    def test_upload_skips_probe_for_non_youtube(self, admin_client):
        with patch("cookie_health.probe_jar", new_callable=AsyncMock) as probe:
            response = admin_client.post(
                "/api/sites",
                json={
                    "name": "Vimeo",
                    "extractor_pattern": "vimeo",
                    "credentials": [{"credential_type": "cookies_file", "value": AUTH_JAR}],
                },
            )
        assert response.status_code == 200
        probe.assert_not_called()
        assert response.json()["cookie_validation_supported"] is False
        assert [s for s in admin_client.get("/api/sites").json() if s["id"] == 1][0]["cookie_validation_supported"]

    def test_list_reports_stale_count_and_validate_endpoint(self, admin_client):
        cred_id = database.add_credential(1, "cookies_file", AUTH_JAR)
        cookie_health.mark_stale(cred_id, "rotated")

        sites = admin_client.get("/api/sites").json()
        yt = [s for s in sites if s["id"] == 1][0]
        assert yt["stale_credential_count"] == 1

        detail = admin_client.get("/api/sites/1").json()
        assert detail["credentials"][0]["status"] == "stale"
        assert detail["credentials"][0]["last_error"] == "rotated"

        with patch("innertube._client.get_client", AsyncMock(return_value=_mock_client('"LOGGED_IN":true'))):
            response = admin_client.post("/api/sites/1/validate")
        assert response.status_code == 200
        assert response.json()[0]["status"] == "ok"
        assert database.get_credential(cred_id)["status"] == "ok"

    def test_validate_unknown_site(self, admin_client):
        assert admin_client.post("/api/sites/999/validate").status_code == 404
