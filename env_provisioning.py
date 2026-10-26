"""Auto-provisioning from environment variables for automated deployments."""

import base64
import logging

from cryptography.fernet import InvalidToken

import auth
import config
import database
import encryption
import settings as settings_module

logger = logging.getLogger(__name__)


def apply_env_provisioning():
    """Apply provisioning from environment variables (runs once at startup).

    - ADMIN_USERNAME + ADMIN_PASSWORD: creates or updates admin user
    - YT_COOKIES_YOUTUBE_B64 / YT_COOKIES_YOUTUBE: provisions YouTube cookies (survives ephemeral disk)
    - INVIDIOUS_INSTANCE_URL: configures Invidious instance and enables proxy
    - YT_EGRESS_PROXY: configures HTTP/SOCKS proxy for YouTube-bound traffic
    - YT_IP_FAMILY: forces IP family (auto/ipv4/ipv6) for YouTube-bound traffic
    - YT_POT_ENABLED + YT_POT_PROVIDER_URL: configures the PO token provider
    """
    _provision_admin_user()
    _provision_cookies_youtube()
    _provision_invidious()
    _provision_egress_proxy()
    _provision_ip_family()
    _provision_pot()


def _provision_admin_user():
    """Create or update admin user from env vars."""
    username = config.ADMIN_USERNAME
    password = config.ADMIN_PASSWORD

    if not username or not password:
        return

    existing = database.get_user_by_username(username)
    if existing:
        database.update_user_password(existing["id"], auth.hash_password(password))
        database.update_user(existing["id"], is_admin=True)
        logger.info("ENV provisioning: updated admin user '%s'", username)
    else:
        database.create_admin(username, auth.hash_password(password))
        logger.info("ENV provisioning: created admin user '%s'", username)


def _provision_cookies_youtube():
    """Provision the YouTube cookies_file credential from env vars.

    The data directory (SQLite DB + encryption key) is ephemeral on PaaS
    hosts, so cookies uploaded through the API vanish on every restart or
    redeploy. When YT_COOKIES_YOUTUBE_B64 (or YT_COOKIES_YOUTUBE) is set,
    the credential is (re)created at every startup, making cookies durable
    across restarts. The env value is the source of truth: it replaces any
    existing cookies_file credential on the YouTube site.
    """
    cookies = None
    if config.YT_COOKIES_YOUTUBE_B64:
        compact = "".join(config.YT_COOKIES_YOUTUBE_B64.split())
        try:
            cookies = base64.b64decode(compact, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            logger.warning("ENV provisioning: ignoring invalid YT_COOKIES_YOUTUBE_B64 (%s)", exc)
            return
    elif config.YT_COOKIES_YOUTUBE:
        cookies = config.YT_COOKIES_YOUTUBE

    if not cookies or "youtube.com" not in cookies:
        logger.warning("ENV provisioning: YT_COOKIES_YOUTUBE(_B64) does not look like YouTube cookies; ignoring")
        return

    site = database.get_site_by_extractor("youtube")
    if site:
        site_id = site["id"]
    else:
        site_id = database.create_site(
            name="YouTube", extractor_pattern="youtube", enabled=True, priority=100, proxy_streaming=False
        )

    stored = encryption.encrypt(cookies) if encryption.should_encrypt("cookies_file") else cookies

    identical = False
    for cred in database.get_cookie_credentials(site_id):
        try:
            current = encryption.decrypt(cred["value"]) if cred["is_encrypted"] else cred["value"]
        except (InvalidToken, ValueError):
            current = None
        if current == cookies:
            identical = True
        else:
            database.delete_credential(cred["id"])

    if identical:
        logger.info("ENV provisioning: YouTube cookies_file credential already up to date")
        return

    database.add_credential(
        site_id=site_id,
        credential_type="cookies_file",
        value=stored,
        is_encrypted=encryption.should_encrypt("cookies_file"),
    )
    logger.info("ENV provisioning: provisioned YouTube cookies_file credential (%d bytes)", len(cookies))


def _provision_invidious():
    """Configure Invidious instance URL from env var."""
    url = config.INVIDIOUS_INSTANCE_URL
    if not url:
        return

    s = settings_module.load_settings()
    s.invidious_instance = url.rstrip("/")
    s.invidious_enabled = True
    settings_module.save_settings(s)
    logger.info("ENV provisioning: configured Invidious instance '%s'", url)


def _provision_egress_proxy():
    """Configure YouTube egress proxy from env var."""
    url = config.YT_EGRESS_PROXY
    if not url:
        return

    s = settings_module.load_settings()
    s.yt_egress_proxy = url
    s.yt_egress_proxy_enabled = True
    settings_module.save_settings(s)
    logger.info("ENV provisioning: configured YT egress proxy")


def _provision_ip_family():
    """Configure forced IP family for YouTube egress from env var."""
    family = config.YT_IP_FAMILY
    if not family:
        return

    family = family.strip().lower()
    if family not in ("auto", "ipv4", "ipv6"):
        logger.warning("ENV provisioning: ignoring invalid YT_IP_FAMILY %r (use auto/ipv4/ipv6)", family)
        return

    s = settings_module.load_settings()
    s.yt_ip_family = family
    settings_module.save_settings(s)
    logger.info("ENV provisioning: configured YT IP family '%s'", family)


def _provision_pot():
    """Configure the PO token provider from env vars."""
    enabled = config.YT_POT_ENABLED
    url = config.YT_POT_PROVIDER_URL
    if enabled is None and url is None:
        # Sin variable explícita: si la imagen trae el provider horneado, se
        # enciende solo. En un host de datacenter (Render, Fly, Railway) sin PO
        # token YouTube contesta con el muro de bot y /videos devuelve 404 en
        # TODO; con token la extracción vuelve. Las cookies no alcanzan: la
        # sesión se considera deslogueada desde esas IPs.
        import pot_provider

        if not pot_provider.bundle_available():
            return
        s = settings_module.load_settings()
        if s.yt_pot_enabled:
            return
        s.yt_pot_enabled = True
        settings_module.save_settings(s)
        logger.info("ENV provisioning: POT provider encontrado en la imagen; se habilita solo")
        return

    s = settings_module.load_settings()
    if enabled is not None:
        value = enabled.strip().lower()
        if value in ("true", "1", "yes"):
            s.yt_pot_enabled = True
        elif value in ("false", "0", "no"):
            s.yt_pot_enabled = False
        else:
            logger.warning("ENV provisioning: ignoring invalid YT_POT_ENABLED %r (use true/false)", enabled)
    if url is not None:
        s.yt_pot_provider_url = url.rstrip("/")
    settings_module.save_settings(s)
    logger.info(
        "ENV provisioning: configured POT provider (enabled=%s, url=%s)",
        s.yt_pot_enabled,
        s.yt_pot_provider_url or "bundled",
    )
