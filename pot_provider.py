"""Manages the bundled bgutil POT provider Node process.

The provider server is baked into the Docker image at /opt/bgutil-pot-provider
(see Dockerfile pot-builder stage). When yt_pot_enabled is on and no external
provider URL is configured, this module spawns and supervises the Node process
so yt-dlp's bgutil plugin can fetch PO tokens from http://127.0.0.1:4416.

Token minting egress: the plugin forwards yt-dlp's --proxy in the /get_pot
request body, so the provider's outbound Google requests use the same egress
as yt-dlp itself — no proxy plumbing needed here.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

BUNDLE_DIR = Path(os.getenv("POT_PROVIDER_DIR", "/opt/bgutil-pot-provider"))
NODE_BIN = BUNDLE_DIR / "bin" / "node"
MAIN_JS = BUNDLE_DIR / "build" / "main.js"
POT_PORT = 4416
DEFAULT_BASE_URL = f"http://127.0.0.1:{POT_PORT}"

_TERMINATE_GRACE = 5
# Node's cold JS boot takes ~1s on a normal box but 10-15s+ on a throttled
# 512MB Render instance — a 15s window expired 1s before the server answered
# /ping in production. 60s covers the worst cold boot observed.
_READY_ATTEMPTS = 60
_MAX_BACKOFF = 60


def bundle_available() -> bool:
    """True when the bundled provider (node binary + built server) is present."""
    return NODE_BIN.is_file() and MAIN_JS.is_file()


def memoria_limite_mb() -> Optional[int]:
    """Límite de memoria del contenedor en MB (cgroup v2 o v1), o None."""
    for ruta in (
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ):
        try:
            texto = Path(ruta).read_text().strip()
        except OSError:
            continue
        if texto.isdigit():
            mb = int(texto) // (1024 * 1024)
            # "max" y los límites absurdos (2^63) significan "sin límite".
            if 0 < mb < 1_000_000:
                return mb
    return None


# Un yt-dlp + uvicorn + node(BotGuard) no entra en 512 MB: el contenedor muere
# por OOM en plena extracción y el servicio entero se cae (502 para todo).
# Debajo de este umbral el provider embebido NO se arranca; se usa uno externo
# (YT_POT_PROVIDER_URL) o se sube la memoria de la instancia.
MIN_MB_PARA_POT_EMBEBIDO = 900


def cabe_el_provider_embebido() -> bool:
    """¿Hay memoria para levantar node dentro de ESTA instancia?"""
    limite = memoria_limite_mb()
    if limite is not None and limite < MIN_MB_PARA_POT_EMBEBIDO:
        logger.warning(
            "POT provider embebido omitido: la instancia tiene %s MB y necesita "
            "~%s MB (usá YT_POT_PROVIDER_URL en un servicio aparte o subí la memoria)",
            limite,
            MIN_MB_PARA_POT_EMBEBIDO,
        )
        return False
    return True


async def _ping(timeout: float = 2.0) -> bool:
    # trust_env=False: HTTP(S)_PROXY env must never intercept the localhost ping
    try:
        async with httpx.AsyncClient(trust_env=False, timeout=timeout) as client:
            response = await client.get(f"{DEFAULT_BASE_URL}/ping")
            return response.status_code == 200
    except httpx.HTTPError:
        return False


class PotProviderManager:
    """Supervises the bundled POT provider subprocess."""

    def __init__(self):
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._task: Optional[asyncio.Task] = None
        self._healthy = False
        self._stopping = False
        self._external_process = False

    def is_healthy(self) -> bool:
        return self._healthy

    def status(self) -> dict:
        from settings import get_settings

        s = get_settings()
        if not s.yt_pot_enabled:
            mode = "off"
        elif s.effective_pot_provider_url():
            mode = "external"
        else:
            mode = "bundled"
        return {
            "mode": mode,
            "bundle_available": bundle_available(),
            "running": self._proc is not None and self._proc.returncode is None,
            "healthy": self._healthy if mode == "bundled" else None,
            "base_url": s.effective_pot_provider_url() or (DEFAULT_BASE_URL if mode == "bundled" else None),
        }

    async def apply_settings(self, s) -> None:
        """Start or stop the bundled provider to match settings.

        Called at startup and whenever POT settings change via the admin API.
        """
        want = (
            s.yt_pot_enabled
            and not s.effective_pot_provider_url()
            and bundle_available()
            and cabe_el_provider_embebido()
        )
        if want and self._task is None:
            await self.start()
        elif not want and self._task is not None:
            await self.stop()
        elif s.yt_pot_enabled and not s.effective_pot_provider_url() and not bundle_available():
            logger.warning(
                "POT provider enabled but bundle not found at %s "
                "(image built with POT_PROVIDER=none?) — PO tokens disabled",
                BUNDLE_DIR,
            )
        elif s.yt_pot_enabled and s.effective_pot_provider_url():
            logger.info("POT provider: using external provider at %s", s.effective_pot_provider_url())

    async def start(self) -> None:
        self._stopping = False
        self._task = asyncio.create_task(self._supervise())

    async def stop(self) -> None:
        self._stopping = True
        self._healthy = False
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        proc, self._proc = self._proc, None
        if proc is not None and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=_TERMINATE_GRACE)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        self._external_process = False

    async def _supervise(self) -> None:
        backoff = 1
        while not self._stopping:
            # Port already answering means another process (or worker) owns the
            # provider — don't spawn a competing one, just use it.
            if await _ping():
                if not self._external_process:
                    logger.info("POT provider already running at %s; not spawning", DEFAULT_BASE_URL)
                self._external_process = True
                self._healthy = True
                await asyncio.sleep(30)
                continue
            self._external_process = False
            try:
                # Techo de heap para el provider: en un host de 512 MB (Render
                # free) node se come el presupuesto y el contenedor muere por
                # OOM en plena extracción. Con el heap acotado V8 hace GC en vez
                # de crecer sin freno; el mint del token sigue funcionando.
                entorno = dict(os.environ)
                entorno.setdefault("NODE_OPTIONS", "--max-old-space-size=192")
                self._proc = await asyncio.create_subprocess_exec(
                    str(NODE_BIN),
                    str(MAIN_JS),
                    "--port",
                    str(POT_PORT),
                    cwd=str(BUNDLE_DIR),
                    env=entorno,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except OSError as e:
                logger.error("POT provider spawn failed: %s", e)
            else:
                pump = asyncio.create_task(self._pump_logs(self._proc))
                heal = None
                if await self._wait_ready(self._proc):
                    self._healthy = True
                    backoff = 1
                    logger.info("POT provider ready at %s", DEFAULT_BASE_URL)
                else:
                    # The server can outlive the readiness window (slow cold
                    # boot) and keep running fine — without this, the supervisor
                    # would block on wait() with _healthy stuck False forever.
                    heal = asyncio.create_task(self._heal_when_ready(self._proc))
                await self._proc.wait()
                pump.cancel()
                if heal is not None:
                    heal.cancel()
                self._healthy = False
                if self._stopping:
                    return
                logger.warning(
                    "POT provider exited rc=%s; restarting in %ss",
                    self._proc.returncode,
                    backoff,
                )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)

    async def _wait_ready(self, proc: asyncio.subprocess.Process) -> bool:
        for _ in range(_READY_ATTEMPTS):
            if proc.returncode is not None:
                return False
            if await _ping():
                return True
            await asyncio.sleep(1)
        logger.warning("POT provider did not become ready within %ss", _READY_ATTEMPTS)
        return False

    async def _heal_when_ready(self, proc: asyncio.subprocess.Process) -> None:
        """Late readiness: flip healthy when /ping answers after the window."""
        try:
            while proc.returncode is None:
                if await _ping():
                    self._healthy = True
                    logger.info("POT provider became ready (late) at %s", DEFAULT_BASE_URL)
                    return
                await asyncio.sleep(2)
        except asyncio.CancelledError:
            pass

    async def _pump_logs(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stdout is not None
        try:
            async for line in proc.stdout:
                logger.info("[POT] %s", line.decode(errors="replace").rstrip())
        except asyncio.CancelledError:
            pass


# ── Auto-encendido cuando aparece el muro de bot ─────────────────────
#
# En un host de datacenter (Render, Fly, Railway) YouTube contesta
# "Sign in to confirm you're not a bot" y todo /videos cae en 404, con o sin
# cookies: la sesión se considera deslogueada desde esas IPs. El PO token del
# provider horneado es la única salida, pero depende de una variable de entorno
# que es fácil que quede en `false` de una prueba anterior.
#
# En vez de obligar a alguien a recordarlo, el servidor se cura solo: la PRIMERA
# vez que ve el muro enciende el provider (una sola vez por proceso). Se puede
# apagar con `YT_POT_AUTO_HEAL=false`.
_AUTO_HEAL_HECHO = False


def auto_heal_habilitado() -> bool:
    valor = os.getenv("YT_POT_AUTO_HEAL", "true").strip().lower()
    return valor not in ("false", "0", "no")


async def despertar_externo() -> None:
    """Despierta el provider EXTERNO (otro servicio que puede estar dormido).

    Un plan free apaga la instancia por inactividad y el primer mint pagaría
    30-50 s de arranque, justo cuando el reproductor ya está esperando. La
    búsqueda siempre llega antes que la extracción, así que se aprovecha ese
    momento para picar el provider (best-effort, nunca lanza).
    """
    try:
        from settings import get_settings

        url = get_settings().effective_pot_provider_url()
        if not url:
            return
        async with httpx.AsyncClient(timeout=8.0) as client:
            await client.get(f"{url.rstrip('/')}/ping")
    except Exception:
        pass


def auto_heal_disparado() -> bool:
    """¿Este proceso ya intentó curarse del muro de bot?"""
    return _AUTO_HEAL_HECHO


async def auto_heal_for_wall() -> bool:
    """Enciende el provider bundled si el muro de bot apareció. Una vez por proceso."""
    global _AUTO_HEAL_HECHO
    if _AUTO_HEAL_HECHO or not auto_heal_habilitado() or not bundle_available():
        return False
    if not cabe_el_provider_embebido():
        _AUTO_HEAL_HECHO = True
        return False
    try:
        from settings import get_settings, save_settings

        s = get_settings()
        if s.yt_pot_enabled or s.effective_pot_provider_url():
            _AUTO_HEAL_HECHO = True
            return False
        _AUTO_HEAL_HECHO = True
        s.yt_pot_enabled = True
        save_settings(s)
        logger.warning(
            "Muro de bot de YouTube detectado: enciendo el PO token provider "
            "(bgutil). Desactivá esto con YT_POT_AUTO_HEAL=false."
        )
        await manager.apply_settings(s)
        return True
    except Exception as e:  # nunca romper la extracción por el auto-encendido
        logger.warning("Auto-encendido del POT provider falló: %s", e)
        return False


manager = PotProviderManager()
