"""Bandcamp track audio resolver.

Bandcamp publishes the signed MP3 of every track inside its own page, but that
page sits behind Fastly's bot challenge for datacenter IPs: Cloudflare Workers
get a 3 KB challenge page with no ``data-tralbum`` and no way to solve it. This
endpoint exists so the site can ask an instance with a normal egress IP for the
audio of a track it already found through Bandcamp's public search API.

It only reads the public page (no account, no purchase) and returns the MP3 URL
that page already hands to any visitor who plays the track.
"""

import html
import json
import logging
import re
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(tags=["bandcamp"])
logger = logging.getLogger(__name__)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

_TRALBUM = re.compile(r'data-tralbum="([^"]+)"')
_PISTA = re.compile(r"^https://[a-z0-9-]+\.bandcamp\.com/track/[A-Za-z0-9._~%-]+$")
_TIMEOUT = httpx.Timeout(15.0, connect=8.0)
_CABECERAS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "es-BO,es;q=0.9,en;q=0.8",
}


def extraer_audio(pagina: str) -> Optional[dict]:
    """Saca el MP3 y la duración del ``data-tralbum`` de la página."""
    encontrado = _TRALBUM.search(pagina)
    if not encontrado:
        return None
    datos = json.loads(html.unescape(encontrado.group(1)))
    pista = (datos.get("trackinfo") or [{}])[0]
    archivo = pista.get("file") or {}
    audio = archivo.get("mp3-128") or archivo.get("mp3-v0")
    if not audio:
        return None
    return {
        "mp3": html.unescape(audio),
        "duracion": int(pista.get("duration") or 0),
        "pista": pista.get("title") or "",
    }


@router.get("/bandcamp/audio")
async def bandcamp_audio(url: str = Query(..., min_length=8, max_length=300)):
    """Return ``{"ok": true, "mp3": ...}`` for a public Bandcamp track page."""
    if not _PISTA.match(url):
        raise HTTPException(status_code=400, detail="url de Bandcamp inválida")

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as cliente:
            respuesta = await cliente.get(url, headers=_CABECERAS)
    except httpx.HTTPError as error:
        logger.warning("bandcamp: no se pudo pedir %s (%s)", url, error)
        return {"ok": False, "motivo": "sin respuesta de bandcamp"}

    if respuesta.status_code != 200:
        return {"ok": False, "motivo": f"bandcamp respondió {respuesta.status_code}"}

    datos = extraer_audio(respuesta.text)
    if not datos:
        logger.warning(
            "bandcamp: página sin data-tralbum (%s bytes) %s", len(respuesta.text), url
        )
        return {
            "ok": False,
            "motivo": "la página no trae data-tralbum",
            "bytes": len(respuesta.text),
        }

    return {"ok": True, **datos}
