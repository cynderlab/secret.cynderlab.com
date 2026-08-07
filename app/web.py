import hashlib
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from .crypto import SLUG_RE
from .i18n import make_t, negotiate
from .store import get_meta

BASE_DIR = Path(__file__).resolve().parent.parent


def _i18n_context(request: Request) -> dict:
    lang = negotiate(request.headers.get("accept-language"))
    return {"lang": lang, "t": make_t(lang)}


templates = Jinja2Templates(directory=str(BASE_DIR / "templates"),
                            context_processors=[_i18n_context])
router = APIRouter()


@lru_cache(maxsize=None)
def _asset_hash(rel_path: str) -> str:
    return hashlib.sha256((BASE_DIR / "static" / rel_path).read_bytes()).hexdigest()[:8]


def static_url(rel_path: str) -> str:
    """Content-hashed static URL: cache busts exactly when the file changes."""
    try:
        return f"/static/{rel_path}?v={_asset_hash(rel_path)}"
    except OSError:
        return f"/static/{rel_path}"


templates.env.globals["static_url"] = static_url


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    settings = request.app.state.settings
    return templates.TemplateResponse(request, "home.html", {
        "max_ttl_days": settings.max_ttl_days,
        "max_kb": settings.max_secret_bytes // 1024,
    })


@router.get("/how-it-works", response_class=HTMLResponse)
def how_it_works(request: Request):
    return templates.TemplateResponse(request, "how-it-works.html", {})


@router.get("/s/{slug}", response_class=HTMLResponse)
def reveal_page(slug: str, request: Request):
    if not SLUG_RE.fullmatch(slug):
        raise HTTPException(404)
    if get_meta(request.app.state.db, slug) is None:
        # burned, expired or never existed — same branded 404 for all of them
        raise HTTPException(404)
    return templates.TemplateResponse(request, "secret.html", {"slug": slug})


@router.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return "User-agent: *\nDisallow: /s/\nDisallow: /api/\nAllow: /\n"



@router.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    lang = negotiate(request.headers.get("accept-language"))
    return templates.TemplateResponse(request, f"privacy-{lang}.html", {})


@router.get("/legal", response_class=HTMLResponse)
def legal(request: Request):
    lang = negotiate(request.headers.get("accept-language"))
    return templates.TemplateResponse(request, f"legal-{lang}.html", {})
