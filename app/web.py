from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from .crypto import SLUG_RE

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    settings = request.app.state.settings
    return templates.TemplateResponse(request, "home.html", {
        "max_ttl_days": settings.max_ttl_days,
        "max_kb": settings.max_secret_bytes // 1024,
    })


@router.get("/s/{slug}", response_class=HTMLResponse)
def reveal_page(slug: str, request: Request):
    if not SLUG_RE.fullmatch(slug):
        raise HTTPException(404)
    return templates.TemplateResponse(request, "secret.html", {"slug": slug})


@router.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    return "User-agent: *\nDisallow: /s/\nDisallow: /api/\nAllow: /\n"
