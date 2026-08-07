from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

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
