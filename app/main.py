import asyncio
import contextlib
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import api, cleanup, web
from .config import Settings, load_settings
from .db import connect, migrate
from .ratelimit import RateLimiter

CLEANUP_INTERVAL_SECONDS = 3600

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

from .i18n import make_t, negotiate

TRANSLATED_ERRORS = (405, 410, 429, 500)


def _error_context(request, status: int, detail) -> dict:
    t = make_t(negotiate(request.headers.get("accept-language")))
    if status in TRANSLATED_ERRORS:
        return {"status": status, "heading": t(f"err_{status}_h"),
                "message": t(f"err_{status}_m")}
    # 404 renders its own animated branch; heading/message are the generic fallback
    return {"status": status, "heading": t("err_generic_h"), "message": str(detail)}


def _body_size_guard(application: FastAPI, max_secret_bytes: int) -> None:
    # b64 inflates 4/3 and JSON adds envelope; anything beyond this cap is
    # rejected before FastAPI even parses the body.
    cap = max_secret_bytes * 4 // 3 + 131_072

    @application.middleware("http")
    async def reject_oversized_bodies(request, call_next):
        if request.method == "POST" and request.url.path.startswith("/api/"):
            length = request.headers.get("content-length", "0")
            if not length.isdigit() or int(length) > cap:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)


def _security_headers_middleware(application: FastAPI) -> None:
    @application.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if request.url.path.startswith(("/s/", "/api/")):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/static/"):
            # URLs carry a content hash (?v=), so caches may hold them forever
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Vary"] = "Accept-Language"
        return response


def _error_handlers(application: FastAPI) -> None:
    @application.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                                headers=getattr(exc, "headers", None))
        return web.templates.TemplateResponse(
            request, "error.html",
            _error_context(request, exc.status_code, exc.detail),
            status_code=exc.status_code)

    @application.exception_handler(Exception)
    async def server_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        return web.templates.TemplateResponse(
            request, "error.html", _error_context(request, 500, None), status_code=500)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app_: FastAPI):
        # Expired secrets are swept by the process itself: once at startup,
        # then hourly. No external cron or systemd timer needed.
        async def sweeper():
            while True:
                deleted = await asyncio.to_thread(cleanup.run, app_.state.db)
                if deleted:
                    print(f"sweep: purged {deleted} expired secret(s)", flush=True)
                await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)

        task = asyncio.create_task(sweeper())
        yield
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None,
                          lifespan=lifespan)
    application.state.settings = settings
    application.state.db = connect(settings.db_path)
    migrate(application.state.db)
    application.state.limiter = RateLimiter(settings.rate_limit_per_hour)
    web.templates.env.globals["base_url"] = settings.base_url
    application.include_router(api.router)
    application.include_router(web.router)
    application.mount("/static", StaticFiles(directory=str(web.BASE_DIR / "static")),
                      name="static")
    _body_size_guard(application, settings.max_secret_bytes)
    _security_headers_middleware(application)
    _error_handlers(application)
    return application


app = create_app()
