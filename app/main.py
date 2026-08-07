from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import api, web
from .config import Settings, load_settings
from .db import connect, migrate
from .ratelimit import RateLimiter

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

ERROR_COPY = {
    404: ("Nothing at this address.",
          "The page you asked for does not exist. If you followed a secret link, the secret"
          " may simply be gone — burned or expired."),
    405: ("Wrong method.",
          "That endpoint exists, but not for this HTTP method. See /llms.txt for the API"
          " contract."),
    410: ("Burned.", "This resource was consumed and no longer exists. That is by design."),
    429: ("Slow down.",
          "You hit the rate limit for creating secrets. Wait a bit and try again."),
    500: ("Something broke on our side.",
          "The error has been logged without any of your data in it. Try again in a minute."),
}


def _security_headers_middleware(application: FastAPI) -> None:
    @application.middleware("http")
    async def add_security_headers(request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if request.url.path.startswith(("/s/", "/api/")):
            response.headers["Cache-Control"] = "no-store"
        return response


def _error_handlers(application: FastAPI) -> None:
    @application.exception_handler(StarletteHTTPException)
    async def http_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                                headers=getattr(exc, "headers", None))
        heading, message = ERROR_COPY.get(exc.status_code, ("Unexpected error.", str(exc.detail)))
        return web.templates.TemplateResponse(
            request, "error.html",
            {"status": exc.status_code, "heading": heading, "message": message},
            status_code=exc.status_code)

    @application.exception_handler(Exception)
    async def server_error(request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        heading, message = ERROR_COPY[500]
        return web.templates.TemplateResponse(
            request, "error.html",
            {"status": 500, "heading": heading, "message": message}, status_code=500)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    application.state.settings = settings
    application.state.db = connect(settings.db_path)
    migrate(application.state.db)
    application.state.limiter = RateLimiter(settings.rate_limit_per_hour)
    application.include_router(api.router)
    application.include_router(web.router)
    application.mount("/static", StaticFiles(directory=str(web.BASE_DIR / "static")),
                      name="static")
    _security_headers_middleware(application)
    _error_handlers(application)
    return application


app = create_app()
