from fastapi import FastAPI

from . import api
from .config import Settings, load_settings
from .db import connect, migrate
from .ratelimit import RateLimiter


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    application.state.settings = settings
    application.state.db = connect(settings.db_path)
    migrate(application.state.db)
    application.state.limiter = RateLimiter(settings.rate_limit_per_hour)
    application.include_router(api.router)
    return application


app = create_app()
