from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from .api.auth import router as auth_router
from .api.features import router as features_router
from .api.pages import router as pages_router
from .auth.dependencies import AuthRedirect
from .core.config import settings
from .services.dns import dns
from .services.wireguard import wireguard


@asynccontextmanager
async def lifespan(_app: FastAPI):
    dns.sync_adguard_clients_from_home()
    wireguard.import_clients_from_disk()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(auth_router)
app.include_router(features_router)
app.include_router(pages_router)


@app.exception_handler(ValueError)
async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(AuthRedirect)
async def auth_redirect_handler(_request: Request, exc: AuthRedirect) -> RedirectResponse:
    return RedirectResponse(url=exc.url, status_code=302)


# Wildcard origin is incompatible with credentials=True (browser CORS rules).
_cors = settings.cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors if _cors else ["*"],
    allow_credentials=bool(_cors),
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
templates_dir = Path(__file__).resolve().parent / "templates"

if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

templates = Jinja2Templates(directory=str(templates_dir))


@app.get("/")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/login")
async def login_page_alias(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
