from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api.auth import router as auth_router
from .api.features import router as features_router
from .core.config import settings
from .services.dns import dns_service
from .services.wireguard import wireguard_service


@asynccontextmanager
async def lifespan(_app: FastAPI):
    dns_service.sync_adguard_clients_from_home()
    wireguard_service.import_clients_from_disk()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(auth_router)
app.include_router(features_router)


@app.exception_handler(ValueError)
async def value_error_handler(_request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


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
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")


@app.get("/")
def login_page() -> FileResponse:
    return FileResponse(frontend_dir / "login.html")


@app.get("/login")
def login_page_alias() -> FileResponse:
    return FileResponse(frontend_dir / "login.html")


@app.get("/dashboard")
def dashboard_page() -> FileResponse:
    return FileResponse(frontend_dir / "index.html")
