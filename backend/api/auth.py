from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

from ..core.config import settings
from ..core.security import create_access_token
from ..models.auth import LoginRequest, TokenResponse
from ..services.auth import authenticate

router = APIRouter(prefix="/api/auth", tags=["auth"])

_COOKIE_MAX_AGE = 365 * 24 * 60 * 60  # 1 year


def _make_token_response(token: str, redirect_url: str | None = None) -> JSONResponse | RedirectResponse:
    if redirect_url:
        r = RedirectResponse(url=redirect_url, status_code=302)
    else:
        r = JSONResponse(content={"access_token": token, "token_type": "bearer"})
    r.set_cookie(
        key=settings.auth_cookie_name,
        value=token,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return r


@router.post("/login")
def login(payload: LoginRequest) -> JSONResponse:
    if not authenticate.authenticate(payload.username, payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
        )
    token = create_access_token(payload.username)
    return _make_token_response(token)  # type: ignore[return-value]


@router.post("/login/form")
def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> RedirectResponse:
    """Form-based login: sets cookie and redirects to dashboard."""
    if not authenticate.authenticate(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
        )
    token = create_access_token(form_data.username)
    return _make_token_response(token, redirect_url="/dashboard/wireguard")  # type: ignore[return-value]


@router.get("/logout")
def logout() -> RedirectResponse:
    """Clear auth cookie and redirect to login."""
    r = RedirectResponse(url="/login", status_code=302)
    r.delete_cookie(settings.auth_cookie_name, path="/")
    return r
