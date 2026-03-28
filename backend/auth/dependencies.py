from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from ..core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class AuthRedirect(Exception):
    """Raised when cookie auth fails — redirect to login."""

    def __init__(self, url: str = "/login"):
        self.url = url


def _decode_token(token: str) -> str | None:
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        return payload.get("sub")
    except JWTError:
        return None


def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    username = _decode_token(token)
    if not username:
        raise credentials_exception
    return username


def get_current_user_from_cookie(request: Request) -> str:
    """For server-rendered pages: auth via cookie. Raises AuthRedirect if not authenticated."""
    token = request.cookies.get(settings.auth_cookie_name)
    if not token:
        raise AuthRedirect()
    username = _decode_token(token)
    if not username:
        raise AuthRedirect()
    return username
