from fastapi import APIRouter, HTTPException, status

from ..core.security import create_access_token
from ..models.auth import LoginRequest, TokenResponse
from ..services.auth import authenticate

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    if not authenticate.authenticate(payload.username, payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
        )
    token = create_access_token(payload.username)
    return TokenResponse(access_token=token)
