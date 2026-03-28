from fastapi import APIRouter, Depends, HTTPException, status

from ..auth.dependencies import get_current_user
from ..core.security import create_access_token
from ..models.auth import LoginRequest, TokenResponse, UserResponse
from ..services.auth import authenticate

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/me", response_model=UserResponse)
def me(username: str = Depends(get_current_user)) -> UserResponse:
    return UserResponse(username=username)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    if not authenticate.authenticate(payload.username, payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
        )
    token = create_access_token(payload.username)
    return TokenResponse(access_token=token)
