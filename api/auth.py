from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from datetime import timedelta
from jose import JWTError, jwt
from config import settings
from services.auth_service import create_access_token, verify_password
from services.audit_service import log_audit_action
from rate_limiter import limiter

router = APIRouter()

# Load users from settings to avoid hardcoding secrets
FAKE_USERS_DB = {
    settings.admin_username: {
        "username": settings.admin_username,
        "hashed_password": settings.admin_password_hash, 
        "role": "admin"
    },
    settings.analyst_username: {
        "username": settings.analyst_username,
        "hashed_password": settings.analyst_password_hash, 
        "role": "l1_analyst"
    }
}

@router.post("/token")
@limiter.limit("5/minute")
async def login_for_access_token(request: Request, response: Response, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = FAKE_USERS_DB.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60
    )
    await log_audit_action(user["username"], "LOGIN", "Successful login")
    return {"message": "Successfully authenticated"}

@router.post("/logout")
async def logout(response: Response, request: Request):
    response.delete_cookie(key="access_token", httponly=True, secure=False, samesite="lax")
    
    # Try to extract user for log
    try:
        token = request.cookies.get("access_token")
        if token:
            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
            if payload.get("sub"):
                await log_audit_action(payload["sub"], "LOGOUT", "Successful logout")
    except Exception:
        pass
        
    return {"message": "Successfully logged out"}

async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = FAKE_USERS_DB.get(username)
    if user is None:
        raise credentials_exception
    return user

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires admin privileges"
        )
    return current_user
