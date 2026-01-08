
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)

try:
    from jose import JWTError, jwt
    JOSE_AVAILABLE = True
except ImportError:
    JOSE_AVAILABLE = False
    logger.warning("python-jose not installed, JWT auth disabled")

class AuthConfig:
    SECRET_KEY: str = "isolog-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    ENABLED: bool = False  # Disabled by default for air-gapped

class AuthMiddleware:
    
    def __init__(self, config: AuthConfig = None):
        self.config = config or AuthConfig()
        self._bearer = HTTPBearer(auto_error=False)
    
    def create_access_token(
        self,
        data: dict,
        expires_delta: timedelta = None,
    ) -> str:
        if not JOSE_AVAILABLE:
            raise HTTPException(500, "JWT library not available")
        
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.config.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode.update({"exp": expire})
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.config.SECRET_KEY,
            algorithm=self.config.ALGORITHM,
        )
        
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[dict]:
        if not JOSE_AVAILABLE:
            return None
        
        try:
            payload = jwt.decode(
                token,
                self.config.SECRET_KEY,
                algorithms=[self.config.ALGORITHM],
            )
            return payload
        except JWTError as e:
            logger.debug(f"JWT verification failed: {e}")
            return None
    
    async def get_current_user(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
    ) -> Optional[dict]:
        if not self.config.ENABLED:
            return {"username": "anonymous", "role": "admin"}
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        payload = self.verify_token(credentials.credentials)
        
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return payload
    
    async def get_optional_user(
        self,
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
    ) -> Optional[dict]:
        if not self.config.ENABLED:
            return {"username": "anonymous", "role": "admin"}
        
        if not credentials:
            return None
        
        return self.verify_token(credentials.credentials)
    
    def require_role(self, role: str):
        async def role_checker(user: dict = Depends(self.get_current_user)):
            if user.get("role") != role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role}' required",
                )
            return user
        
        return role_checker

auth = AuthMiddleware()

def create_token(username: str, role: str = "user") -> str:
    return auth.create_access_token({"username": username, "role": role})

def get_current_user():
    return Depends(auth.get_current_user)

def get_optional_user():
    return Depends(auth.get_optional_user)
