from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import os
import httpx
import logging
from typing import Dict, Any, List, Optional
import time

logger = logging.getLogger(__name__)

# Configuration
SECRET_KEY = os.getenv("UNISON_JWT_SECRET", "your-secret-key")
ALGORITHM = "HS256"
AUTH_SERVICE_URL = os.getenv("UNISON_AUTH_SERVICE_URL", "http://auth:8088")
SERVICE_SECRET = os.getenv("UNISON_SERVICE_SECRET", "default-service-secret")

security = HTTPBearer(auto_error=False)

class AuthError(Exception):
    """Authentication error exception"""
    def __init__(self, message: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class PermissionError(Exception):
    """Authorization error exception"""
    def __init__(self, message: str, status_code: int = status.HTTP_403_FORBIDDEN):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

async def verify_token_with_auth_service(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token with auth service"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{AUTH_SERVICE_URL}/verify",
                json={"token": token}
            )
            
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            logger.warning(f"Token verification failed: {response.text}")
            return None
        else:
            logger.error(f"Auth service error: {response.status_code} - {response.text}")
            return None
            
    except httpx.RequestError as e:
        logger.error(f"Auth service unavailable: {e}")
        # Fail closed - if auth service is down, deny access
        return None
    except Exception as e:
        logger.error(f"Unexpected error during token verification: {e}")
        return None

async def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict[str, Any]:
    """Verify JWT token and return user information"""
    
    if not credentials:
        raise AuthError("No authentication token provided")
    
    # Verify token with auth service
    token_data = await verify_token_with_auth_service(credentials.credentials)
    
    if not token_data or not token_data.get("valid"):
        raise AuthError("Invalid or expired authentication token")
    
    return {
        "username": token_data.get("username"),
        "roles": token_data.get("roles", []),
        "token_type": token_data.get("type"),
        "exp": token_data.get("exp")
    }

async def verify_service_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict[str, Any]:
    """Verify service token for inter-service communication"""
    
    if not credentials:
        raise AuthError("No service token provided")
    
    user_data = await verify_token(credentials)
    
    if not user_data:
        raise AuthError("Invalid service token")
    
    # Check if this is a service token
    if "service" not in user_data.get("roles", []):
        raise PermissionError("Token does not have service role")
    
    return user_data

def require_roles(required_roles: List[str]):
    """Dependency decorator to require specific roles"""
    async def role_checker(current_user: Dict[str, Any] = Depends(verify_token)) -> Dict[str, Any]:
        user_roles = current_user.get("roles", [])
        
        if not any(role in user_roles for role in required_roles):
            raise PermissionError(
                f"Insufficient permissions. Required: {required_roles}, User has: {user_roles}"
            )
        
        return current_user
    
    return role_checker

def require_role(role: str):
    """Dependency decorator to require a specific role"""
    return require_roles([role])

def require_any_role(roles: List[str]):
    """Dependency decorator to require any of the specified roles"""
    return require_roles(roles)

def require_admin():
    """Dependency decorator to require admin role"""
    return require_role("admin")

def require_operator():
    """Dependency decorator to require operator role"""
    return require_role("operator")

def require_developer():
    """Dependency decorator to require developer role"""
    return require_role("developer")

def require_user():
    """Dependency decorator to require user role"""
    return require_role("user")

def create_service_token(service_name: str, service_secret: str = None) -> str:
    """Create a service token for inter-service communication"""
    if service_secret is None:
        service_secret = SERVICE_SECRET
    
    # This should use the same secret as the auth service
    payload = {
        "sub": f"service-{service_name}",
        "type": "service",
        "roles": ["service"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour
        "jti": f"service_{int(time.time())}_{service_name}"
    }
    
    try:
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    except Exception as e:
        logger.error(f"Failed to create service token: {e}")
        raise AuthError("Failed to create service token")

def verify_service_token_locally(token: str) -> bool:
    """Verify service token locally (for when auth service is unavailable)"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return (
            payload.get("type") == "service" and
            "service" in payload.get("roles", []) and
            payload.get("exp", 0) > int(time.time())
        )
    except JWTError as e:
        logger.warning(f"Service token verification failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error verifying service token: {e}")
        return False

class SecurityContext:
    """Security context for request processing"""
    
    def __init__(self, user_data: Dict[str, Any]):
        self.username = user_data.get("username")
        self.roles = user_data.get("roles", [])
        self.token_type = user_data.get("type")
        self.exp = user_data.get("exp")
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role"""
        return role in self.roles
    
    def has_any_role(self, roles: List[str]) -> bool:
        """Check if user has any of the specified roles"""
        return any(role in self.roles for role in roles)
    
    def is_admin(self) -> bool:
        """Check if user is admin"""
        return self.has_role("admin")
    
    def is_operator(self) -> bool:
        """Check if user is operator"""
        return self.has_role("operator")
    
    def is_developer(self) -> bool:
        """Check if user is developer"""
        return self.has_role("developer")
    
    def is_user(self) -> bool:
        """Check if user is regular user"""
        return self.has_role("user")
    
    def is_service(self) -> bool:
        """Check if this is a service token"""
        return self.has_role("service")
    
    def can_access_resource(self, required_roles: List[str]) -> bool:
        """Check if user can access resource requiring specific roles"""
        return self.has_any_role(required_roles)

def get_security_context(user_data: Dict[str, Any]) -> SecurityContext:
    """Create security context from user data"""
    return SecurityContext(user_data)

# Rate limiting utilities
from collections import defaultdict
import asyncio
from datetime import datetime, timedelta

class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self._cleanup_task = None
    
    async def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """Check if request is allowed"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window)
        
        # Clean old requests
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if req_time > window_start
        ]
        
        # Check limit
        if len(self.requests[key]) >= limit:
            return False
        
        # Add current request
        self.requests[key].append(now)
        return True
    
    async def cleanup_old_requests(self):
        """Periodically clean old request records"""
        while True:
            await asyncio.sleep(60)  # Clean every minute
            now = datetime.utcnow()
            window_start = now - timedelta(seconds=3600)  # 1 hour window
            
            for key in list(self.requests.keys()):
                self.requests[key] = [
                    req_time for req_time in self.requests[key]
                    if req_time > window_start
                ]
                
                # Remove empty keys
                if not self.requests[key]:
                    del self.requests[key]

# Global rate limiter instance
rate_limiter = RateLimiter()

async def rate_limit(key: str, limit: int, window: int):
    """Rate limiting decorator"""
    if not await rate_limiter.is_allowed(key, limit, window):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {limit} requests per {window} seconds."
        )

# Security headers
def add_security_headers(response):
    """Add security headers to response"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Add HSTS for HTTPS
    if os.getenv("UNISON_FORCE_HTTPS", "false").lower() == "true":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    
    return response

# CORS configuration
def get_cors_config():
    """Get CORS configuration"""
    allowed_origins = os.getenv("UNISON_CORS_ORIGINS", "http://localhost:3000").split(",")
    allowed_methods = os.getenv("UNISON_CORS_METHODS", "GET,POST,PUT,DELETE,OPTIONS").split(",")
    allowed_headers = os.getenv("UNISON_CORS_HEADERS", "*").split(",")
    
    return {
        "allow_origins": allowed_origins,
        "allow_credentials": True,
        "allow_methods": allowed_methods,
        "allow_headers": allowed_headers,
    }

# Authentication middleware factory
def create_auth_middleware(
    require_auth: bool = True,
    allowed_paths: List[str] = None,
    required_roles: List[str] = None
):
    """Create authentication middleware"""
    
    if allowed_paths is None:
        allowed_paths = ["/health", "/metrics", "/", "/docs", "/openapi.json", "/redoc"]
    
    if required_roles is None:
        required_roles = []
    
    async def auth_middleware(request, call_next):
        # Skip authentication for allowed paths
        if request.url.path in allowed_paths:
            return await call_next(request)
        
        if not require_auth:
            return await call_next(request)
        
        # Get authorization header
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token = auth_header.split(" ")[1]
        
        # Verify token
        token_data = await verify_token_with_auth_service(token)
        if not token_data or not token_data.get("valid"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check roles if required
        if required_roles:
            user_roles = token_data.get("roles", [])
            if not any(role in user_roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: {required_roles}"
                )
        
        # Add user info to request state
        request.state.user = {
            "username": token_data.get("username"),
            "roles": token_data.get("roles", []),
            "token_type": token_data.get("type"),
            "exp": token_data.get("exp")
        }
        
        response = await call_next(request)
        return add_security_headers(response)
    
    return auth_middleware
