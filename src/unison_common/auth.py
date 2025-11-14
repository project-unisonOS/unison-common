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
ALGORITHM = "RS256"  # RS256 default
AUTH_SERVICE_URL = os.getenv("UNISON_AUTH_SERVICE_URL", "http://auth:8088")
SERVICE_SECRET = os.getenv("UNISON_SERVICE_SECRET", "default-service-secret")
CONSENT_SERVICE_URL = os.getenv("UNISON_CONSENT_SERVICE_URL", "http://consent:7072")
CONSENT_SECRET = os.getenv("UNISON_CONSENT_SECRET", "consent-secret-key")
CONSENT_AUDIENCE = os.getenv("UNISON_CONSENT_AUDIENCE", "orchestrator")

# JWKS configuration for RS256 verification
JWKS_URL = f"{AUTH_SERVICE_URL}/.well-known/jwks.json"
JWKS_CACHE_TTL_SECONDS = int(os.getenv("UNISON_AUTH_JWKS_CACHE_TTL_SECONDS", "300"))
_jwks_cache = {"keys": None, "expires": 0, "etag": None}
EXPECTED_ISSUER = os.getenv("UNISON_AUTH_ISSUER")  # optional hardening
EXPECTED_AUDIENCE = os.getenv("UNISON_AUTH_AUDIENCE")  # optional hardening
JWKS_REFRESH_SECONDS = int(os.getenv("UNISON_AUTH_JWKS_REFRESH_SECONDS", "0"))

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

# P0.1: JWKS functions for RS256 verification
async def get_jwks(force_refresh: bool = False) -> Dict[str, Any]:
    """Get JWKS from auth service with caching and conditional requests."""
    global _jwks_cache

    # Serve from cache unless force_refresh requested or expired
    if not force_refresh and time.time() < _jwks_cache["expires"] and _jwks_cache["keys"]:
        return _jwks_cache["keys"]

    try:
        headers = {}
        if _jwks_cache.get("etag") and not force_refresh:
            headers["If-None-Match"] = _jwks_cache["etag"]

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(JWKS_URL, headers=headers)

        if response.status_code == 304 and _jwks_cache["keys"]:
            # Not modified; extend TTL
            _jwks_cache["expires"] = time.time() + JWKS_CACHE_TTL_SECONDS
            return _jwks_cache["keys"]

        response.raise_for_status()
        jwks = response.json()
        _jwks_cache["keys"] = jwks
        _jwks_cache["expires"] = time.time() + JWKS_CACHE_TTL_SECONDS
        _jwks_cache["etag"] = response.headers.get("etag")
        logger.debug("Fetched JWKS (etag=%s)", _jwks_cache["etag"])
        return jwks

    except httpx.RequestError as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        if _jwks_cache["keys"]:
            # Serve stale cache if available
            logger.warning("Serving stale JWKS from cache due to fetch error")
            return _jwks_cache["keys"]
        raise AuthError("Unable to fetch verification keys")
    except Exception as e:
        logger.error(f"Unexpected error fetching JWKS: {e}")
        if _jwks_cache["keys"]:
            logger.warning("Serving stale JWKS from cache due to unexpected error")
            return _jwks_cache["keys"]
        raise AuthError("Unable to fetch verification keys")

# Optional background JWKS refresher
_jwks_refresh_thread = None
_jwks_refresh_stop = False

def _jwks_refresher():
    import time as _time
    import asyncio as _asyncio
    while not _jwks_refresh_stop:
        try:
            # Run async get_jwks in a new loop per tick
            _asyncio.run(get_jwks())
        except Exception:
            pass
        # Sleep refresh interval, or default to cache TTL if set shorter
        interval = JWKS_REFRESH_SECONDS if JWKS_REFRESH_SECONDS > 0 else 300
        _time.sleep(interval)

def start_jwks_background_refresh():
    global _jwks_refresh_thread
    if JWKS_REFRESH_SECONDS <= 0:
        return
    if _jwks_refresh_thread and _jwks_refresh_thread.is_alive():
        return
    import threading
    _jwks_refresh_thread = threading.Thread(target=_jwks_refresher, daemon=True)
    _jwks_refresh_thread.start()

def find_public_key(kid: str, jwks: Dict[str, Any]) -> Optional[str]:
    """Find public key by key ID in JWKS"""
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None

def construct_rsa_public_key(jwk_key: Dict[str, Any]) -> str:
    """Construct RSA public key from JWK format"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import base64
    
    def base64url_decode(input_str):
        # Add padding if needed
        padding = len(input_str) % 4
        if padding:
            input_str += '=' * (4 - padding)
        return base64.urlsafe_b64decode(input_str)
    
    try:
        # Extract modulus and exponent
        n = int.from_bytes(base64url_decode(jwk_key["n"]), byteorder='big')
        e = int.from_bytes(base64url_decode(jwk_key["e"]), byteorder='big')
        
        # Create RSA public key
        public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        
        # Convert to PEM format
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return pem.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Failed to construct RSA public key: {e}")
        raise AuthError("Invalid public key format")

async def verify_rs256_token_locally(token: str) -> Dict[str, Any]:
    """Verify RS256 JWT locally using JWKS"""
    try:
        # Get unverified header to find key ID
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        if not kid:
            raise JWTError("Token missing key ID (kid)")
        
        # Get JWKS and find the public key
        jwks = await get_jwks()
        jwk_key = find_public_key(kid, jwks)
        
        if not jwk_key:
            # Force refresh JWKS once in case of rotation, then try again
            jwks = await get_jwks(force_refresh=True)
            jwk_key = find_public_key(kid, jwks)
            if not jwk_key:
                raise JWTError(f"Unknown key ID: {kid}")
        
        # Construct public key
        public_key_pem = construct_rsa_public_key(jwk_key)
        
        # Verify token
        decode_kwargs = {"algorithms": [ALGORITHM]}
        if EXPECTED_ISSUER:
            decode_kwargs["issuer"] = EXPECTED_ISSUER
        if EXPECTED_AUDIENCE:
            decode_kwargs["audience"] = EXPECTED_AUDIENCE

        payload = jwt.decode(token, public_key_pem, **decode_kwargs)
        
        return payload
        
    except JWTError as e:
        logger.warning(f"RS256 token verification failed: {e}")
        raise AuthError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error verifying token: {e}")
        raise AuthError("Token verification failed")

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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    try:
        # P0.1: Try local RS256 verification first (faster, no network call)
        payload = await verify_rs256_token_locally(credentials.credentials)
        
        # Validate required claims
        if not payload.get("sub"):
            raise AuthError("Token missing subject claim")
        
        return {
            "username": payload.get("sub"),
            "roles": payload.get("roles", []),
            "token_type": payload.get("type"),
            "exp": payload.get("exp")
        }
        
    except AuthError:
        # Fallback to auth service verification for compatibility
        logger.debug("Local verification failed, trying auth service fallback")
        token_data = await verify_token_with_auth_service(credentials.credentials)
        
        if not token_data or not token_data.get("valid"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired authentication token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
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
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {required_roles}"
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
    # P0.1: Service tokens should be created by auth service
    # This function is deprecated - use auth service /token endpoint instead
    logger.warning("create_service_token is deprecated - use auth service /token endpoint")
    
    if service_secret is None:
        service_secret = SERVICE_SECRET
    
    # Fallback to HS256 for backward compatibility during migration
    payload = {
        "sub": f"service-{service_name}",
        "type": "service",
        "roles": ["service"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour
        "jti": f"service_{int(time.time())}_{service_name}"
    }
    
    try:
        # Use HS256 for legacy service tokens during migration
        return jwt.encode(payload, service_secret, algorithm="HS256")
    except Exception as e:
        logger.error(f"Failed to create service token: {e}")
        raise AuthError("Failed to create service token")

def verify_service_token_locally(token: str) -> bool:
    """Verify service token locally (for when auth service is unavailable)"""
    try:
        # P0.1: Try RS256 verification first
        try:
            unverified_header = jwt.get_unverified_header(token)
            if unverified_header.get("kid"):
                # RS256 token - we can't verify async here, return False to trigger service verification
                # This maintains backward compatibility
                return False
        except:
            pass
        
        # Fallback to HS256 for legacy tokens
        payload = jwt.decode(token, SERVICE_SECRET, algorithms=["HS256"])
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
        now = now_utc()
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
            now = now_utc()
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


# Consent Grant Verification Functions

def verify_consent_grant_locally(grant_token: str) -> Dict[str, Any]:
    """Verify a consent grant JWT locally without network calls"""
    try:
        # P0.1: Try RS256 verification first for consent grants
        try:
            unverified_header = jwt.get_unverified_header(grant_token)
            if unverified_header.get("kid"):
                # RS256 token - we can't verify async here, raise to trigger service verification
                raise JWTError("RS256 consent grants require async verification")
        except JWTError:
            # Re-raise JWT errors from RS256 check
            raise
        except:
            pass
        
        # Fallback to HS256 for legacy tokens
        payload = jwt.decode(
            grant_token,
            CONSENT_SECRET,
            algorithms=["HS256"],
            audience=CONSENT_AUDIENCE,
            issuer="unison-consent"
        )
        
        # Validate required claims
        required_claims = ["sub", "aud", "iss", "iat", "exp", "jti", "scopes", "purpose", "type"]
        for claim in required_claims:
            if claim not in payload:
                raise JWTError(f"Missing required claim: {claim}")
        
        # Validate grant type
        if payload.get("type") != "consent_grant":
            raise JWTError("Invalid token type: expected consent_grant")
        
        # Check expiration
        if time.time() > payload.get("exp", 0):
            raise JWTError("Grant has expired")
        
        return payload
        
    except JWTError as e:
        logger.error(f"Consent grant verification failed: {e}")
        raise AuthError(f"Invalid consent grant: {str(e)}")

async def verify_consent_grant_with_service(grant_token: str) -> Optional[Dict[str, Any]]:
    """Verify a consent grant with the consent service (fallback)"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{CONSENT_SERVICE_URL}/introspect",
                json={"token": grant_token}
            )
            
        if response.status_code == 200:
            result = response.json()
            if result.get("active"):
                return result
        return None
        
    except httpx.RequestError as e:
        logger.error(f"Consent service unavailable: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during grant verification: {e}")
        return None

async def verify_consent_grant(grant_token: str, use_local_first: bool = True) -> Dict[str, Any]:
    """Verify a consent grant, trying local verification first, then service fallback"""
    if use_local_first:
        try:
            # Try local verification first (fast, no network call)
            return verify_consent_grant_locally(grant_token)
        except AuthError:
            # Fall back to service verification
            logger.info("Local verification failed, trying consent service")
            result = await verify_consent_grant_with_service(grant_token)
            if not result:
                raise AuthError("Consent grant verification failed")
            return result
    else:
        # Only use service verification
        result = await verify_consent_grant_with_service(grant_token)
        if not result:
            raise AuthError("Consent grant verification failed")
        return result

def check_grant_scope(grant_payload: Dict[str, Any], required_scope: str) -> bool:
    """Check if a grant includes the required scope"""
    scopes = grant_payload.get("scopes", [])
    return required_scope in scopes

def check_grant_purpose(grant_payload: Dict[str, Any], allowed_purposes: List[str]) -> bool:
    """Check if a grant's purpose is in the allowed list"""
    purpose = grant_payload.get("purpose", "")
    return purpose in allowed_purposes

async def require_consent_grant(
    required_scope: str,
    allowed_purposes: List[str] = None,
    grant_token: str = None
) -> Dict[str, Any]:
    """
    Dependency function to require a valid consent grant with specific scope
    
    Args:
        required_scope: The scope required for this operation
        allowed_purposes: List of allowed purposes (optional)
        grant_token: The grant token (if None, will look for Authorization header)
    
    Returns:
        The verified grant payload
    
    Raises:
        AuthError: If grant is invalid or missing required scope
    """
    if not grant_token:
        raise AuthError("No consent grant provided")
    
    # Verify the grant
    grant_payload = await verify_consent_grant(grant_token)
    
    # Check required scope
    if not check_grant_scope(grant_payload, required_scope):
        raise AuthError(f"Consent grant does not include required scope: {required_scope}")
    
    # Check purpose if restrictions apply
    if allowed_purposes and not check_grant_purpose(grant_payload, allowed_purposes):
        raise AuthError(f"Consent grant purpose not allowed: {grant_payload.get('purpose')}")
    
    return grant_payload
from .datetime_utils import now_utc
