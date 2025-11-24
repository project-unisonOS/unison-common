import os
import httpx
import logging
from typing import Dict, Any, List, Optional
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta

FAIL_OPEN = os.getenv("UNISON_CONSENT_FAIL_OPEN", "true").lower() == "true"
"""
Consent grant verification for Unison platform.

M5.2: Scope-based authorization with consent grants.
"""

logger = logging.getLogger(__name__)
security = HTTPBearer()

# Consent service configuration
CONSENT_HOST = os.getenv("UNISON_CONSENT_HOST", "consent")
CONSENT_PORT = os.getenv("UNISON_CONSENT_PORT", "7072")
CONSENT_SECRET = os.getenv("UNISON_CONSENT_SECRET", "consent-secret-key-change-in-production")

# Cache for consent verification (5 minute TTL)
_consent_cache: Dict[str, Dict[str, Any]] = {}
_cache_ttl_seconds = 300  # 5 minutes


# Consent scope definitions
class ConsentScopes:
    """Standard consent scopes for Unison platform"""
    INGEST_WRITE = "unison.ingest.write"
    REPLAY_READ = "unison.replay.read"
    REPLAY_WRITE = "unison.replay.write"
    REPLAY_DELETE = "unison.replay.delete"
    ADMIN_ALL = "unison.admin.all"


async def verify_consent_grant(
    token: str,
    required_scopes: List[str]
) -> Dict[str, Any]:
    """
    Verify a consent grant token and check if it has required scopes.
    
    Args:
        token: JWT consent grant token
        required_scopes: List of required scopes
        
    Returns:
        Dict with grant information
        
    Raises:
        HTTPException: If grant is invalid or missing required scopes
    """
    # Check cache first
    normalized_scopes = sorted(required_scopes)
    cache_key = f"{token}:{':'.join(normalized_scopes)}"
    if cache_key in _consent_cache:
        cached = _consent_cache[cache_key]
        if datetime.now() < cached["expires_at"]:
            logger.debug(f"Consent cache hit for scopes: {required_scopes}")
            return cached["grant"]
        else:
            # Remove expired cache entry
            del _consent_cache[cache_key]
    
    # Call consent service to introspect token
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"http://{CONSENT_HOST}:{CONSENT_PORT}/introspect",
                json={"token": token}
            )
            
            if response.status_code != 200:
                logger.warning(f"Consent introspection failed: {response.status_code}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid or expired consent grant"
                )
            
            grant_data = response.json()
            # If AsyncMock or coroutine slipped through in tests, await it
            if callable(getattr(grant_data, "__await__", None)):
                grant_data = await grant_data  # type: ignore
            
            # Check if grant is active
            if not grant_data.get("active", False):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Consent grant is not active"
                )
            
            # Check if grant has required scopes
            granted_scopes = grant_data.get("scopes", [])
            
            # Admin scope grants all permissions
            if ConsentScopes.ADMIN_ALL in granted_scopes:
                logger.info(f"Admin consent grant verified for subject: {grant_data.get('sub')}")
            else:
                # Check each required scope
                missing_scopes = [scope for scope in required_scopes if scope not in granted_scopes]
                if missing_scopes:
                    logger.warning(
                        f"Missing consent scopes: {missing_scopes}. "
                        f"Required: {required_scopes}, Granted: {granted_scopes}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing required consent scopes: {', '.join(missing_scopes)}"
                    )
            
            # Cache the successful verification
            _consent_cache[cache_key] = {
                "grant": grant_data,
                "expires_at": datetime.now() + timedelta(seconds=_cache_ttl_seconds)
            }
            
            logger.info(
                f"Consent grant verified for subject: {grant_data.get('sub')}, "
                f"scopes: {granted_scopes}"
            )
            
            return grant_data
            
    except httpx.RequestError as e:
        logger.error(f"Failed to connect to consent service: {e}")
        # In strict mode (UNISON_REQUIRE_CONSENT=true), fail closed to avoid bypassing scope checks.
        require_consent_env = os.getenv("UNISON_REQUIRE_CONSENT", "false").lower() == "true"
        if require_consent_env:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Consent verification failed"
            )
        if FAIL_OPEN:
            # Graceful degradation: allow when configured to fail open
            logger.warning("Consent service unavailable - allowing request (fail open)")
            return {
                "active": True,
                "sub": "unknown",
                "scopes": required_scopes,
                "degraded": True
            }
        # Fail closed when configured
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Consent service unavailable"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Consent verification error: {e}")
        # Mirror fail-open behavior unless strict
        require_consent_env = os.getenv("UNISON_REQUIRE_CONSENT", "false").lower() == "true"
        if not require_consent_env and FAIL_OPEN:
            return {
                "active": True,
                "sub": "unknown",
                "scopes": required_scopes,
                "degraded": True
            }
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN if require_consent_env else status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Consent verification failed"
        )


def require_consent(required_scopes: List[str]):
    """
    Dependency decorator to require specific consent scopes.
    
    Usage:
        @app.post("/ingest")
        async def ingest(
            consent: Dict = Depends(require_consent([ConsentScopes.INGEST_WRITE]))
        ):
            ...
    """
    async def consent_checker(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> Dict[str, Any]:
        # Prefer X-Consent-Grant header if provided
        consent_header = request.headers.get("x-consent-grant") or request.headers.get("X-Consent-Grant")
        consent_token: Optional[str] = None
        if consent_header:
            consent_token = consent_header
        elif credentials:
            # Extract consent token from Authorization header
            consent_token = credentials.credentials
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No consent grant provided",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Verify consent grant
        grant_data = await verify_consent_grant(consent_token, required_scopes)

        return grant_data
    
    return consent_checker


async def check_consent_header(
    request_headers: Dict[str, str],
    required_scopes: List[str]
) -> Optional[Dict[str, Any]]:
    """
    Check for consent grant in X-Consent-Grant header.
    
    This is an alternative to requiring consent in Authorization header,
    allowing separate auth and consent tokens.
    
    Args:
        request_headers: Request headers dict
        required_scopes: Required consent scopes
        
    Returns:
        Grant data if valid, None if no consent header present
        
    Raises:
        HTTPException: If consent grant is invalid
    """
    consent_header = request_headers.get("x-consent-grant") or request_headers.get("X-Consent-Grant")
    
    if not consent_header:
        return None
    
    # Verify the consent grant
    grant_data = await verify_consent_grant(consent_header, required_scopes)
    
    return grant_data


def clear_consent_cache():
    """Clear the consent verification cache"""
    _consent_cache.clear()
    logger.info("Consent cache cleared")
