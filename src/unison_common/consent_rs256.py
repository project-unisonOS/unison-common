"""
Local consent grant verification using RS256 and JWKS (P0.2)

This module provides local verification of consent grants without
network calls to the consent service for each request.
"""

import os
import httpx
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from jose import JWTError

from .auth_rs256 import JWKSClient

logger = logging.getLogger(__name__)

# Consent service configuration
CONSENT_HOST = os.getenv("UNISON_CONSENT_HOST", "consent")
CONSENT_PORT = os.getenv("UNISON_CONSENT_PORT", "7072")
CONSENT_JWKS_URL = f"http://{CONSENT_HOST}:{CONSENT_PORT}/jwks.json"
CONSENT_REVOKED_URL = f"http://{CONSENT_HOST}:{CONSENT_PORT}/revoked"


# Consent scope definitions
class ConsentScopes:
    """Standard consent scopes for Unison platform"""
    INGEST_WRITE = "unison.ingest.write"
    REPLAY_READ = "unison.replay.read"
    REPLAY_WRITE = "unison.replay.write"
    REPLAY_DELETE = "unison.replay.delete"
    ADMIN_ALL = "unison.admin.all"


class ConsentVerifier:
    """
    Verifies consent grants locally using JWKS.
    
    Features:
    - Local JWT verification (zero network calls for valid grants)
    - JWKS caching (5 minutes)
    - Revocation list caching (60 seconds)
    - Graceful degradation on service unavailability
    """
    
    def __init__(
        self,
        jwks_url: str = CONSENT_JWKS_URL,
        revoked_url: str = CONSENT_REVOKED_URL,
        jwks_cache_ttl: int = 300,  # 5 minutes
        revoked_cache_ttl: int = 60  # 60 seconds
    ):
        """
        Initialize consent verifier.
        
        Args:
            jwks_url: URL of consent service JWKS endpoint
            revoked_url: URL of revocation list endpoint
            jwks_cache_ttl: JWKS cache TTL in seconds
            revoked_cache_ttl: Revocation list cache TTL in seconds
        """
        self.jwks_client = JWKSClient(jwks_url, jwks_cache_ttl)
        self.revoked_url = revoked_url
        self.revoked_cache_ttl = timedelta(seconds=revoked_cache_ttl)
        
        self._revoked_jtis: Set[str] = set()
        self._revoked_fetched_at: Optional[datetime] = None
    
    def _is_revoked_cache_valid(self) -> bool:
        """Check if revocation list cache is still valid"""
        if self._revoked_fetched_at is None:
            return False
        
        age = now_utc() - self._revoked_fetched_at
        return age < self.revoked_cache_ttl
    
    async def fetch_revoked_list(self, force: bool = False) -> Set[str]:
        """
        Fetch revocation list from consent service.
        
        Args:
            force: Force fetch even if cache is valid
        
        Returns:
            Set of revoked JTIs
        """
        if not force and self._is_revoked_cache_valid():
            logger.debug("Using cached revocation list")
            return self._revoked_jtis
        
        logger.info(f"Fetching revocation list from {self.revoked_url}")
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(self.revoked_url)
                response.raise_for_status()
                
                data = response.json()
                revoked_list = data.get("revoked", [])
                
                # Update cache
                self._revoked_jtis = set(revoked_list)
                self._revoked_fetched_at = now_utc()
                
                logger.info(f"Fetched {len(self._revoked_jtis)} revoked grants")
                return self._revoked_jtis
                
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch revocation list: {e}")
            # Return cached list if available (graceful degradation)
            if self._revoked_jtis:
                logger.warning("Using stale revocation list due to fetch failure")
                return self._revoked_jtis
            # If no cache, return empty set (fail open for availability)
            logger.warning("No revocation list available, allowing all grants")
            return set()
    
    async def verify_grant(
        self,
        token: str,
        required_scopes: List[str],
        check_revocation: bool = True
    ) -> Dict[str, Any]:
        """
        Verify a consent grant token locally.
        
        This is the hot path - zero network calls for valid, non-revoked grants.
        
        Args:
            token: JWT consent grant token
            required_scopes: List of required scopes
            check_revocation: Whether to check revocation list
        
        Returns:
            Dict with grant information
        
        Raises:
            HTTPException: If grant is invalid or missing required scopes
        """
        try:
            # Step 1: Verify JWT signature locally (uses cached JWKS)
            # This is the hot path - no network call if JWKS is cached
            payload = self._verify_jwt_signature(token)
            
            # Step 2: Verify claims
            self._verify_claims(payload)
            
            # Step 3: Check revocation (uses cached list)
            if check_revocation:
                await self._check_revocation(payload)
            
            # Step 4: Check scopes
            self._check_scopes(payload, required_scopes)
            
            logger.debug(f"Consent grant verified for subject: {payload.get('sub')}")
            return payload
            
        except JWTError as e:
            logger.warning(f"Consent grant verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Invalid consent grant: {str(e)}"
            )
    
    def _verify_jwt_signature(self, token: str) -> Dict[str, Any]:
        """Verify JWT signature using JWKS"""
        from jose import jwt
        
        # Get kid from token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        if kid is None:
            raise JWTError("Token missing kid in header")
        
        # Get public key for kid (uses cached JWKS)
        try:
            public_key = self.jwks_client.get_signing_key(kid)
        except ValueError as e:
            raise JWTError(f"Failed to get public key: {e}")
        
        # Verify token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"]
        )
        
        return payload
    
    def _verify_claims(self, payload: Dict[str, Any]):
        """Verify standard JWT claims"""
        # Check expiration
        exp = payload.get("exp")
        if exp is None:
            raise JWTError("Token missing exp claim")
        
        if now_utc().timestamp() > exp:
            raise JWTError("Token has expired")
        
        # Check issuer
        iss = payload.get("iss")
        if iss != "unison-consent":
            raise JWTError(f"Invalid issuer: {iss}")
        
        # Check type
        token_type = payload.get("type")
        if token_type != "consent_grant":
            raise JWTError(f"Invalid token type: {token_type}")
    
    async def _check_revocation(self, payload: Dict[str, Any]):
        """Check if grant is revoked"""
        jti = payload.get("jti")
        if jti is None:
            raise JWTError("Token missing jti claim")
        
        # Fetch revocation list (uses cache)
        revoked_jtis = await self.fetch_revoked_list()
        
        if jti in revoked_jtis:
            raise JWTError("Grant has been revoked")
    
    def _check_scopes(self, payload: Dict[str, Any], required_scopes: List[str]):
        """Check if grant has required scopes"""
        granted_scopes = payload.get("scopes", [])
        
        # Admin scope grants all permissions
        if ConsentScopes.ADMIN_ALL in granted_scopes:
            logger.debug(f"Admin consent grant for subject: {payload.get('sub')}")
            return
        
        # Check each required scope
        missing_scopes = [scope for scope in required_scopes if scope not in granted_scopes]
        if missing_scopes:
            raise JWTError(f"Missing required scopes: {missing_scopes}")


# Global verifier instance
_verifier: Optional[ConsentVerifier] = None


def initialize_consent_verifier(
    jwks_url: Optional[str] = None,
    revoked_url: Optional[str] = None
):
    """
    Initialize the global consent verifier.
    
    Args:
        jwks_url: URL of consent service JWKS endpoint
        revoked_url: URL of revocation list endpoint
    """
    global _verifier
    
    if jwks_url is None:
        jwks_url = CONSENT_JWKS_URL
    if revoked_url is None:
        revoked_url = CONSENT_REVOKED_URL
    
    _verifier = ConsentVerifier(jwks_url, revoked_url)
    logger.info(f"Initialized consent verifier with JWKS URL: {jwks_url}")


def get_consent_verifier() -> ConsentVerifier:
    """Get the global consent verifier instance"""
    if _verifier is None:
        # Auto-initialize with defaults
        initialize_consent_verifier()
    return _verifier


async def verify_consent_grant(
    token: str,
    required_scopes: List[str]
) -> Dict[str, Any]:
    """
    Verify a consent grant token (convenience function).
    
    Args:
        token: JWT consent grant token
        required_scopes: List of required scopes
    
    Returns:
        Dict with grant information
    
    Raises:
        HTTPException: If grant is invalid or missing required scopes
    """
    verifier = get_consent_verifier()
    return await verifier.verify_grant(token, required_scopes)


async def check_consent_header(
    request_headers: Dict[str, str],
    required_scopes: List[str]
) -> Optional[Dict[str, Any]]:
    """
    Check for consent grant in request headers and verify it.
    
    Args:
        request_headers: Request headers dict
        required_scopes: List of required scopes
    
    Returns:
        Grant information if valid, None if no consent header present
    
    Raises:
        HTTPException: If consent header present but invalid
    """
    # Look for X-Consent-Grant header
    consent_token = request_headers.get("x-consent-grant")
    if not consent_token:
        # No consent header - this is optional
        return None
    
    # Verify the consent grant
    return await verify_consent_grant(consent_token, required_scopes)
from .datetime_utils import now_utc
