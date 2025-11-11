"""
RS256 JWT token verification using JWKS (P0.1)

This module provides utilities for verifying RS256 JWT tokens
by fetching public keys from the auth service's JWKS endpoint.
"""

import logging
import time
from typing import Dict, Optional
from datetime import datetime, timedelta
import httpx
from jose import jwt, JWTError

logger = logging.getLogger(__name__)


class JWKSClient:
    """
    Client for fetching and caching JWKS from auth service.
    """
    
    def __init__(
        self,
        jwks_url: str,
        cache_ttl_seconds: int = 300,  # 5 minutes
        timeout_seconds: int = 5
    ):
        """
        Initialize JWKS client.
        
        Args:
            jwks_url: URL of JWKS endpoint (e.g., http://auth:7070/jwks.json)
            cache_ttl_seconds: How long to cache JWKS (default: 5 minutes)
            timeout_seconds: HTTP request timeout
        """
        self.jwks_url = jwks_url
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.timeout = timeout_seconds
        
        self._jwks: Optional[Dict] = None
        self._jwks_fetched_at: Optional[datetime] = None
        self._keys_by_kid: Dict[str, str] = {}
    
    def _is_cache_valid(self) -> bool:
        """Check if cached JWKS is still valid"""
        if self._jwks is None or self._jwks_fetched_at is None:
            return False
        
        age = datetime.utcnow() - self._jwks_fetched_at
        return age < self.cache_ttl
    
    def fetch_jwks(self, force: bool = False) -> Dict:
        """
        Fetch JWKS from auth service.
        
        Args:
            force: Force fetch even if cache is valid
        
        Returns:
            JWKS dictionary
        """
        if not force and self._is_cache_valid():
            logger.debug("Using cached JWKS")
            return self._jwks
        
        logger.info(f"Fetching JWKS from {self.jwks_url}")
        
        try:
            response = httpx.get(self.jwks_url, timeout=self.timeout)
            response.raise_for_status()
            
            jwks = response.json()
            
            # Cache JWKS
            self._jwks = jwks
            self._jwks_fetched_at = datetime.utcnow()
            
            # Build kid -> key mapping
            self._keys_by_kid = {}
            for key in jwks.get("keys", []):
                kid = key.get("kid")
                if kid:
                    # Convert JWK to PEM format for jose
                    self._keys_by_kid[kid] = key
            
            logger.info(f"Fetched JWKS with {len(self._keys_by_kid)} keys")
            return jwks
            
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            # Return cached JWKS if available
            if self._jwks is not None:
                logger.warning("Using stale cached JWKS due to fetch failure")
                return self._jwks
            raise
    
    def get_public_key(self, kid: str) -> Optional[Dict]:
        """
        Get public key for a specific kid.
        
        Args:
            kid: Key ID
        
        Returns:
            JWK dictionary or None if not found
        """
        # Ensure JWKS is fetched
        if not self._is_cache_valid():
            self.fetch_jwks()
        
        return self._keys_by_kid.get(kid)
    
    def get_signing_key(self, kid: str) -> str:
        """
        Get signing key in PEM format for jose library.
        
        Args:
            kid: Key ID
        
        Returns:
            Public key in PEM format
        """
        jwk = self.get_public_key(kid)
        if jwk is None:
            # Try refreshing JWKS
            self.fetch_jwks(force=True)
            jwk = self.get_public_key(kid)
            
            if jwk is None:
                raise ValueError(f"Key {kid} not found in JWKS")
        
        # Convert JWK to PEM using jose
        from jose.backends.cryptography_backend import CryptographyRSAKey
        
        key = CryptographyRSAKey(jwk, "RS256")
        return key.to_pem().decode('utf-8')


class RS256TokenVerifier:
    """
    Verifies RS256 JWT tokens using JWKS.
    """
    
    def __init__(
        self,
        jwks_url: str,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        cache_ttl_seconds: int = 300
    ):
        """
        Initialize token verifier.
        
        Args:
            jwks_url: URL of JWKS endpoint
            issuer: Expected issuer (iss claim)
            audience: Expected audience (aud claim)
            cache_ttl_seconds: JWKS cache TTL
        """
        self.jwks_client = JWKSClient(jwks_url, cache_ttl_seconds)
        self.issuer = issuer
        self.audience = audience
    
    def verify_token(self, token: str) -> Dict:
        """
        Verify a JWT token.
        
        Args:
            token: JWT token string
        
        Returns:
            Decoded token payload
        
        Raises:
            JWTError: If token is invalid
        """
        # Get kid from token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        if kid is None:
            raise JWTError("Token missing kid in header")
        
        # Get public key for kid
        try:
            public_key = self.jwks_client.get_signing_key(kid)
        except ValueError as e:
            raise JWTError(f"Failed to get public key: {e}")
        
        # Verify token
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "require_exp": True,
            "require_iat": True
        }
        
        # Add issuer/audience verification if configured
        if self.issuer:
            options["verify_iss"] = True
        if self.audience:
            options["verify_aud"] = True
        
        try:
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                options=options
            )
            
            return payload
            
        except JWTError as e:
            logger.warning(f"Token verification failed: {e}")
            raise
    
    def verify_token_safe(self, token: str) -> Optional[Dict]:
        """
        Verify token and return None on failure (safe version).
        
        Args:
            token: JWT token string
        
        Returns:
            Decoded payload or None if invalid
        """
        try:
            return self.verify_token(token)
        except JWTError:
            return None


# Global verifier instance
_verifier: Optional[RS256TokenVerifier] = None


def initialize_verifier(
    jwks_url: str,
    issuer: Optional[str] = None,
    audience: Optional[str] = None
):
    """
    Initialize the global token verifier.
    
    Args:
        jwks_url: URL of JWKS endpoint
        issuer: Expected issuer
        audience: Expected audience
    """
    global _verifier
    _verifier = RS256TokenVerifier(jwks_url, issuer, audience)
    logger.info(f"Initialized RS256 token verifier with JWKS URL: {jwks_url}")


def get_verifier() -> RS256TokenVerifier:
    """Get the global token verifier instance"""
    if _verifier is None:
        raise RuntimeError("Token verifier not initialized. Call initialize_verifier() first.")
    return _verifier


def verify_token(token: str) -> Dict:
    """
    Verify a JWT token using the global verifier.
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded token payload
    
    Raises:
        JWTError: If token is invalid
    """
    return get_verifier().verify_token(token)


def verify_token_safe(token: str) -> Optional[Dict]:
    """
    Verify token and return None on failure (safe version).
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload or None if invalid
    """
    return get_verifier().verify_token_safe(token)
