"""
Unit tests for local consent verification (P0.2)
"""

import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
from jose import jwt, JWTError
import httpx
import uuid

from unison_common.consent_rs256 import (
    ConsentVerifier,
    ConsentScopes,
    initialize_consent_verifier,
    get_consent_verifier,
    verify_consent_grant,
    check_consent_header
)


class TestConsentScopes:
    """Tests for consent scope definitions"""
    
    def test_scope_definitions(self):
        """Test that all required scopes are defined"""
        assert ConsentScopes.INGEST_WRITE == "unison.ingest.write"
        assert ConsentScopes.REPLAY_READ == "unison.replay.read"
        assert ConsentScopes.REPLAY_WRITE == "unison.replay.write"
        assert ConsentScopes.REPLAY_DELETE == "unison.replay.delete"
        assert ConsentScopes.ADMIN_ALL == "unison.admin.all"


class TestConsentVerifier:
    """Tests for consent verifier"""
    
    @pytest.fixture
    def mock_jwks_client(self):
        """Mock JWKS client"""
        client = Mock()
        return client
    
    @pytest.fixture
    def verifier(self, mock_jwks_client):
        """Create consent verifier with mocked JWKS client"""
        verifier = ConsentVerifier(
            "http://consent:7072/jwks.json",
            "http://consent:7072/revoked"
        )
        verifier.jwks_client = mock_jwks_client
        return verifier
    
    @pytest.mark.asyncio
    async def test_fetch_revoked_list(self, verifier):
        """Test fetching revocation list"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "revoked": ["jti-1", "jti-2", "jti-3"],
            "count": 3,
            "cache_ttl": 60
        }
        mock_response.raise_for_status = Mock()
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            revoked = await verifier.fetch_revoked_list()
            
            assert len(revoked) == 3
            assert "jti-1" in revoked
            assert "jti-2" in revoked
            assert "jti-3" in revoked
    
    @pytest.mark.asyncio
    async def test_revoked_list_caching(self, verifier):
        """Test revocation list caching"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "revoked": ["jti-1"],
            "count": 1
        }
        mock_response.raise_for_status = Mock()
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.get = mock_get
            
            # First fetch
            await verifier.fetch_revoked_list()
            assert mock_get.call_count == 1
            
            # Second fetch (should use cache)
            await verifier.fetch_revoked_list()
            assert mock_get.call_count == 1  # Not called again
    
    @pytest.mark.asyncio
    async def test_revoked_list_force_refresh(self, verifier):
        """Test forcing revocation list refresh"""
        mock_response = Mock()
        mock_response.json.return_value = {
            "revoked": ["jti-1"],
            "count": 1
        }
        mock_response.raise_for_status = Mock()
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.get = mock_get
            
            # First fetch
            await verifier.fetch_revoked_list()
            assert mock_get.call_count == 1
            
            # Force refresh
            await verifier.fetch_revoked_list(force=True)
            assert mock_get.call_count == 2
    
    @pytest.mark.asyncio
    async def test_revoked_list_graceful_degradation(self, verifier):
        """Test graceful degradation when revocation list unavailable"""
        # Pre-populate cache
        verifier._revoked_jtis = {"jti-1", "jti-2"}
        verifier._revoked_fetched_at = datetime.utcnow()
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPError("Connection failed")
            )
            
            # Should return cached list
            revoked = await verifier.fetch_revoked_list(force=True)
            assert len(revoked) == 2
            assert "jti-1" in revoked
    
    def test_verify_claims_valid(self, verifier):
        """Test verifying valid JWT claims"""
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write"],
            "purpose": "test",
            "type": "consent_grant"
        }
        
        # Should not raise
        verifier._verify_claims(payload)
    
    def test_verify_claims_expired(self, verifier):
        """Test verifying expired token"""
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int((datetime.utcnow() - timedelta(hours=2)).timestamp()),
            "exp": int((datetime.utcnow() - timedelta(hours=1)).timestamp()),  # Expired
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write"],
            "purpose": "test",
            "type": "consent_grant"
        }
        
        with pytest.raises(JWTError, match="expired"):
            verifier._verify_claims(payload)
    
    def test_verify_claims_invalid_issuer(self, verifier):
        """Test verifying token with invalid issuer"""
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "evil-issuer",  # Wrong issuer
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write"],
            "purpose": "test",
            "type": "consent_grant"
        }
        
        with pytest.raises(JWTError, match="Invalid issuer"):
            verifier._verify_claims(payload)
    
    def test_verify_claims_invalid_type(self, verifier):
        """Test verifying token with invalid type"""
        payload = {
            "sub": "user123",
            "aud": "orchestrator",
            "iss": "unison-consent",
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
            "scopes": ["unison.ingest.write"],
            "purpose": "test",
            "type": "access_token"  # Wrong type
        }
        
        with pytest.raises(JWTError, match="Invalid token type"):
            verifier._verify_claims(payload)
    
    @pytest.mark.asyncio
    async def test_check_revocation_not_revoked(self, verifier):
        """Test checking non-revoked grant"""
        verifier._revoked_jtis = {"jti-1", "jti-2"}
        verifier._revoked_fetched_at = datetime.utcnow()
        
        payload = {
            "jti": "jti-3"  # Not in revoked list
        }
        
        # Should not raise
        await verifier._check_revocation(payload)
    
    @pytest.mark.asyncio
    async def test_check_revocation_is_revoked(self, verifier):
        """Test checking revoked grant"""
        verifier._revoked_jtis = {"jti-1", "jti-2"}
        verifier._revoked_fetched_at = datetime.utcnow()
        
        payload = {
            "jti": "jti-1"  # In revoked list
        }
        
        with pytest.raises(JWTError, match="revoked"):
            await verifier._check_revocation(payload)
    
    def test_check_scopes_valid(self, verifier):
        """Test checking valid scopes"""
        payload = {
            "sub": "user123",
            "scopes": ["unison.ingest.write", "unison.replay.read"]
        }
        
        required_scopes = ["unison.ingest.write"]
        
        # Should not raise
        verifier._check_scopes(payload, required_scopes)
    
    def test_check_scopes_missing(self, verifier):
        """Test checking missing scopes"""
        payload = {
            "sub": "user123",
            "scopes": ["unison.replay.read"]
        }
        
        required_scopes = ["unison.ingest.write", "unison.replay.write"]
        
        with pytest.raises(JWTError, match="Missing required scopes"):
            verifier._check_scopes(payload, required_scopes)
    
    def test_check_scopes_admin_grants_all(self, verifier):
        """Test that admin scope grants all permissions"""
        payload = {
            "sub": "admin-user",
            "scopes": ["unison.admin.all"]
        }
        
        # Admin should have access to any scope
        required_scopes = ["unison.ingest.write", "unison.replay.delete"]
        
        # Should not raise
        verifier._check_scopes(payload, required_scopes)
    
    def test_check_scopes_empty_required(self, verifier):
        """Test checking with no required scopes"""
        payload = {
            "sub": "user123",
            "scopes": ["unison.ingest.write"]
        }
        
        required_scopes = []
        
        # Should not raise
        verifier._check_scopes(payload, required_scopes)


class TestGlobalVerifier:
    """Tests for global verifier functions"""
    
    def test_initialize_consent_verifier(self):
        """Test initializing global consent verifier"""
        initialize_consent_verifier(
            "http://consent:7072/jwks.json",
            "http://consent:7072/revoked"
        )
        
        verifier = get_consent_verifier()
        
        assert verifier is not None
        assert isinstance(verifier, ConsentVerifier)
    
    def test_get_consent_verifier_auto_init(self):
        """Test auto-initialization of global verifier"""
        # Reset global verifier
        import unison_common.consent_rs256 as consent_module
        consent_module._verifier = None
        
        # Should auto-initialize
        verifier = get_consent_verifier()
        
        assert verifier is not None
        assert isinstance(verifier, ConsentVerifier)
    
    @pytest.mark.asyncio
    async def test_check_consent_header_present(self):
        """Test checking consent header when present"""
        headers = {
            "x-consent-grant": "mock.jwt.token"
        }
        
        with patch('unison_common.consent_rs256.verify_consent_grant') as mock_verify:
            mock_verify.return_value = {"sub": "user123", "scopes": ["unison.ingest.write"]}
            
            result = await check_consent_header(headers, ["unison.ingest.write"])
            
            assert result is not None
            assert result["sub"] == "user123"
            mock_verify.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_consent_header_absent(self):
        """Test checking consent header when absent"""
        headers = {}
        
        result = await check_consent_header(headers, ["unison.ingest.write"])
        
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
