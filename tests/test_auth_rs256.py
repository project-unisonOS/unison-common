"""
Unit tests for RS256 token verification (P0.1)
"""

import pytest
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from jose import jwt, JWTError
import httpx

from unison_common.auth_rs256 import (
    JWKSClient,
    RS256TokenVerifier,
    initialize_verifier,
    get_verifier,
    verify_token,
    verify_token_safe
)


class TestJWKSClient:
    """Tests for JWKS client"""
    
    @pytest.fixture
    def mock_jwks(self):
        """Mock JWKS response"""
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "test-key-1",
                    "alg": "RS256",
                    "n": "xGOr-H7A-PWh8D4FqXxX6E4Qs0Xm9c8VvXxX6E4Qs0Xm9c8V",
                    "e": "AQAB"
                },
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "test-key-2",
                    "alg": "RS256",
                    "n": "yHPs-I8B-QXi9E5GrYyY7F5Rt1Yn0d9WwYyY7F5Rt1Yn0d9W",
                    "e": "AQAB"
                }
            ]
        }
    
    @pytest.fixture
    def jwks_client(self):
        """Create JWKS client"""
        return JWKSClient("http://auth:7070/jwks.json", cache_ttl_seconds=300)
    
    def test_init(self, jwks_client):
        """Test JWKS client initialization"""
        assert jwks_client.jwks_url == "http://auth:7070/jwks.json"
        assert jwks_client._jwks is None
        assert jwks_client._jwks_fetched_at is None
    
    @patch('httpx.get')
    def test_fetch_jwks(self, mock_get, jwks_client, mock_jwks):
        """Test fetching JWKS"""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        jwks = jwks_client.fetch_jwks()
        
        assert jwks == mock_jwks
        assert len(jwks_client._keys_by_kid) == 2
        assert "test-key-1" in jwks_client._keys_by_kid
        assert "test-key-2" in jwks_client._keys_by_kid
    
    @patch('httpx.get')
    def test_fetch_jwks_caching(self, mock_get, jwks_client, mock_jwks):
        """Test JWKS caching"""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        # First fetch
        jwks_client.fetch_jwks()
        assert mock_get.call_count == 1
        
        # Second fetch (should use cache)
        jwks_client.fetch_jwks()
        assert mock_get.call_count == 1  # Not called again
    
    @patch('httpx.get')
    def test_fetch_jwks_force_refresh(self, mock_get, jwks_client, mock_jwks):
        """Test forcing JWKS refresh"""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        # First fetch
        jwks_client.fetch_jwks()
        assert mock_get.call_count == 1
        
        # Force refresh
        jwks_client.fetch_jwks(force=True)
        assert mock_get.call_count == 2
    
    @patch('httpx.get')
    def test_fetch_jwks_http_error(self, mock_get, jwks_client):
        """Test JWKS fetch with HTTP error"""
        mock_get.side_effect = httpx.HTTPError("Connection failed")
        
        with pytest.raises(httpx.HTTPError):
            jwks_client.fetch_jwks()
    
    @patch('httpx.get')
    def test_fetch_jwks_fallback_to_cache(self, mock_get, jwks_client, mock_jwks):
        """Test falling back to cached JWKS on error"""
        # First successful fetch
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        jwks_client.fetch_jwks()
        
        # Second fetch fails, should return cached
        mock_get.side_effect = httpx.HTTPError("Connection failed")
        
        jwks = jwks_client.fetch_jwks(force=True)
        assert jwks == mock_jwks  # Returns cached version
    
    @patch('httpx.get')
    def test_get_public_key(self, mock_get, jwks_client, mock_jwks):
        """Test getting a specific public key"""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        jwks_client.fetch_jwks()
        
        key = jwks_client.get_public_key("test-key-1")
        
        assert key is not None
        assert key["kid"] == "test-key-1"
        assert key["alg"] == "RS256"
    
    @patch('httpx.get')
    def test_get_public_key_not_found(self, mock_get, jwks_client, mock_jwks):
        """Test getting a non-existent key"""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        jwks_client.fetch_jwks()
        
        key = jwks_client.get_public_key("non-existent-key")
        
        assert key is None
    
    @patch('httpx.get')
    def test_cache_expiration(self, mock_get, jwks_client, mock_jwks):
        """Test cache expiration"""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        # Set very short TTL
        jwks_client.cache_ttl = timedelta(seconds=0.1)
        
        # First fetch
        jwks_client.fetch_jwks()
        assert mock_get.call_count == 1
        
        # Wait for cache to expire
        time.sleep(0.2)
        
        # Should fetch again
        jwks_client.fetch_jwks()
        assert mock_get.call_count == 2


class TestRS256TokenVerifier:
    """Tests for RS256 token verifier"""
    
    @pytest.fixture
    def mock_jwks_client(self):
        """Mock JWKS client"""
        client = Mock(spec=JWKSClient)
        return client
    
    @pytest.fixture
    def verifier(self, mock_jwks_client):
        """Create token verifier with mocked JWKS client"""
        verifier = RS256TokenVerifier("http://auth:7070/jwks.json")
        verifier.jwks_client = mock_jwks_client
        return verifier
    
    def test_init(self):
        """Test verifier initialization"""
        verifier = RS256TokenVerifier(
            "http://auth:7070/jwks.json",
            issuer="unison-auth",
            audience="unison-api"
        )
        
        assert verifier.issuer == "unison-auth"
        assert verifier.audience == "unison-api"
    
    def test_verify_token_missing_kid(self, verifier):
        """Test verifying token without kid"""
        # Create token without kid
        token = jwt.encode(
            {"sub": "user123"},
            "secret",
            algorithm="HS256"
        )
        
        with pytest.raises(JWTError, match="Token missing kid"):
            verifier.verify_token(token)
    
    @patch('jose.jwt.decode')
    @patch('jose.jwt.get_unverified_header')
    def test_verify_token_success(self, mock_header, mock_decode, verifier, mock_jwks_client):
        """Test successful token verification"""
        mock_header.return_value = {"kid": "test-key", "alg": "RS256"}
        mock_jwks_client.get_signing_key.return_value = "mock-public-key"
        mock_decode.return_value = {
            "sub": "user123",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.utcnow().timestamp())
        }
        
        token = "mock.jwt.token"
        payload = verifier.verify_token(token)
        
        assert payload["sub"] == "user123"
        mock_jwks_client.get_signing_key.assert_called_once_with("test-key")
    
    @patch('jose.jwt.get_unverified_header')
    def test_verify_token_key_not_found(self, mock_header, verifier, mock_jwks_client):
        """Test verifying token with unknown kid"""
        mock_header.return_value = {"kid": "unknown-key", "alg": "RS256"}
        mock_jwks_client.get_signing_key.side_effect = ValueError("Key not found")
        
        token = "mock.jwt.token"
        
        with pytest.raises(JWTError, match="Failed to get public key"):
            verifier.verify_token(token)
    
    def test_verify_token_safe_success(self, verifier, mock_jwks_client):
        """Test safe token verification (success)"""
        with patch.object(verifier, 'verify_token') as mock_verify:
            mock_verify.return_value = {"sub": "user123"}
            
            payload = verifier.verify_token_safe("mock.jwt.token")
            
            assert payload == {"sub": "user123"}
    
    def test_verify_token_safe_failure(self, verifier, mock_jwks_client):
        """Test safe token verification (failure)"""
        with patch.object(verifier, 'verify_token') as mock_verify:
            mock_verify.side_effect = JWTError("Invalid token")
            
            payload = verifier.verify_token_safe("mock.jwt.token")
            
            assert payload is None


class TestGlobalVerifier:
    """Tests for global verifier functions"""
    
    def test_initialize_verifier(self):
        """Test initializing global verifier"""
        initialize_verifier(
            "http://auth:7070/jwks.json",
            issuer="unison-auth",
            audience="unison-api"
        )
        
        verifier = get_verifier()
        
        assert verifier is not None
        assert verifier.issuer == "unison-auth"
        assert verifier.audience == "unison-api"
    
    def test_get_verifier_not_initialized(self):
        """Test getting verifier before initialization"""
        # Reset global verifier
        import unison_common.auth_rs256 as auth_module
        auth_module._verifier = None
        
        with pytest.raises(RuntimeError, match="not initialized"):
            get_verifier()
    
    def test_verify_token_global(self):
        """Test global verify_token function"""
        initialize_verifier("http://auth:7070/jwks.json")
        
        with patch.object(get_verifier(), 'verify_token') as mock_verify:
            mock_verify.return_value = {"sub": "user123"}
            
            payload = verify_token("mock.jwt.token")
            
            assert payload == {"sub": "user123"}
    
    def test_verify_token_safe_global(self):
        """Test global verify_token_safe function"""
        initialize_verifier("http://auth:7070/jwks.json")
        
        with patch.object(get_verifier(), 'verify_token_safe') as mock_verify:
            mock_verify.return_value = {"sub": "user123"}
            
            payload = verify_token_safe("mock.jwt.token")
            
            assert payload == {"sub": "user123"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
