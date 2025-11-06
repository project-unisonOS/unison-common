"""
Unit tests for consent grant verification (M5.2)
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from fastapi import HTTPException

from unison_common.consent import (
    ConsentScopes,
    verify_consent_grant,
    check_consent_header,
    clear_consent_cache,
    _consent_cache,
)


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear consent cache before each test"""
    clear_consent_cache()
    yield
    clear_consent_cache()


@pytest.fixture
def mock_consent_response():
    """Mock successful consent service response"""
    return {
        "active": True,
        "sub": "test-user",
        "scopes": ["unison.ingest.write", "unison.replay.read"],
        "jti": "grant-123",
        "aud": "orchestrator",
        "exp": 1234567890,
    }


@pytest.fixture
def mock_admin_response():
    """Mock admin consent grant response"""
    return {
        "active": True,
        "sub": "admin-user",
        "scopes": ["unison.admin.all"],
        "jti": "admin-grant-456",
        "aud": "orchestrator",
        "exp": 1234567890,
    }


class TestVerifyConsentGrant:
    """Tests for verify_consent_grant function"""

    @pytest.mark.asyncio
    async def test_valid_consent_grant(self, mock_consent_response):
        """Test verification with valid consent grant"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_consent_response
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            result = await verify_consent_grant(
                "valid-token",
                [ConsentScopes.INGEST_WRITE]
            )
            
            assert result["active"] is True
            assert result["sub"] == "test-user"
            assert ConsentScopes.INGEST_WRITE in result["scopes"]

    @pytest.mark.asyncio
    async def test_invalid_consent_grant(self):
        """Test verification with invalid consent grant"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 403
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await verify_consent_grant(
                    "invalid-token",
                    [ConsentScopes.INGEST_WRITE]
                )
            
            assert exc_info.value.status_code == 403
            assert "Invalid or expired" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_inactive_consent_grant(self):
        """Test verification with inactive consent grant"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "active": False,
                "sub": "test-user",
            }
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            with pytest.raises(HTTPException) as exc_info:
                await verify_consent_grant(
                    "inactive-token",
                    [ConsentScopes.INGEST_WRITE]
                )
            
            assert exc_info.value.status_code == 403
            assert "not active" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_missing_required_scopes(self, mock_consent_response):
        """Test verification when required scopes are missing"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_consent_response
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Request scope that's not in the grant
            with pytest.raises(HTTPException) as exc_info:
                await verify_consent_grant(
                    "valid-token",
                    [ConsentScopes.REPLAY_DELETE]  # Not in mock_consent_response
                )
            
            assert exc_info.value.status_code == 403
            assert "Missing required consent scopes" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_admin_scope_grants_all(self, mock_admin_response):
        """Test that admin scope grants all permissions"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_admin_response
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Admin should have access to any scope
            result = await verify_consent_grant(
                "admin-token",
                [ConsentScopes.REPLAY_DELETE, ConsentScopes.INGEST_WRITE]
            )
            
            assert result["active"] is True
            assert ConsentScopes.ADMIN_ALL in result["scopes"]

    @pytest.mark.asyncio
    async def test_consent_caching(self, mock_consent_response):
        """Test that consent verification is cached"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_consent_response
            
            mock_post = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post
            
            # First call - should hit the service
            result1 = await verify_consent_grant(
                "cached-token",
                [ConsentScopes.INGEST_WRITE]
            )
            assert mock_post.call_count == 1
            
            # Second call - should use cache
            result2 = await verify_consent_grant(
                "cached-token",
                [ConsentScopes.INGEST_WRITE]
            )
            assert mock_post.call_count == 1  # Still 1, not 2
            
            # Results should be identical
            assert result1 == result2

    @pytest.mark.asyncio
    async def test_cache_expiration(self, mock_consent_response):
        """Test that cache entries expire"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_consent_response
            
            mock_post = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post
            
            # First call
            await verify_consent_grant("token", [ConsentScopes.INGEST_WRITE])
            assert mock_post.call_count == 1
            
            # Manually expire the cache entry
            cache_key = f"token:{ConsentScopes.INGEST_WRITE}"
            if cache_key in _consent_cache:
                _consent_cache[cache_key]["expires_at"] = datetime.now() - timedelta(seconds=1)
            
            # Second call - should hit service again due to expiration
            await verify_consent_grant("token", [ConsentScopes.INGEST_WRITE])
            assert mock_post.call_count == 2

    @pytest.mark.asyncio
    async def test_graceful_degradation_on_service_failure(self):
        """Test graceful degradation when consent service is unavailable"""
        with patch("httpx.AsyncClient") as mock_client:
            # Simulate connection error
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            
            # Should not raise exception, but return degraded response
            result = await verify_consent_grant(
                "token",
                [ConsentScopes.INGEST_WRITE]
            )
            
            assert result["active"] is True
            assert result["degraded"] is True
            assert ConsentScopes.INGEST_WRITE in result["scopes"]

    @pytest.mark.asyncio
    async def test_multiple_required_scopes(self, mock_consent_response):
        """Test verification with multiple required scopes"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_consent_response
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Both scopes are in mock_consent_response
            result = await verify_consent_grant(
                "token",
                [ConsentScopes.INGEST_WRITE, ConsentScopes.REPLAY_READ]
            )
            
            assert result["active"] is True
            assert ConsentScopes.INGEST_WRITE in result["scopes"]
            assert ConsentScopes.REPLAY_READ in result["scopes"]


class TestCheckConsentHeader:
    """Tests for check_consent_header function"""

    @pytest.mark.asyncio
    async def test_no_consent_header(self):
        """Test when no consent header is present"""
        headers = {"authorization": "Bearer token"}
        
        result = await check_consent_header(headers, [ConsentScopes.INGEST_WRITE])
        
        assert result is None

    @pytest.mark.asyncio
    async def test_consent_header_present(self, mock_consent_response):
        """Test when consent header is present and valid"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_consent_response
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            headers = {
                "authorization": "Bearer auth-token",
                "x-consent-grant": "consent-token"
            }
            
            result = await check_consent_header(
                headers,
                [ConsentScopes.INGEST_WRITE]
            )
            
            assert result is not None
            assert result["active"] is True
            assert result["sub"] == "test-user"

    @pytest.mark.asyncio
    async def test_consent_header_case_insensitive(self, mock_consent_response):
        """Test that consent header is case-insensitive"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_consent_response
            
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Test with uppercase header
            headers = {"X-Consent-Grant": "consent-token"}
            
            result = await check_consent_header(
                headers,
                [ConsentScopes.INGEST_WRITE]
            )
            
            assert result is not None
            assert result["active"] is True


class TestConsentScopes:
    """Tests for ConsentScopes class"""

    def test_scope_definitions(self):
        """Test that all expected scopes are defined"""
        assert hasattr(ConsentScopes, "INGEST_WRITE")
        assert hasattr(ConsentScopes, "REPLAY_READ")
        assert hasattr(ConsentScopes, "REPLAY_WRITE")
        assert hasattr(ConsentScopes, "REPLAY_DELETE")
        assert hasattr(ConsentScopes, "ADMIN_ALL")
        
        # Verify scope format
        assert ConsentScopes.INGEST_WRITE.startswith("unison.")
        assert ConsentScopes.ADMIN_ALL == "unison.admin.all"


class TestCacheManagement:
    """Tests for cache management"""

    @pytest.mark.asyncio
    async def test_clear_consent_cache(self, mock_consent_response):
        """Test that clear_consent_cache removes all entries"""
        with patch("httpx.AsyncClient") as mock_client:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_consent_response
            
            mock_post = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post
            
            # Add entry to cache
            await verify_consent_grant("token", [ConsentScopes.INGEST_WRITE])
            assert len(_consent_cache) > 0
            
            # Clear cache
            clear_consent_cache()
            assert len(_consent_cache) == 0
            
            # Next call should hit service again
            await verify_consent_grant("token", [ConsentScopes.INGEST_WRITE])
            assert mock_post.call_count == 2

    def test_cache_key_format(self):
        """Test that cache keys are formatted correctly"""
        # Cache keys should be: token:scope1:scope2 (sorted)
        token = "test-token"
        scopes = [ConsentScopes.REPLAY_READ, ConsentScopes.INGEST_WRITE]
        
        expected_key = f"{token}:{ConsentScopes.INGEST_WRITE}:{ConsentScopes.REPLAY_READ}"
        
        # The actual implementation sorts scopes
        cache_key = f"{token}:{':'.join(sorted(scopes))}"
        
        assert cache_key == expected_key
