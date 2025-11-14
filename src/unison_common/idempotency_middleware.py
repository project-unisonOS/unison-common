"""
FastAPI middleware for idempotency handling

This module provides middleware to automatically handle idempotency keys
in FastAPI applications, preventing duplicate request processing.
"""

import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse
import logging

from .idempotency import (
    IdempotencyManager,
    IdempotencyRecord,
    get_idempotency_manager,
    extract_idempotency_key,
    validate_idempotency_key
)

logger = logging.getLogger(__name__)


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Middleware to handle idempotency for HTTP requests"""
    
    def __init__(self, app, idempotency_manager: Optional[IdempotencyManager] = None,
                 require_key_for_methods: Optional[list] = None,
                 ttl_seconds: Optional[int] = None):
        super().__init__(app)
        self.idempotency_manager = idempotency_manager or get_idempotency_manager()
        self.require_key_for_methods = require_key_for_methods or ['POST', 'PUT', 'PATCH', 'DELETE']
        self.default_ttl_seconds = ttl_seconds or 24 * 60 * 60  # 24 hours
        
        # Endpoints to exclude from idempotency checking
        self.excluded_paths = ['/health', '/metrics', '/docs', '/openapi.json']
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with idempotency handling"""
        
        # Skip idempotency for certain methods and paths
        if (request.method not in self.require_key_for_methods or
            any(request.url.path.startswith(path) for path in self.excluded_paths)):
            return await call_next(request)
        
        # Extract idempotency key from headers
        idempotency_key = extract_idempotency_key(dict(request.headers))
        
        if not idempotency_key:
            # For POST/PUT/PATCH/DELETE, idempotency key is recommended but not required
            if request.method in ['POST', 'PUT', 'PATCH']:
                logger.warning(f"No idempotency key provided for {request.method} {request.url.path}")
                # Continue processing without idempotency
                return await self._process_without_idempotency(request, call_next)
            else:
                return await call_next(request)
        
        # Validate idempotency key format
        if not validate_idempotency_key(idempotency_key):
            raise HTTPException(
                status_code=400,
                detail="Invalid idempotency key format. Must be a valid UUID."
            )
        
        # Get request body for hashing
        request_body = None
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                request_body = await request.json()
            except Exception:
                # If we can't parse JSON, continue without body hashing
                request_body = None
        
        # Get user info from request state (if available from auth)
        user_id = None
        if hasattr(request.state, 'user') and request.state.user:
            user_id = request.state.user.get('username')
        
        # Check if this is a duplicate request
        is_duplicate, existing_record = self.idempotency_manager.check_idempotency(
            idempotency_key=idempotency_key,
            method=request.method,
            url=str(request.url),
            body=request_body,
            user_id=user_id,
            ttl_seconds=self.default_ttl_seconds
        )
        
        if is_duplicate and existing_record:
            # Return the cached response
            logger.info(f"Returning cached response for idempotent request: {idempotency_key}")
            
            # Add idempotency headers to response
            headers = {
                'Idempotency-Key': idempotency_key,
                'Idempotency-Original-Response': str(existing_record.status_code),
                'Idempotency-Created-At': existing_record.created_at.isoformat()
            }
            
            return JSONResponse(
                content=existing_record.response_data,
                status_code=existing_record.status_code,
                headers=headers
            )
        
        # Process the request normally
        return await self._process_with_idempotency(
            request, call_next, idempotency_key, request_body, user_id
        )
    
    async def _process_with_idempotency(self, request: Request, call_next: Callable,
                                       idempotency_key: str, request_body: Optional[Dict[str, Any]],
                                       user_id: Optional[str]) -> Response:
        """Process request and cache the response for idempotency"""
        
        # Record start time
        start_time = time.time()
        
        # Process the request
        response = await call_next(request)
        
        # Only cache successful responses (2xx status codes)
        if 200 <= response.status_code < 300:
            try:
                # Get response data
                response_data = None
                if hasattr(response, 'body'):
                    # For JSONResponse
                    if hasattr(response, 'body'):
                        response_data = response.body
                else:
                    # For other response types, try to get content
                    response_data = {"message": "Request processed successfully"}
                
                # Create idempotency record
                self.idempotency_manager.create_record(
                    idempotency_key=idempotency_key,
                    response_data=response_data,
                    status_code=response.status_code,
                    method=request.method,
                    url=str(request.url),
                    body=request_body,
                    user_id=user_id,
                    ttl_seconds=self.default_ttl_seconds
                )
                
                # Add idempotency headers to response
                response.headers['Idempotency-Key'] = idempotency_key
                response.headers['Idempotency-Created-At'] = datetime.utcnow().isoformat()
                
                processing_time = (time.time() - start_time) * 1000
                logger.info(f"Processed and cached idempotent request: {idempotency_key} in {processing_time:.2f}ms")
                
            except Exception as e:
                logger.error(f"Error creating idempotency record: {e}")
                # Continue without caching if there's an error
                pass
        
        return response
    
    async def _process_without_idempotency(self, request: Request, call_next: Callable) -> Response:
        """Process request without idempotency handling"""
        return await call_next(request)


class IdempotencyKeyRequiredMiddleware(BaseHTTPMiddleware):
    """Middleware that requires idempotency keys for specific endpoints"""
    
    def __init__(self, app, required_paths: Optional[list] = None):
        super().__init__(app)
        self.required_paths = required_paths or ['/ingest']
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Require idempotency key for specific paths"""
        from starlette.responses import JSONResponse
        
        # Check if this path requires an idempotency key
        if request.url.path in self.required_paths:
            idempotency_key = extract_idempotency_key(dict(request.headers))
            
            if not idempotency_key:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Idempotency key required. Provide Idempotency-Key header with a valid UUID v4."},
                )

            if not validate_idempotency_key(idempotency_key):
                return JSONResponse(
                    status_code=400,
                    content={
                        "detail": f"Invalid Idempotency-Key format. Must be a valid UUID v4. Provided: {idempotency_key}"
                    },
                )
        
        return await call_next(request)


def add_idempotency_headers(response: Response, idempotency_key: str, 
                           original_response: int, created_at: str) -> Response:
    """Add idempotency-related headers to a response"""
    response.headers['Idempotency-Key'] = idempotency_key
    response.headers['Idempotency-Original-Response'] = str(original_response)
    response.headers['Idempotency-Created-At'] = created_at
    return response


def create_idempotency_response(idempotency_key: str, response_data: Dict[str, Any],
                               status_code: int = 200) -> JSONResponse:
    """Create a response with idempotency headers"""
    headers = {
        'Idempotency-Key': idempotency_key,
        'Idempotency-Original-Response': str(status_code),
        'Idempotency-Created-At': datetime.utcnow().isoformat()
    }
    
    return JSONResponse(
        content=response_data,
        status_code=status_code,
        headers=headers
    )
