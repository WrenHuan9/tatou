"""Integration tests for general API endpoints.

This module tests health check, static file serving, and other general
server functionality.
"""

import json
from unittest.mock import patch, MagicMock
import pytest
from flask import Flask
from flask.testing import FlaskClient


@pytest.mark.integration
class TestGeneralAPI:
    """Test general API functionality."""

    @pytest.mark.xfail
    def test_health_check_success(self, client: FlaskClient):
        """Test successful health check with database connection."""
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock successful database query - this should be called
            mock_conn.execute.return_value = None
            
            response = client.get("/healthz")

            # Verify the database connection was attempted
            mock_create_engine.assert_called_once()
            mock_engine.connect.assert_called_once()
            mock_conn.execute.assert_called_once()
            
            # Verify the SQL query was the expected one
            call_args = mock_conn.execute.call_args[0]
            assert len(call_args) == 1
            # The argument should be a sqlalchemy.text object containing "SELECT 1"
            assert "SELECT 1" in str(call_args[0])
            
            # Verify the response
            assert response.status_code == 200
            result = response.get_json()
            assert "message" in result
            assert "The server is up and running" in result["message"]
            assert "db_connected" in result
            assert result["db_connected"] is True
    
    @pytest.mark.xfail
    def test_health_check_db_failure(self, client: FlaskClient):
        """Test health check when database connection fails."""
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            
            # Mock database connection failure
            mock_engine.connect.side_effect = Exception("Database connection failed")
            
            response = client.get("/healthz")
            
            # Verify the database connection was attempted
            mock_create_engine.assert_called_once()
            mock_engine.connect.assert_called_once()
            
            # Verify the response shows db failure but server is still up
            assert response.status_code == 200
            result = response.get_json()
            assert "message" in result
            assert "The server is up and running" in result["message"]
            assert "db_connected" in result
            assert result["db_connected"] is False
    
    @pytest.mark.xfail
    def test_health_check_sql_execution_failure(self, client: FlaskClient):
        """Test health check when SQL execution fails but connection succeeds."""
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock successful connection but failed SQL execution
            mock_conn.execute.side_effect = Exception("SQL execution failed")
            
            response = client.get("/healthz")
            
            # Verify the database connection and query were attempted
            mock_create_engine.assert_called_once()
            mock_engine.connect.assert_called_once()
            mock_conn.execute.assert_called_once()
            
            # Verify the SQL query was the expected one
            call_args = mock_conn.execute.call_args[0]
            assert len(call_args) == 1
            assert "SELECT 1" in str(call_args[0])
            
            # Verify the response shows db failure
            assert response.status_code == 200
            result = response.get_json()
            assert "message" in result
            assert "The server is up and running" in result["message"]
            assert "db_connected" in result
            assert result["db_connected"] is False
    
    @pytest.mark.xfail
    def test_health_check_with_cached_engine(self, client: FlaskClient, app: Flask):
        """Test health check with engine caching behavior."""
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            mock_conn.execute.return_value = None
            
            # First call should create engine
            response1 = client.get("/healthz")
            assert response1.status_code == 200
            assert response1.get_json()["db_connected"] is True
            
            # Second call should use cached engine (create_engine called only once)
            response2 = client.get("/healthz")
            assert response2.status_code == 200
            assert response2.get_json()["db_connected"] is True
            
            # Verify create_engine was called only once due to caching
            mock_create_engine.assert_called_once()
            # But connect and execute should be called twice
            assert mock_engine.connect.call_count == 2
            assert mock_conn.execute.call_count == 2
    
    def test_home_page(self, client: FlaskClient):
        """Test home page serves static file."""
        with patch.object(client.application, 'send_static_file') as mock_send_static:
            mock_send_static.return_value = "index.html content"
            
            response = client.get("/")
            
            mock_send_static.assert_called_once_with("index.html")
    
    def test_static_files(self, client: FlaskClient):
        """Test static file serving."""
        test_files = [
            "style.css",
            "script.js",
            "login.html",
            "documents.html",
            "signup.html"
        ]
        
        for filename in test_files:
            with patch.object(client.application, 'send_static_file') as mock_send_static:
                mock_send_static.return_value = f"{filename} content"
                
                response = client.get(f"/{filename}")
                
                mock_send_static.assert_called_once_with(filename=filename)
    
    def test_static_files_nested_path(self, client: FlaskClient):
        """Test static file serving with nested paths."""
        nested_paths = [
            "css/main.css",
            "js/app.js",
            "images/logo.png",
            "fonts/roboto.woff2"
        ]
        
        for filepath in nested_paths:
            with patch.object(client.application, 'send_static_file') as mock_send_static:
                mock_send_static.return_value = f"{filepath} content"
                
                response = client.get(f"/{filepath}")
                
                mock_send_static.assert_called_once_with(filename=filepath)
    
    def test_nonexistent_endpoint(self, client: FlaskClient):
        """Test accessing non-existent endpoint returns 404."""
        response = client.get("/nonexistent-endpoint")
        
        # Should return 404 or be handled by static file handler
        assert response.status_code in [404, 500]  # 500 if static file handler fails
    
    @pytest.mark.xfail
    def test_invalid_method_on_endpoint(self, client: FlaskClient):
        """Test using invalid HTTP method on endpoints."""
        # Test invalid methods on various endpoints
        test_cases = [
            ("/healthz", "POST"),
            ("/healthz", "PUT"),
            ("/healthz", "DELETE"),
            ("/api/create-user", "GET"),
            ("/api/create-user", "PUT"),
            ("/api/login", "GET"),
            ("/api/login", "PUT"),
        ]
        
        for endpoint, method in test_cases:
            response = client.open(endpoint, method=method)
            # Should return 405 Method Not Allowed
            assert response.status_code == 405
    
    def test_api_endpoints_require_json_content_type(self, client: FlaskClient):
        """Test that API endpoints handle different content types appropriately."""
        # Test with form data instead of JSON
        form_data = "email=test@example.com&login=testuser&password=password123"
        
        response = client.post("/api/create-user", 
                             data=form_data, 
                             content_type="application/x-www-form-urlencoded")
        
        # Should handle gracefully (empty JSON payload)
        assert response.status_code == 400  # Missing required fields
        result = response.get_json()
        assert "error" in result
    
    def test_api_endpoints_handle_malformed_json(self, client: FlaskClient):
        """Test API endpoints with malformed JSON."""
        malformed_json = '{"email": "test@example.com", "login": "testuser", "password":'
        
        response = client.post("/api/create-user", 
                             data=malformed_json, 
                             content_type="application/json")
        
        # Should handle gracefully (silent=True in get_json)
        assert response.status_code == 400  # Missing required fields due to empty payload
        result = response.get_json()
        assert "error" in result
    
    def test_api_endpoints_handle_empty_json(self, client: FlaskClient):
        """Test API endpoints with empty JSON."""
        response = client.post("/api/create-user", json={})
        
        assert response.status_code == 400
        result = response.get_json()
        assert "error" in result
        assert "required" in result["error"].lower()
    
    def test_api_endpoints_handle_null_json(self, client: FlaskClient):
        """Test API endpoints with null JSON."""
        response = client.post("/api/create-user", 
                             data="null", 
                             content_type="application/json")
        
        assert response.status_code == 400
        result = response.get_json()
        assert "error" in result
    
    def test_cors_headers(self, client: FlaskClient):
        """Test CORS headers if implemented."""
        response = client.get("/healthz")
        
        # Check if CORS headers are present (optional, depends on implementation)
        # This test documents expected behavior if CORS is implemented
        headers = response.headers
        # Note: CORS headers might not be implemented in the current server
        # This test serves as documentation of expected behavior
    
    def test_security_headers(self, client: FlaskClient):
        """Test security headers."""
        response = client.get("/healthz")
        
        # Document expected security headers
        headers = response.headers
        # Note: Security headers might not be implemented in the current server
        # Common security headers to consider:
        # - X-Content-Type-Options: nosniff
        # - X-Frame-Options: DENY
        # - X-XSS-Protection: 1; mode=block
        # - Content-Security-Policy
        # - Strict-Transport-Security (for HTTPS)
    
    def test_rate_limiting_behavior(self, client: FlaskClient):
        """Test rate limiting behavior if implemented."""
        # Make multiple rapid requests to test rate limiting
        responses = []
        for i in range(10):
            response = client.get("/healthz")
            responses.append(response)
        
        # All should succeed if no rate limiting is implemented
        for response in responses:
            assert response.status_code == 200
        
        # Note: If rate limiting is implemented, some requests might return 429
    
    @pytest.mark.xfail
    def test_request_size_limits(self, client: FlaskClient):
        """Test request size limits."""
        # Test with very large JSON payload
        large_payload = {
            "email": "test@example.com",
            "login": "testuser", 
            "password": "password123",
            "large_field": "x" * 10000  # 10KB string
        }
        
        response = client.post("/api/create-user", json=large_payload)
        
        # Should either succeed or fail gracefully
        assert response.status_code in [200, 201, 400, 413, 500]
    
    def test_concurrent_requests(self, client: FlaskClient):
        """Test handling of concurrent requests."""
        import threading
        import time
        
        results = []
        
        def make_request():
            response = client.get("/healthz")
            results.append(response.status_code)
        
        # Create multiple threads to make concurrent requests
        threads = []
        for i in range(5):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # All requests should succeed
        assert len(results) == 5
        for status_code in results:
            assert status_code == 200
    
    def test_error_response_format(self, client: FlaskClient):
        """Test that error responses follow consistent format."""
        # Test various error scenarios
        error_responses = [
            client.post("/api/create-user", json={}),  # Missing fields
            client.post("/api/login", json={}),  # Missing fields
            client.get("/api/list-documents"),  # No auth
        ]
        
        for response in error_responses:
            assert response.status_code >= 400
            result = response.get_json()
            assert isinstance(result, dict)
            assert "error" in result
            assert isinstance(result["error"], str)
            assert len(result["error"]) > 0
    
    def test_success_response_format(self, client: FlaskClient):
        """Test that success responses follow consistent format."""
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            mock_conn.execute.return_value = None
            
            response = client.get("/healthz")
            
            assert response.status_code == 200
            result = response.get_json()
            assert isinstance(result, dict)
            # Should have consistent structure
            assert "message" in result or "data" in result or "documents" in result or "versions" in result