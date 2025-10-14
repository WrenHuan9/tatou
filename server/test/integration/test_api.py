"""Integration tests for general API endpoints.

This module tests health check, static file serving, and other general
server functionality.
"""

import json
import io
from unittest.mock import patch, MagicMock
import pytest
from flask import Flask
from flask.testing import FlaskClient


@pytest.mark.integration
class TestGeneralAPI:
    """Test general API functionality."""

    def test_health_check_success(self, client: FlaskClient, app):
        """Test successful health check with database connection."""
        mock_engine = app.config['mock_db_engine']
        mock_conn = app.config['mock_db_conn']

        mock_engine.reset_mock()
        mock_conn.reset_mock()

        # Mock successful database query
        mock_conn.execute.return_value = None

        response = client.get("/healthz")

        # Verify the database connection was attempted
        mock_engine.connect.assert_called_once()
        mock_conn.execute.assert_called_once()

        # Verify the SQL query was the expected one
        call_args = mock_conn.execute.call_args[0]
        assert len(call_args) == 1
        assert "SELECT 1" in str(call_args[0])

        # Verify the response
        assert response.status_code == 200
        result = response.get_json()
        assert "message" in result
        assert "The server is up and running" in result["message"]
        assert "db_connected" in result
        assert result["db_connected"] is True

    def test_health_check_db_failure(self, client: FlaskClient, app):
        """Test health check when database connection fails."""
        mock_engine = app.config['mock_db_engine']

        mock_engine.reset_mock()

        # Mock database connection failure
        mock_engine.connect.side_effect = Exception("Database connection failed")

        response = client.get("/healthz")

        # Verify the database connection was attempted
        mock_engine.connect.assert_called_once()

        # Verify the response shows db failure but server is still up
        assert response.status_code == 200
        result = response.get_json()
        assert "message" in result
        assert "The server is up and running" in result["message"]
        assert "db_connected" in result
        assert result["db_connected"] is False

        mock_engine.connect.side_effect = None

    def test_health_check_sql_execution_failure(self, client: FlaskClient, app):
        """Test health check when SQL execution fails but connection succeeds."""
        mock_engine = app.config['mock_db_engine']
        mock_conn = app.config['mock_db_conn']

        mock_engine.reset_mock()
        mock_conn.reset_mock()

        # Mock successful connection but failed SQL execution
        mock_conn.execute.side_effect = Exception("SQL execution failed")

        response = client.get("/healthz")

        # Verify the database connection and query were attempted
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

        mock_conn.execute.side_effect = None

    def test_health_check_with_cached_engine(self, client: FlaskClient, app: Flask):
        """Test health check with engine caching behavior."""
        with patch('server.src.server.create_engine') as mock_create_engine:
            app.config['_ENGINE'] = None

            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine

            mock_context = MagicMock()
            mock_context.__enter__ = MagicMock(return_value=mock_conn)
            mock_context.__exit__ = MagicMock(return_value=False)
            mock_engine.connect.return_value = mock_context

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
                
                response = client.get(f"/static/{filename}")
                
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
                
                response = client.get(f"/static/{filepath}")
                
                mock_send_static.assert_called_once_with(filename=filepath)
    
    def test_nonexistent_endpoint(self, client: FlaskClient):
        """Test accessing non-existent endpoint returns 404."""
        response = client.get("/nonexistent-endpoint")
        
        # Should return 404 or be handled by static file handler
        assert response.status_code in [404, 500]  # 500 if static file handler fails
    

    def test_invalid_method_on_endpoint(self, client: FlaskClient):
        """Test using invalid HTTP method on endpoints."""
        # Test invalid methods on various endpoints
        test_cases = [
            ("/healthz", "POST", 405),  # healthz only accepts GET, should return 405
            ("/healthz", "PUT", 405),
            ("/healthz", "DELETE", 405),
            ("/api/create-user", "GET", 404),  # GET caught by catch-all route, return 404
            ("/api/create-user", "PUT", 405),  # PUT properly handled by Flask, return 405
            ("/api/login", "GET", 404),  # GET caught by catch-all route, return 404
            ("/api/login", "PUT", 405),  # PUT properly handled by Flask, return 405
        ]
        
        for endpoint, method, expected_status in test_cases:
            response = client.open(endpoint, method=method)
            # Should return expected status code
            assert response.status_code == expected_status
    
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

    def test_rmap_initialization_failure(self, client: FlaskClient, app: Flask):
        """Test RMAP service initialization failure."""
        from unittest.mock import patch

        # Mock RMAP modules to be None to trigger the else branch
        with patch('server.src.server.IdentityManager', None), \
                patch('server.src.server.RMAP', None):
            # Create a new app instance to test initialization
            from server.src.server import create_app
            test_app = create_app()

            # Verify that RMAP service is None and config is set accordingly
            assert test_app.config.get("IDENTITY_MANAGER") is None
            assert test_app.config.get("RMAP_SERVICE") is None

    def test_static_file_404_error(self, client: FlaskClient):
        """Test static file serving 404 error."""
        from werkzeug.exceptions import NotFound
        
        with patch.object(client.application, 'send_static_file') as mock_send_static:
            # Mock send_static_file to raise NotFound exception
            mock_send_static.side_effect = NotFound()
            
            response = client.get("/static/nonexistent-file.css")
            
            assert response.status_code == 404
            result = response.get_json()
            assert "error" in result
            assert "Not Found" in result["error"]


@pytest.mark.integration
class TestRMAPFlows:
    """Cover RMAP main branches and leak identification endpoints."""

    def _set_rmap_mocks(self, monkeypatch, decrypt_result=None, nonces=None,
                         handle1=None, handle2=None):
        from server.src import server as srv
        # Mock identity_manager.decrypt_for_server
        identity = MagicMock()
        if isinstance(decrypt_result, Exception):
            identity.decrypt_for_server.side_effect = decrypt_result
        else:
            identity.decrypt_for_server.return_value = decrypt_result or {}
        monkeypatch.setattr(srv, "identity_manager", identity, raising=True)

        # Mock rmap_service with nonces and helpers
        rmap = MagicMock()
        rmap.nonces = nonces or {}
        rmap._find_identity_by_nonce_server.side_effect = lambda x: next(iter((nonces or {None: None}).keys()), None)
        if handle1 is not None:
            rmap.handle_message1.return_value = handle1
        if handle2 is not None:
            rmap.handle_message2.return_value = handle2
        monkeypatch.setattr(srv, "rmap_service", rmap, raising=True)
        return identity, rmap

    def test_rmap_initiate_error_response(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1275-1276: handle_message1 returns error
        _, rmap = self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"identity": "alice@example.com"},
            nonces={"alice@example.com": True},
            handle1={"error": "bad request"}
        )
        resp = client.post("/api/rmap-initiate", json={"payload": "x"})
        assert resp.status_code == 400

    def test_rmap_get_link_invalid_session(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1296-1299: invalid session or nonce mismatch
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={}  # empty
        )
        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 401

    def test_rmap_get_link_no_source_document(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1217-1256 via rmap_get_link -> get_rmap_source_document raises
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={"alice@example.com": True}
        )

        # Mock DB for get_rmap_source_document: fetchall() -> []
        mock_conn = app.config['mock_db_conn']
        empty_result = MagicMock()
        empty_result.fetchall.return_value = []
        mock_conn.execute.return_value = empty_result

        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 503

    def test_rmap_get_link_versions_db_error(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1323-1325 database error when querying Versions
        from pathlib import Path
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={"alice@example.com": True}
        )
        # Make get_rmap_source_document succeed (one row and file exists)
        mock_conn = app.config['mock_db_conn']
        one_row_result = MagicMock()
        one_row = MagicMock()
        one_row.id = 1
        one_row.path = str(Path(app.config["STORAGE_DIR"]) / "sample.pdf")
        Path(one_row.path).write_bytes(b"%PDF-1.4\n%%EOF")
        one_row_result.fetchall.return_value = [one_row]
        # First execute (source doc) -> fetchall; then raise on Versions query
        mock_conn.execute.side_effect = [one_row_result, Exception("db error")]

        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 503

    def test_rmap_get_link_message2_error(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1329-1333: handle_message2 returns error
        from pathlib import Path
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={"alice@example.com": True},
            handle2={"error": "oops"}
        )
        mock_conn = app.config['mock_db_conn']
        # Source doc ok
        one_row_result = MagicMock()
        one_row = MagicMock(id=1, path=str(Path(app.config["STORAGE_DIR"]) / "src.pdf"))
        Path(one_row.path).write_bytes(b"%PDF-1.4\n%%EOF")
        one_row_result.fetchall.return_value = [one_row]

        # Versions SELECT returns .first() -> None
        versions_result = MagicMock()
        versions_result.first.return_value = None
        mock_conn.execute.side_effect = [one_row_result, versions_result]

        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 400

    def test_rmap_get_link_watermark_empty_output(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1346-1348: apply_watermark returns empty/invalid
        from pathlib import Path
        from server.src import server as srv
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={"alice@example.com": True},
            handle2={"result": "secret-link"}
        )
        mock_conn = app.config['mock_db_conn']
        one_row_result = MagicMock()
        src = MagicMock(id=1, path=str(Path(app.config["STORAGE_DIR"]) / "src2.pdf"))
        Path(src.path).write_bytes(b"%PDF-1.4\n%%EOF")
        one_row_result.fetchall.return_value = [src]
        versions_result = MagicMock(); versions_result.first.return_value = None
        mock_conn.execute.side_effect = [one_row_result, versions_result]
        # Patch apply_watermark to return empty bytes
        monkeypatch.setattr(srv.WMUtils, "apply_watermark", lambda **kw: b"", raising=True)

        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 500

    def test_rmap_get_link_watermark_exception(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1349-1353: apply_watermark raises
        from pathlib import Path
        from server.src import server as srv
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={"alice@example.com": True},
            handle2={"result": "secret-link"}
        )
        mock_conn = app.config['mock_db_conn']
        one_row_result = MagicMock(); one_row = MagicMock(id=1, path=str(Path(app.config["STORAGE_DIR"]) / "src3.pdf"))
        Path(one_row.path).write_bytes(b"%PDF-1.4\n%%EOF")
        one_row_result.fetchall.return_value = [one_row]
        versions_result = MagicMock(); versions_result.first.return_value = None
        mock_conn.execute.side_effect = [one_row_result, versions_result]
        monkeypatch.setattr(srv.WMUtils, "apply_watermark", MagicMock(side_effect=Exception("wm err")), raising=True)

        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 500

    def test_rmap_get_link_save_file_failure(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1363-1367: saving bytes fails
        from pathlib import Path
        from server.src import server as srv
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={"alice@example.com": True},
            handle2={"result": "secret-link"}
        )
        mock_conn = app.config['mock_db_conn']
        one_row_result = MagicMock(); one_row = MagicMock(id=1, path=str(Path(app.config["STORAGE_DIR"]) / "src4.pdf"))
        Path(one_row.path).write_bytes(b"%PDF-1.4\n%%EOF")
        one_row_result.fetchall.return_value = [one_row]
        versions_result = MagicMock(); versions_result.first.return_value = None
        mock_conn.execute.side_effect = [one_row_result, versions_result]
        monkeypatch.setattr(srv.WMUtils, "apply_watermark", MagicMock(return_value=b"pdf-bytes"), raising=True)
        # Make Path.open raise
        monkeypatch.setattr("pathlib.Path.open", MagicMock(side_effect=Exception("io")))

        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 500

    def test_rmap_get_link_insert_failure_cleans_file(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1388-1396: insert fails, file is cleaned, 503 returned
        from pathlib import Path
        from server.src import server as srv
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={"alice@example.com": True},
            handle2={"result": "secret-link"}
        )
        mock_conn = app.config['mock_db_conn']
        one_row_result = MagicMock(); one_row = MagicMock(id=1, path=str(Path(app.config["STORAGE_DIR"]) / "src5.pdf"))
        Path(one_row.path).write_bytes(b"%PDF-1.4\n%%EOF")
        one_row_result.fetchall.return_value = [one_row]
        versions_result = MagicMock(); versions_result.first.return_value = None
        # Sequence: source doc, versions select, insert -> raise
        mock_conn.execute.side_effect = [one_row_result, versions_result, Exception("insert fail")]
        monkeypatch.setattr(srv.WMUtils, "apply_watermark", MagicMock(return_value=b"pdf-bytes"), raising=True)

        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 503

    def test_rmap_get_link_success_and_existing(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1398-1405 success (generated) and 1406-1412 existing branch
        from pathlib import Path
        from server.src import server as srv
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns"},
            nonces={"alice@example.com": True},
            handle2={"result": "secret-link"}
        )
        mock_conn = app.config['mock_db_conn']
        # First flow: generate new
        one_row_result = MagicMock(); src1 = MagicMock(id=1, path=str(Path(app.config["STORAGE_DIR"]) / "src6.pdf"))
        Path(src1.path).write_bytes(b"%PDF-1.4\n%%EOF")
        one_row_result.fetchall.return_value = [src1]
        versions_result_none = MagicMock(); versions_result_none.first.return_value = None
        insert_ok = MagicMock()
        monkeypatch.setattr(srv.WMUtils, "apply_watermark", MagicMock(return_value=b"pdf-bytes"), raising=True)
        mock_conn.execute.side_effect = [one_row_result, versions_result_none, insert_ok]
        resp1 = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp1.status_code == 200

        # Second flow: existing row
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result={"nonceServer": "ns2"},
            nonces={"bob@example.com": True}
        )
        one_row_result2 = MagicMock(); src2 = MagicMock(id=1, path=str(Path(app.config["STORAGE_DIR"]) / "src7.pdf"))
        Path(src2.path).write_bytes(b"%PDF-1.4\n%%EOF")
        one_row_result2.fetchall.return_value = [src2]
        existing = MagicMock(); existing_row = MagicMock(); existing_row.link = "preexisting-link"; existing.first.return_value = existing_row
        mock_conn.execute.side_effect = [one_row_result2, existing]
        resp2 = client.post("/api/rmap-get-link", json={"payload": "y"})
        assert resp2.status_code == 200

    def test_rmap_get_link_outer_exception(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1415-1417: outer except returns 400
        self._set_rmap_mocks(
            monkeypatch,
            decrypt_result=Exception("boom"),
            nonces={"alice@example.com": True}
        )
        resp = client.post("/api/rmap-get-link", json={"payload": "x"})
        assert resp.status_code == 400

    def test_identify_leak_admin_key_and_empty_file(self, client: FlaskClient, app: Flask):
        # cover 1431: empty file object
        headers = {"X-Admin-Key": app.config["RMAP_ADMIN_KEY"]}
        resp = client.post("/api/rmap-identify-leak", headers=headers, data={"file": (io.BytesIO(b"content"), "")})
        assert resp.status_code == 400

    def test_identify_leak_db_error_and_not_found(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1465-1467 and 1470-1471
        from server.src import server as srv
        headers = {"X-Admin-Key": app.config["RMAP_ADMIN_KEY"]}
        # Patch watermark extraction to a known secret
        monkeypatch.setattr(srv.WMUtils, "read_watermark", MagicMock(return_value="sec-1"), raising=True)

        # First: DB error
        mock_conn = app.config['mock_db_conn']
        mock_conn.execute.side_effect = Exception("db err")
        resp_err = client.post("/api/rmap-identify-leak", headers=headers, data={"file": (io.BytesIO(b"pdf"), "x.pdf")})
        assert resp_err.status_code == 503

        # Second: not found
        mock_conn.execute.side_effect = None
        notfound = MagicMock(); notfound.first.return_value = None
        mock_conn.execute.return_value = notfound
        resp_nf = client.post("/api/rmap-identify-leak", headers=headers, data={"file": (io.BytesIO(b"pdf"), "x.pdf")})
        assert resp_nf.status_code == 200
        assert resp_nf.get_json().get("identified") is False

    def test_identify_leak_success(self, client: FlaskClient, app: Flask, monkeypatch):
        # cover 1477-1490
        from server.src import server as srv
        headers = {"X-Admin-Key": app.config["RMAP_ADMIN_KEY"]}
        monkeypatch.setattr(srv.WMUtils, "read_watermark", MagicMock(return_value="sec-2"), raising=True)
        mock_conn = app.config['mock_db_conn']
        row = MagicMock(); row.id = 42; row.link = "lk"; row.intended_for = "alice"; row.method = "m"; row.path = "/p"
        ok = MagicMock(); ok.first.return_value = row
        mock_conn.execute.return_value = ok
        resp = client.post("/api/rmap-identify-leak", headers=headers, data={"file": (io.BytesIO(b"pdf"), "x.pdf")})
        assert resp.status_code == 200

    def test_home_page_404_error(self, client: FlaskClient):
        """Test home page 404 error."""
        from werkzeug.exceptions import NotFound

        with patch.object(client.application, 'send_static_file') as mock_send_static:
            # Mock send_static_file to raise NotFound exception
            mock_send_static.side_effect = NotFound()

            response = client.get("/")

            assert response.status_code == 404
            result = response.get_json()
            assert "error" in result
            assert "File not found" in result["error"]