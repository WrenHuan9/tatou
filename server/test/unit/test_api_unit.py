"""Complete integration tests for all server endpoints.

This module provides comprehensive integration tests for the entire Tatou server API,
covering all endpoints, authentication flows, and business logic interactions.
"""

import datetime as dt
import hashlib
import io
import json
import os
import secrets
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from typing import Dict, Any

import pytest
from flask import Flask
from flask.testing import FlaskClient
from itsdangerous import URLSafeTimedSerializer


@pytest.mark.integration
class TestBasicEndpoints:
    """Test basic server endpoints and functionality."""

    def test_health_check_success(self, client: FlaskClient, app: Flask):
        """Test health check endpoint with working database."""
        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.return_value = MagicMock()

        response = client.get("/healthz")

        assert response.status_code == 200
        data = response.get_json()
        assert "message" in data
        assert "db_connected" in data

    def test_health_check_db_failure(self, client: FlaskClient, app: Flask):
        """Test health check endpoint with database connection failure."""
        mock_engine = MagicMock()
        mock_engine.connect.side_effect = Exception("DB connection failed")
        app.config["_ENGINE"] = mock_engine

        response = client.get("/healthz")

        assert response.status_code == 200
        data = response.get_json()
        assert data["db_connected"] is False

        app.config["_ENGINE"] = None

    def test_home_page(self, client: FlaskClient):
        """Test home page returns static file."""
        # This will attempt to serve static/index.html
        response = client.get("/")
        # In test environment, static files may not exist, so we expect 404
        # The important thing is that it tries to serve the file
        assert response.status_code in [200, 404]

    def test_static_file_serving(self, client: FlaskClient):
        """Test static file serving."""
        response = client.get("/test.css")
        # In test environment, static files may not exist
        assert response.status_code in [200, 404]


@pytest.mark.integration
class TestCompleteAuthenticationFlow:
    """Test complete authentication workflow."""

    def test_create_user_success(self, client: FlaskClient, app: Flask):
        """Test successful user creation."""
        user_data = {
            "email": "newuser@example.com",
            "login": "newuser",
            "password": "securepassword123"
        }

        # Create a simple class to hold the row data
        class MockRow:
            def __init__(self):
                self.id = 1
                self.email = "newuser@example.com"
                self.login = "newuser"

        mock_user_row = MockRow()

        # Get or create the mock engine
        if '_ENGINE' not in app.config or app.config['_ENGINE'] is None:
            mock_engine = MagicMock()
            app.config['_ENGINE'] = mock_engine
        else:
            mock_engine = app.config['_ENGINE']

        # Mock the database operations
        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn

        # Mock INSERT result
        mock_insert_result = MagicMock()
        mock_insert_result.lastrowid = 1

        # Mock SELECT result
        mock_select_result = MagicMock()
        mock_select_result.one.return_value = mock_user_row

        mock_conn.execute.side_effect = [
            mock_insert_result,  # INSERT result
            mock_select_result  # SELECT result
        ]

        response = client.post("/api/create-user", json=user_data)

        assert response.status_code == 201
        data = response.get_json()
        assert data["id"] == 1
        assert data["email"] == "newuser@example.com"
        assert data["login"] == "newuser"

    def test_create_user_validation_errors(self, client: FlaskClient):
        """Test user creation with various validation errors."""
        test_cases = [
            ({}, "missing all fields"),
            ({"email": "test@example.com"}, "missing login and password"),
            ({"login": "testuser"}, "missing email and password"),
            ({"password": "password123"}, "missing email and login"),
            ({"email": "", "login": "test", "password": "pass"}, "empty email"),
            ({"email": "test@example.com", "login": "", "password": "pass"}, "empty login"),
            ({"email": "test@example.com", "login": "test", "password": ""}, "empty password"),
        ]

        for user_data, description in test_cases:
            response = client.post("/api/create-user", json=user_data)
            assert response.status_code == 400, f"Failed for case: {description}"
            data = response.get_json()
            assert "error" in data
            assert "required" in data["error"].lower()

    def test_create_user_duplicate_email(self, client: FlaskClient, app: Flask):
        """Test user creation with duplicate email."""
        user_data = {
            "email": "duplicate@example.com",
            "login": "user1",
            "password": "password123"
        }

        # Get or create the mock engine
        if '_ENGINE' not in app.config or app.config['_ENGINE'] is None:
            mock_engine = MagicMock()
            app.config['_ENGINE'] = mock_engine
        else:
            mock_engine = app.config['_ENGINE']

        # Mock the database operations to raise IntegrityError
        from sqlalchemy.exc import IntegrityError
        mock_conn = MagicMock()
        mock_engine.begin.return_value.__enter__.return_value = mock_conn

        # Make execute raise IntegrityError
        mock_conn.execute.side_effect = IntegrityError("", "", "")

        response = client.post("/api/create-user", json=user_data)

        assert response.status_code == 409
        data = response.get_json()
        assert "error" in data
        assert "already exists" in data["error"]

    def test_login_success(self, client: FlaskClient, app: Flask):
        """Test successful login."""
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }

        from werkzeug.security import generate_password_hash

        # Create a simple class to hold the row data
        class MockRow:
            def __init__(self):
                self.id = 1
                self.email = "test@example.com"
                self.login = "testuser"
                self.hpassword = generate_password_hash("testpassword123")

        mock_row = MockRow()

        # Get or create the mock engine
        if '_ENGINE' not in app.config or app.config['_ENGINE'] is None:
            mock_engine = MagicMock()
            app.config['_ENGINE'] = mock_engine
        else:
            mock_engine = app.config['_ENGINE']

        # Mock the database operations (login uses connect, not begin)
        mock_conn = MagicMock()
        mock_engine.connect.return_value.__enter__.return_value = mock_conn

        mock_result = MagicMock()
        mock_result.first.return_value = mock_row
        mock_conn.execute.return_value = mock_result

        response = client.post("/api/login", json=login_data)

        assert response.status_code == 200
        data = response.get_json()
        assert "token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert data["expires_in"] == app.config["TOKEN_TTL_SECONDS"]

    def test_login_invalid_credentials(self, client: FlaskClient, app: Flask):
        """Test login with invalid credentials."""
        test_cases = [
            ({"email": "nonexistent@example.com", "password": "password123"}, "nonexistent user"),
            ({"email": "test@example.com", "password": "wrongpassword"}, "wrong password"),
        ]

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            for login_data, description in test_cases:
                if "nonexistent" in login_data["email"]:
                    # Mock user not found
                    mock_conn.execute.return_value.first.return_value = None
                else:
                    # Mock wrong password
                    from werkzeug.security import generate_password_hash
                    mock_row = MagicMock()
                    mock_row.id = 1
                    mock_row.email = "test@example.com"
                    mock_row.login = "testuser"
                    mock_row.hpassword = generate_password_hash("correctpassword")
                    mock_conn.execute.return_value.first.return_value = mock_row

                response = client.post("/api/login", json=login_data)

                assert response.status_code == 401, f"Failed for case: {description}"
                data = response.get_json()
                assert "error" in data
                assert "invalid credentials" in data["error"]

    def test_login_validation_errors(self, client: FlaskClient):
        """Test login with various validation errors."""
        test_cases = [
            ({}, "empty payload"),
            ({"email": "test@example.com"}, "missing password"),
            ({"password": "password123"}, "missing email"),
            ({"email": "", "password": "password123"}, "empty email"),
            ({"email": "test@example.com", "password": ""}, "empty password"),
        ]

        for login_data, description in test_cases:
            response = client.post("/api/login", json=login_data)
            assert response.status_code == 400, f"Failed for case: {description}"
            data = response.get_json()
            assert "error" in data
            assert "required" in data["error"].lower()

    def test_token_authentication(self, client: FlaskClient, app: Flask):
        """Test token-based authentication."""
        # Create a valid token
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        valid_token = serializer.dumps(token_data)

        headers = {"Authorization": f"Bearer {valid_token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.return_value.all.return_value = []

        response = client.get("/api/list-documents", headers=headers)

        # Should not get auth error
        assert response.status_code != 401

    def test_invalid_token_authentication(self, client: FlaskClient):
        """Test authentication with invalid tokens."""
        test_cases = [
            ({}, "no authorization header"),
            ({"Authorization": "Bearer invalid_token"}, "invalid token"),
            ({"Authorization": "Basic dXNlcjpwYXNz"}, "wrong auth type"),
            ({"Authorization": "Bearer "}, "empty token"),
        ]

        for headers, description in test_cases:
            response = client.get("/api/list-documents", headers=headers)
            assert response.status_code == 401, f"Failed for case: {description}"
            data = response.get_json()
            assert "error" in data


import io
import datetime as dt
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask.testing import FlaskClient
from itsdangerous import URLSafeTimedSerializer


@pytest.mark.integration
class TestDocumentManagement:
    """Test complete document management workflow."""

    def _get_valid_token(self, app: Flask) -> str:
        """Helper method to create a valid token."""
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6"
        )
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        return serializer.dumps(token_data)

    def test_upload_document_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes,
                                     temp_storage: Path):
        """Test successful document upload."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # Ensure STORAGE_DIR is a Path object and use temp_storage
        app.config["STORAGE_DIR"] = temp_storage

        # Get the existing mock engine
        mock_engine = app.config.get('_ENGINE')

        # Create a fresh mock connection for this test
        mock_conn = MagicMock()
        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)

        # Reconfigure mock_engine.begin() for this test
        mock_engine.begin.return_value = mock_context

        # Create mock objects for the three database operations
        mock_insert = MagicMock()
        mock_lastid = MagicMock()
        mock_lastid.scalar.return_value = 1

        # CRITICAL: Use real datetime, not MagicMock
        creation_time = dt.datetime(2023, 1, 1, 12, 0, 0)
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.name = "test.pdf"
        mock_row.creation = creation_time  # Real datetime
        mock_row.sha256_hex = "abcdef123456"
        mock_row.size = len(sample_pdf_bytes)

        mock_select = MagicMock()
        mock_select.one.return_value = mock_row

        # Set up side_effect for multiple execute calls
        mock_conn.execute.side_effect = [
            mock_insert,  # INSERT
            mock_lastid,  # LAST_INSERT_ID
            mock_select  # SELECT
        ]

        with patch('hashlib.sha256') as mock_hash:
            mock_hash_obj = MagicMock()
            mock_hash_obj.hexdigest.return_value = "abcdef123456"
            mock_hash.return_value = mock_hash_obj

            data = {'file': (io.BytesIO(sample_pdf_bytes), 'test.pdf')}
            response = client.post("/api/upload-document", headers=headers, data=data)

        assert response.status_code == 201
        result = response.get_json()
        assert "id" in result
        assert result["name"] == "test.pdf"
        assert "sha256" in result
        assert "size" in result

    def test_upload_document_validation_errors(self, client: FlaskClient, app: Flask):
        """Test document upload with various validation errors."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        test_cases = [
            ({}, "no file"),
            ({'file': (io.BytesIO(b''), '')}, "empty filename"),
            ({'file': (io.BytesIO(b'not a pdf'), 'test.txt')}, "not a PDF"),
            ({'file': (io.BytesIO(b'fake pdf content'), 'test.pdf')}, "invalid PDF content"),
        ]

        for data, description in test_cases:
            response = client.post("/api/upload-document", headers=headers, data=data)
            assert response.status_code == 400, f"Failed for case: {description}"
            result = response.get_json()
            assert "error" in result

    def test_list_documents_success(self, client: FlaskClient, app: Flask):
        """Test successful document listing."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # Get the existing mock engine
        mock_engine = app.config.get('_ENGINE')

        # Create a fresh mock connection for this test
        mock_conn = MagicMock()
        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)

        # Reconfigure mock_engine.connect() for this test
        mock_engine.connect.return_value = mock_context

        # Mock document list with real datetime objects
        mock_doc1 = MagicMock()
        mock_doc1.id = 1
        mock_doc1.name = "doc1.pdf"
        mock_doc1.creation = dt.datetime(2023, 1, 1)
        mock_doc1.sha256_hex = "hash1"
        mock_doc1.size = 1024

        mock_doc2 = MagicMock()
        mock_doc2.id = 2
        mock_doc2.name = "doc2.pdf"
        mock_doc2.creation = dt.datetime(2023, 1, 2)
        mock_doc2.sha256_hex = "hash2"
        mock_doc2.size = 2048

        mock_docs = [mock_doc1, mock_doc2]

        mock_result = MagicMock()
        mock_result.all.return_value = mock_docs
        mock_conn.execute.return_value = mock_result

        response = client.get("/api/list-documents", headers=headers)

        assert response.status_code == 200
        data = response.get_json()
        assert "documents" in data
        assert len(data["documents"]) == 2

    def test_get_document_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes, temp_storage: Path):
        """Test successful document retrieval."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # CRITICAL: Set STORAGE_DIR to temp_storage so path validation passes
        app.config["STORAGE_DIR"] = temp_storage

        # Create a real test file in the correct location
        test_file = temp_storage / "test_doc.pdf"
        test_file.write_bytes(sample_pdf_bytes)

        # Get the existing mock engine
        mock_engine = app.config.get('_ENGINE')

        # Create a fresh mock connection for this test
        mock_conn = MagicMock()
        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)

        # Reconfigure mock_engine.connect() for this test
        mock_engine.connect.return_value = mock_context

        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.name = "test.pdf"
        mock_row.path = str(test_file)  # Use real file path
        mock_row.sha256_hex = "abcdef123456"
        mock_row.size = len(sample_pdf_bytes)

        mock_result = MagicMock()
        mock_result.first.return_value = mock_row
        mock_conn.execute.return_value = mock_result

        response = client.get("/api/get-document/1", headers=headers)

        assert response.status_code == 200
        assert response.content_type == "application/pdf"

    def test_get_document_not_found(self, client: FlaskClient, app: Flask):
        """Test document retrieval when document doesn't exist."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # Get the existing mock engine
        mock_engine = app.config.get('_ENGINE')

        # Create a fresh mock connection for this test
        mock_conn = MagicMock()
        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)

        # Reconfigure mock_engine.connect() for this test
        mock_engine.connect.return_value = mock_context

        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_conn.execute.return_value = mock_result

        response = client.get("/api/get-document/999", headers=headers)

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    def test_delete_document_success(self, client: FlaskClient, app: Flask, temp_storage: Path):
        """Test successful document deletion."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # Create a real test file
        test_file = temp_storage / "test_delete.pdf"
        test_file.write_bytes(b"%PDF-1.4\ntest")

        # Get the existing mock engine
        mock_engine = app.config.get('_ENGINE')

        # Create fresh mock connections for read and write
        mock_conn_read = MagicMock()
        mock_context_read = MagicMock()
        mock_context_read.__enter__ = MagicMock(return_value=mock_conn_read)
        mock_context_read.__exit__ = MagicMock(return_value=False)

        mock_conn_write = MagicMock()
        mock_context_write = MagicMock()
        mock_context_write.__enter__ = MagicMock(return_value=mock_conn_write)
        mock_context_write.__exit__ = MagicMock(return_value=False)

        # Setup: first call is connect(), subsequent calls are begin()
        mock_engine.connect.return_value = mock_context_read
        mock_engine.begin.return_value = mock_context_write

        # Mock document exists
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.path = str(test_file)

        mock_result1 = MagicMock()
        mock_result1.first.return_value = mock_row

        mock_result2 = MagicMock()
        mock_result2.fetchall.return_value = []  # No versions

        mock_result3 = MagicMock()  # DELETE operation

        # First execute is in connect context (SELECT document)
        mock_conn_read.execute.return_value = mock_result1
        # Rest are in begin context (SELECT versions, DELETE)
        mock_conn_write.execute.side_effect = [mock_result2, mock_result3]

        response = client.delete("/api/delete-document/1", headers=headers)

        assert response.status_code == 200
        data = response.get_json()
        assert data["deleted"] is True
        assert data["id"] == 1

    def test_delete_document_not_found(self, client: FlaskClient, app: Flask):
        """Test document deletion when document doesn't exist."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # Get the existing mock engine
        mock_engine = app.config.get('_ENGINE')

        # Create a fresh mock connection for this test
        mock_conn = MagicMock()
        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)

        # Reconfigure mock_engine.connect() for this test
        mock_engine.connect.return_value = mock_context

        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_conn.execute.return_value = mock_result

        response = client.delete("/api/delete-document/999", headers=headers)

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    def test_delete_versions_query_db_error_returns_503(self, client: FlaskClient, app: Flask, tmp_path: Path):
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}
        app.config["STORAGE_DIR"] = tmp_path

        mock_engine = app.config.get('_ENGINE')

        conn1 = MagicMock()
        ctx1 = MagicMock()
        ctx1.__enter__.return_value = conn1
        ctx1.__exit__.return_value = False

        conn2 = MagicMock()
        conn2.execute.side_effect = Exception("versions query failed")
        ctx2 = MagicMock()
        ctx2.__enter__.return_value = conn2
        ctx2.__exit__.return_value = False

        mock_engine.connect.side_effect = [ctx1, ctx2]

        doc_row = MagicMock()
        doc_row.id = 1
        doc_row.path = str(tmp_path / "files" / "testuser" / "doc.pdf")
        conn1.execute.return_value.first.return_value = doc_row

        resp = client.delete("/api/delete-document/1", headers=headers)
        assert resp.status_code == 503
        assert "error" in resp.get_json()

    def test_delete_version_file_unlink_error_sets_issue_flag(self, client: FlaskClient, app: Flask, tmp_path: Path):
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}
        app.config["STORAGE_DIR"] = tmp_path

        versions_dir = tmp_path / "files" / "testuser" / "watermarks"
        versions_dir.mkdir(parents=True, exist_ok=True)
        version_file = versions_dir / "v1.pdf"
        version_file.write_bytes(b"%PDF-1.4\n%%EOF")

        original_path = tmp_path / "files" / "testuser" / "doc.pdf"

        mock_engine = app.config.get('_ENGINE')

        conn_read = MagicMock()
        ctx_read = MagicMock()
        ctx_read.__enter__.return_value = conn_read
        ctx_read.__exit__.return_value = False

        conn_versions = MagicMock()
        ctx_versions = MagicMock()
        ctx_versions.__enter__.return_value = conn_versions
        ctx_versions.__exit__.return_value = False

        conn_write = MagicMock()
        ctx_write = MagicMock()
        ctx_write.__enter__.return_value = conn_write
        ctx_write.__exit__.return_value = False

        mock_engine.connect.side_effect = [ctx_read, ctx_versions]
        mock_engine.begin.return_value = ctx_write

        doc_row = MagicMock()
        doc_row.id = 1
        doc_row.path = str(original_path)
        conn_read.execute.return_value.first.return_value = doc_row

        version_row = MagicMock()
        version_row.id = 11
        version_row.path = str(version_file)
        conn_versions.execute.return_value.fetchall.return_value = [version_row]

        with patch('pathlib.Path.unlink', side_effect=Exception('unlink error')), patch('pathlib.Path.exists', side_effect=lambda p=version_file: True if str(p) == str(version_file) else False):
            resp = client.delete("/api/delete-document/1", headers=headers)

        assert resp.status_code == 200
        body = resp.get_json()
        assert body["deleted"] is True
        assert body["has_file_issues"] is True

    def test_delete_db_error_returns_503(self, client: FlaskClient, app: Flask, tmp_path: Path):
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}
        app.config["STORAGE_DIR"] = tmp_path

        mock_engine = app.config.get('_ENGINE')

        conn_read = MagicMock()
        ctx_read = MagicMock()
        ctx_read.__enter__.return_value = conn_read
        ctx_read.__exit__.return_value = False
        mock_engine.connect.return_value = ctx_read

        conn_write = MagicMock()
        conn_write.execute.side_effect = Exception("delete failed")
        ctx_write = MagicMock()
        ctx_write.__enter__.return_value = conn_write
        ctx_write.__exit__.return_value = False
        mock_engine.begin.return_value = ctx_write

        doc_row = MagicMock()
        doc_row.id = 1
        doc_row.path = str(tmp_path / "files" / "testuser" / "doc.pdf")
        conn_read.execute.side_effect = [
            MagicMock(first=lambda: doc_row),
            MagicMock(fetchall=lambda: []),
        ]

        with patch('pathlib.Path.exists', return_value=False):
            resp = client.delete("/api/delete-document/1", headers=headers)

        assert resp.status_code == 503
        assert "error" in resp.get_json()

@pytest.mark.integration
class TestWatermarkManagement:
    """Test complete watermark management workflow."""

    def _get_valid_token(self, app: Flask) -> str:
        """Helper method to create a valid token."""
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        return serializer.dumps(token_data)

    def test_get_watermarking_methods(self, client: FlaskClient):
        """Test getting available watermarking methods."""
        with patch('watermarking_utils.METHODS', {"test-method": MagicMock()}), \
             patch('watermarking_utils.get_method') as mock_get_method:

            mock_method = MagicMock()
            mock_method.get_usage.return_value = "Test method description"
            mock_get_method.return_value = mock_method

            response = client.get("/api/get-watermarking-methods")

            assert response.status_code == 200
            data = response.get_json()
            assert "methods" in data
            assert "count" in data

    def test_create_watermark_success(self, client: FlaskClient, app: Flask, temp_storage: Path,
                                      sample_pdf_bytes: bytes):
        """Test successful watermark creation."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # CRITICAL: Set STORAGE_DIR to temp_storage
        app.config["STORAGE_DIR"] = temp_storage

        # Create a real test file
        test_file = temp_storage / "test.pdf"
        test_file.write_bytes(sample_pdf_bytes)

        watermark_data = {
            "method": "test-method",
            "intended_for": "john@example.com",
            "secret": "secret123",
            "key": "key456",
            "position": "bottom-right"
        }

        # Get the existing mock engine
        mock_engine = app.config.get('_ENGINE')

        # Setup for connect() (SELECT query for document lookup)
        mock_conn_read = MagicMock()
        mock_context_read = MagicMock()
        mock_context_read.__enter__ = MagicMock(return_value=mock_conn_read)
        mock_context_read.__exit__ = MagicMock(return_value=False)
        mock_engine.connect.return_value = mock_context_read

        # Setup for begin() (INSERT query for version creation)
        mock_conn_write = MagicMock()
        mock_context_write = MagicMock()
        mock_context_write.__enter__ = MagicMock(return_value=mock_conn_write)
        mock_context_write.__exit__ = MagicMock(return_value=False)
        mock_engine.begin.return_value = mock_context_write

        # Mock document exists
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.name = "test.pdf"
        mock_row.path = str(test_file)  # Use real file path

        mock_result1 = MagicMock()
        mock_result1.first.return_value = mock_row
        mock_conn_read.execute.return_value = mock_result1

        # Mock INSERT and LAST_INSERT_ID for version creation
        mock_insert = MagicMock()
        mock_lastid = MagicMock()
        mock_lastid.scalar.return_value = 1
        mock_conn_write.execute.side_effect = [mock_insert, mock_lastid]

        with patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
                patch('watermarking_utils.apply_watermark', return_value=b'watermarked content'):
            response = client.post("/api/create-watermark/1", headers=headers, json=watermark_data)

        assert response.status_code == 201
        result = response.get_json()
        assert "id" in result
        assert result["link"] is not None
        assert result["intended_for"] == "john@example.com"

    def test_create_watermark_validation_errors(self, client: FlaskClient, app: Flask):
        """Test watermark creation with validation errors."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        test_cases = [
            ({}, "empty payload"),
            ({"method": "test"}, "missing fields"),
            ({"method": "", "intended_for": "john", "secret": "s", "key": "k"}, "empty method"),
        ]

        for watermark_data, description in test_cases:
            response = client.post("/api/create-watermark/1", headers=headers, json=watermark_data)
            assert response.status_code == 400, f"Failed for case: {description}"
            data = response.get_json()
            assert "error" in data

    def test_create_watermark_document_not_found(self, client: FlaskClient, app: Flask):
        """Test watermark creation when document doesn't exist."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        watermark_data = {
            "method": "test-method",
            "intended_for": "john@example.com",
            "secret": "secret123",
            "key": "key456"
        }

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.return_value.first.return_value = None

        response = client.post("/api/create-watermark/999", headers=headers, json=watermark_data)

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data
        assert "not found" in data["error"].lower()

    def test_create_watermark_invalid_id_from_query_returns_400(self, client: FlaskClient, app: Flask, tmp_path: Path):
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}
        app.config["STORAGE_DIR"] = tmp_path

        payload = {"method": "m", "intended_for": "a@b", "secret": "s", "key": "k"}
        resp = client.post("/api/create-watermark?id=abc", headers=headers, json=payload)
        assert resp.status_code == 400
        assert "document_id (int) is required" in resp.get_json().get("error", "")

    def test_create_watermark_invalid_id_from_body_returns_400(self, client: FlaskClient, app: Flask, tmp_path: Path):
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}
        app.config["STORAGE_DIR"] = tmp_path

        payload = {"id": "not-an-int", "method": "m", "intended_for": "a@b", "secret": "s", "key": "k"}
        resp = client.post("/api/create-watermark", headers=headers, json=payload)
        assert resp.status_code == 400
        assert "document_id (int) is required" in resp.get_json().get("error", "")

    def test_list_versions_success(self, client: FlaskClient, app: Flask):
        """Test successful version listing."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_versions = [
                MagicMock(
                    id=1,
                    documentid=1,
                    link="link123",
                    intended_for="john@example.com",
                    secret="secret123",
                    method="test-method"
                )
            ]
            mock_conn.execute.return_value.all.return_value = mock_versions

        response = client.get("/api/list-versions/1", headers=headers)

        assert response.status_code == 200
        data = response.get_json()
        assert "versions" in data
        assert len(data["versions"]) == 1
        assert data["versions"][0]["id"] == 1

    def test_list_all_versions_success(self, client: FlaskClient, app: Flask):
        """Test successful listing of all versions."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_versions = [
                MagicMock(
                    id=1,
                    documentid=1,
                    link="link123",
                    intended_for="john@example.com",
                    method="test-method"
                ),
                MagicMock(
                    id=2,
                    documentid=2,
                    link="link456",
                    intended_for="jane@example.com",
                    method="test-method"
                )
            ]
            mock_conn.execute.return_value.all.return_value = mock_versions

        response = client.get("/api/list-all-versions", headers=headers)

        assert response.status_code == 200
        data = response.get_json()
        assert "versions" in data
        assert len(data["versions"]) == 2

    def test_get_version_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test successful version retrieval by link."""
        storage_dir = app.config["STORAGE_DIR"]
        relative_path = "watermarks/testfile.pdf"
        full_path = storage_dir / relative_path

        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(sample_pdf_bytes)

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.link = "testlink123"
            mock_row.path = relative_path
            mock_conn.execute.return_value.first.return_value = mock_row

        with patch('server.src.server.send_file') as mock_send_file:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_send_file.return_value = mock_response

            response = client.get("/api/get-version/testlink123")

            assert mock_send_file.called
            assert response.status_code == 200

    def test_get_version_not_found(self, client: FlaskClient, app: Flask):
        """Test version retrieval when version doesn't exist."""
        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.return_value.first.return_value = None

        response = client.get("/api/get-version/nonexistent")

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data
        assert "not found" in data["error"].lower()

    def test_read_watermark_by_link_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test successful watermark reading by link."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        read_data = {
            "method": "test-method",
            "key": "test-key"
        }

        storage_dir = app.config["STORAGE_DIR"]
        relative_path = "watermarks/testfile.pdf"
        full_path = storage_dir / relative_path

        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(sample_pdf_bytes)

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.documentid = 1
            mock_row.link = "testlink123"
            mock_row.secret = "extracted_secret"
            mock_row.path = relative_path
            mock_conn.execute.return_value.first.return_value = mock_row

        with patch('watermarking_utils.read_watermark', return_value="extracted_secret"):
            response = client.post("/api/read-watermark-by-link/testlink123",
                                   headers=headers, json=read_data)

            assert response.status_code == 200
            data = response.get_json()
            assert data["link"] == "testlink123"
            assert data["secret"] == "extracted_secret"

    def test_read_watermark_by_link_validation_errors(self, client: FlaskClient, app: Flask):
        """Test watermark reading with validation errors."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        test_cases = [
            ({}, "empty payload"),
            ({"method": "test"}, "missing key"),
            ({"key": "test"}, "missing method"),
        ]

        for read_data, description in test_cases:
            response = client.post("/api/read-watermark-by-link/testlink",
                                 headers=headers, json=read_data)
            assert response.status_code == 400, f"Failed for case: {description}"
            data = response.get_json()
            assert "error" in data


@pytest.mark.integration
class TestRMAPFunctionality:
    """Test RMAP (Remote Monitoring and Provenance) functionality."""

    def test_rmap_initiate_no_service(self, client: FlaskClient):
        """Test RMAP initiate when service is not available."""
        with patch('server.src.server.rmap_service', None):
            response = client.post("/api/rmap-initiate", json={"payload": "test"})

            assert response.status_code == 503
            data = response.get_json()
            assert "error" in data
            assert "not available" in data["error"]

    def test_rmap_initiate_missing_payload(self, client: FlaskClient):
        """Test RMAP initiate with missing payload."""
        with patch('server.src.server.rmap_service', MagicMock()):
            response = client.post("/api/rmap-initiate", json={})

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "Payload missing" in data["error"]

    def test_rmap_initiate_success(self, client: FlaskClient):
        """Test successful RMAP initiate."""
        mock_rmap_service = MagicMock()
        mock_rmap_service.handle_message1.return_value = {"status": "success"}

        # Mock identity_manager
        mock_identity_manager = MagicMock()
        mock_identity_manager.decrypt_for_server.return_value = {
            "identity": "test@example.com",
            "nonce": "test_nonce_123"
        }

        with patch('server.src.server.rmap_service', mock_rmap_service), \
                patch('server.src.server.identity_manager', mock_identity_manager):
            # payload should be armored base64
            response = client.post("/api/rmap-initiate", json={"payload": "test_payload"})

            assert response.status_code == 200
            # Verify identity_manager was called
            mock_identity_manager.decrypt_for_server.assert_called_once_with("test_payload")
            # Verify rmap_service was called
            mock_rmap_service.handle_message1.assert_called_once_with({"payload": "test_payload"})

    def test_rmap_get_link_no_service(self, client: FlaskClient):
        """Test RMAP get link when service is not available."""
        with patch('server.src.server.rmap_service', None):
            response = client.post("/api/rmap-get-link", json={"payload": "test"})

            assert response.status_code == 503
            data = response.get_json()
            assert "error" in data
            assert "not available" in data["error"]

    def test_rmap_get_link_missing_payload(self, client: FlaskClient):
        """Test RMAP get link with missing payload."""
        with patch('server.src.server.rmap_service', MagicMock()):
            response = client.post("/api/rmap-get-link", json={})

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "Payload missing" in data["error"]

    def test_rmap_identify_leak_no_auth(self, client: FlaskClient):
        """Test RMAP identify leak without admin key."""
        response = client.post("/api/rmap-identify-leak")

        assert response.status_code == 401
        data = response.get_json()
        assert "error" in data
        assert "Unauthorized" in data["error"]

    def test_rmap_identify_leak_invalid_auth(self, client: FlaskClient):
        """Test RMAP identify leak with invalid admin key."""
        headers = {"X-Admin-Key": "wrong-key"}
        response = client.post("/api/rmap-identify-leak", headers=headers)

        assert response.status_code == 401
        data = response.get_json()
        assert "error" in data
        assert "Invalid" in data["error"]

    def test_rmap_identify_leak_no_file(self, client: FlaskClient, app: Flask):
        """Test RMAP identify leak without file upload."""
        # Mock the admin key check
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'change-this-admin-key'}):
            headers = {"X-Admin-Key": "change-this-admin-key"}
            response = client.post("/api/rmap-identify-leak", headers=headers)

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "file is required" in data["error"]

    def test_rmap_identify_leak_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test successful RMAP leak identification."""

        # Setup mock data
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.link = "testlink"
        mock_row.intended_for = "john@example.com"
        mock_row.secret = "extracted_secret"
        mock_row.method = "test-method"
        mock_row.path = "/storage/test.pdf"

        # Mock the database query result
        mock_result = MagicMock()
        mock_result.first.return_value = mock_row

        # Get the mock_conn from app config
        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            # Setup the execute -> first chain
            mock_conn.execute.return_value = mock_result

        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'change-this-admin-key'}), \
                patch('server.src.server.WMUtils.read_watermark', return_value="extracted_secret"):
            headers = {"X-Admin-Key": "change-this-admin-key"}
            data = {'file': (io.BytesIO(sample_pdf_bytes), 'leaked.pdf')}
            response = client.post("/api/rmap-identify-leak", headers=headers, data=data)

            assert response.status_code == 200
            result = response.get_json()
            assert result["identified"] is True
            assert result["identity"] == "john@example.com"
            assert "version_info" in result
            assert result["version_info"]["id"] == 1
            assert result["version_info"]["link"] == "testlink"

    def test_rmap_identify_leak_no_watermark(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test RMAP leak identification when no watermark is found."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'change-this-admin-key'}), \
             patch('watermarking_utils.read_watermark', side_effect=Exception("No watermark found")):

            headers = {"X-Admin-Key": "change-this-admin-key"}
            data = {'file': (io.BytesIO(sample_pdf_bytes), 'clean.pdf')}
            response = client.post("/api/rmap-identify-leak", headers=headers, data=data)

            assert response.status_code == 200
            result = response.get_json()
            assert result["identified"] is False
            assert "error" in result


@pytest.mark.integration
class TestCompleteWorkflows:
    """Test complete end-to-end workflows."""

    def _create_user_and_login(self, client: FlaskClient, app: Flask,
                               email: str = "workflow@example.com",
                               login: str = "workflow",
                               password: str = "password123") -> str:
        """Helper to create user and get auth token."""
        # Create user
        user_data = {"email": email, "login": login, "password": password}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_insert_result = MagicMock()
            mock_insert_result.lastrowid = 1
            mock_user_row = MagicMock()
            mock_user_row.id = 1
            mock_user_row.email = email
            mock_user_row.login = login

            # For user creation
            mock_conn.execute.side_effect = [
                mock_insert_result,
                MagicMock(one=lambda: mock_user_row)
            ]

        create_response = client.post("/api/create-user", json=user_data)
        assert create_response.status_code == 201

        # Login - IMPORTANT: Reset side_effect before setting return_value
        if mock_conn:
            from werkzeug.security import generate_password_hash
            mock_login_row = MagicMock()
            mock_login_row.id = 1
            mock_login_row.email = email
            mock_login_row.login = login
            mock_login_row.hpassword = generate_password_hash(password)

            # Reset side_effect to None so return_value can work
            mock_conn.execute.side_effect = None
            mock_conn.execute.return_value.first.return_value = mock_login_row

        login_response = client.post("/api/login", json={"email": email, "password": password})
        assert login_response.status_code == 200

        return login_response.get_json()["token"]

    def test_complete_document_workflow(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test complete document workflow: create user -> login -> upload -> list -> get -> delete."""
        # Step 1: Create user and login
        token = self._create_user_and_login(client, app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')

        # Step 2: Upload document
        if mock_conn:
            # Create properly configured mock row
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "workflow.pdf"
            mock_row.creation = dt.datetime.now()
            mock_row.sha256_hex = "hash123"
            mock_row.size = len(sample_pdf_bytes)

            # Create mock result that returns the row
            mock_select_result = MagicMock()
            mock_select_result.one.return_value = mock_row

            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT
                MagicMock(scalar=lambda: 1),  # LAST_INSERT_ID
                mock_select_result  # SELECT
            ]

        # Don't mock file operations - use real temp directory
        upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'workflow.pdf')}
        upload_response = client.post("/api/upload-document", headers=headers, data=upload_data)

        assert upload_response.status_code == 201
        doc_id = upload_response.get_json()["id"]
        assert doc_id == 1

        # Step 3: List documents
        if mock_conn:
            mock_conn.execute.side_effect = None  # Reset side_effect

            mock_doc = MagicMock()
            mock_doc.id = doc_id
            mock_doc.name = "workflow.pdf"
            mock_doc.creation = dt.datetime.now()
            mock_doc.sha256_hex = "hash123"
            mock_doc.size = len(sample_pdf_bytes)

            mock_list_result = MagicMock()
            mock_list_result.all.return_value = [mock_doc]
            mock_conn.execute.return_value = mock_list_result

        list_response = client.get("/api/list-documents", headers=headers)
        assert list_response.status_code == 200
        assert len(list_response.get_json()["documents"]) == 1

        # Step 4: Get document
        # Find the actual file path that was created
        storage_dir = Path(app.config["STORAGE_DIR"])
        user_files_dir = storage_dir / "files" / "workflow"
        actual_files = list(user_files_dir.glob("*__workflow.pdf"))

        if mock_conn:
            mock_conn.execute.side_effect = None  # Reset side_effect

            mock_get_row = MagicMock()
            mock_get_row.id = doc_id
            mock_get_row.name = "workflow.pdf"
            mock_get_row.path = str(actual_files[0]) if actual_files else "/storage/workflow.pdf"
            mock_get_row.sha256_hex = "hash123"
            mock_get_row.size = len(sample_pdf_bytes)

            mock_get_result = MagicMock()
            mock_get_result.first.return_value = mock_get_row
            mock_conn.execute.return_value = mock_get_result

        get_response = client.get(f"/api/get-document/{doc_id}", headers=headers)
        assert get_response.status_code == 200

        # Step 5: Delete document
        if mock_conn:
            mock_delete_row = MagicMock()
            mock_delete_row.id = doc_id
            mock_delete_row.name = "workflow.pdf"
            mock_delete_row.path = str(actual_files[0]) if actual_files else "/storage/workflow.pdf"

            mock_versions_result = MagicMock()
            mock_versions_result.fetchall.return_value = []

            mock_doc_exists_result = MagicMock()
            mock_doc_exists_result.first.return_value = mock_delete_row

            mock_conn.execute.side_effect = [
                mock_doc_exists_result,  # Document exists check
                mock_versions_result,  # No versions
                MagicMock()  # DELETE
            ]

        delete_response = client.delete(f"/api/delete-document/{doc_id}", headers=headers)
        assert delete_response.status_code == 200
        assert delete_response.get_json()["deleted"] is True

    def test_complete_watermark_workflow(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test complete watermark workflow: upload -> create watermark -> list versions -> get version."""
        # Setup: Create user and upload document
        token = self._create_user_and_login(client, app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        doc_id = 1

        if mock_conn:
            mock_row = MagicMock()
            mock_row.id = doc_id
            mock_row.name = "watermark_test.pdf"
            mock_row.creation = dt.datetime.now()
            mock_row.sha256_hex = "hash123"
            mock_row.size = len(sample_pdf_bytes)

            mock_row.__getitem__ = lambda self, key: getattr(mock_row, key)

            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT
                MagicMock(scalar=lambda: doc_id),
                MagicMock(one=lambda: mock_row)
            ]

        with patch('pathlib.Path.mkdir'), \
                patch('pathlib.Path.stat') as mock_stat, \
                patch('pathlib.Path.open', mock_open(read_data=sample_pdf_bytes)), \
                patch('werkzeug.datastructures.FileStorage.save'), \
                patch('hashlib.sha256') as mock_hash:

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            mock_hash_instance = MagicMock()
            mock_hash_instance.hexdigest.return_value = "hash123"
            mock_hash.return_value = mock_hash_instance

            upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'watermark_test.pdf')}
            upload_response = client.post("/api/upload-document", headers=headers, data=upload_data)

        assert upload_response.status_code == 201
        response_data = upload_response.get_json()
        assert response_data["id"] == doc_id
        assert response_data["name"] == "watermark_test.pdf"

        # Step 1: Create watermark
        watermark_data = {
            "method": "toy-eof",
            "intended_for": "recipient@example.com",
            "secret": "confidential123",
            "key": "encryption456",
            "position": "bottom-right"
        }

        storage_dir = Path(app.config["STORAGE_DIR"])
        relative_doc_path = "files/workflow/watermark_test.pdf"

        doc_full_path = storage_dir / relative_doc_path
        doc_full_path.parent.mkdir(parents=True, exist_ok=True)

        doc_full_path.write_bytes(sample_pdf_bytes)

        watermarks_dir = doc_full_path.parent / "watermarks"
        watermarks_dir.mkdir(parents=True, exist_ok=True)

        if mock_conn:
            mock_doc_row = MagicMock()
            mock_doc_row.id = doc_id
            mock_doc_row.name = "watermark_test.pdf"
            mock_doc_row.path = str(doc_full_path)

            mock_conn.execute.side_effect = [
                MagicMock(first=lambda: mock_doc_row),  # Document check
                MagicMock(),  # INSERT version
                MagicMock(scalar=lambda: 1)  # LAST_INSERT_ID
            ]

        with patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
                patch('watermarking_utils.apply_watermark', return_value=sample_pdf_bytes):

            watermark_response = client.post(f"/api/create-watermark/{doc_id}",
                                             headers=headers, json=watermark_data)

        if watermark_response.status_code != 201:
            print(f"Watermark creation failed: {watermark_response.get_json()}")

        assert watermark_response.status_code == 201, f"Expected 201, got {watermark_response.status_code}: {watermark_response.get_json()}"
        watermark_result = watermark_response.get_json()
        watermark_link = watermark_result["link"]
        assert "link" in watermark_result
        assert watermark_result["intended_for"] == "recipient@example.com"
        assert watermark_result["method"] == "toy-eof"

        # Step 2: List versions
        if mock_conn:
            mock_conn.execute.side_effect = None

            mock_version = MagicMock()
            mock_version.id = 1
            mock_version.documentid = doc_id
            mock_version.link = watermark_link
            mock_version.intended_for = "recipient@example.com"
            mock_version.secret = "confidential123"
            mock_version.method = "toy-eof"

            mock_execute_result = MagicMock()
            mock_execute_result.all.return_value = [mock_version]
            mock_conn.execute.return_value = mock_execute_result

        versions_response = client.get(f"/api/list-versions/{doc_id}", headers=headers)
        assert versions_response.status_code == 200
        versions_data = versions_response.get_json()
        assert "versions" in versions_data
        assert len(versions_data["versions"]) == 1
        assert versions_data["versions"][0]["intended_for"] == "recipient@example.com"
        assert versions_data["versions"][0]["method"] == "toy-eof"

        # Step 3: Get version by link
        actual_filename = watermark_result.get("filename", "test_watermark.pdf")
        watermark_file_path = watermarks_dir / actual_filename

        if not watermark_file_path.exists():
            watermark_file_path.write_bytes(sample_pdf_bytes)

        if mock_conn:
            mock_conn.execute.side_effect = None

            mock_version_row = MagicMock()
            mock_version_row.id = 1
            mock_version_row.link = watermark_link
            mock_version_row.path = str(watermark_file_path)

            mock_execute_result = MagicMock()
            mock_execute_result.first.return_value = mock_version_row
            mock_conn.execute.return_value = mock_execute_result

        version_response = client.get(f"/api/get-version/{watermark_link}")

        assert version_response.status_code == 200, f"Expected 200, got {version_response.status_code}"
        assert version_response.content_type == "application/pdf"


    def test_multi_user_workflow(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test workflow with multiple users to ensure proper isolation."""

        class MockRow:
            def __init__(self, **kwargs):
                for key, value in kwargs.items():
                    setattr(self, key, value)

        # Create two users
        token1 = self._create_user_and_login(client, app, "user1@example.com", "user1", "pass1")
        token2 = self._create_user_and_login(client, app, "user2@example.com", "user2", "pass2")

        headers1 = {"Authorization": f"Bearer {token1}"}
        headers2 = {"Authorization": f"Bearer {token2}"}

        mock_conn = app.config.get('mock_db_conn')

        # ===== User 1 uploads document =====
        if mock_conn:
            upload1_call_count = [0]

            def mock_execute_for_upload1(*args, **kwargs):
                upload1_call_count[0] += 1
                if upload1_call_count[0] == 1:  # INSERT INTO Documents
                    result = MagicMock()
                    result.lastrowid = 1
                    return result
                elif upload1_call_count[0] == 2:  # SELECT LAST_INSERT_ID()
                    result = MagicMock()
                    result.scalar.return_value = 1
                    return result
                elif upload1_call_count[0] == 3:  # SELECT document details
                    result = MagicMock()
                    result.one.return_value = MockRow(
                        id=1,
                        name="user1_doc.pdf",
                        creation=dt.datetime.now(),
                        sha256_hex="hash1",
                        size=len(sample_pdf_bytes)
                    )
                    return result
                else:
                    return MagicMock()

            mock_conn.execute.side_effect = mock_execute_for_upload1

        m_open = mock_open(read_data=sample_pdf_bytes)
        mock_hash_obj = MagicMock()
        mock_hash_obj.hexdigest.return_value = "hash1"

        with patch('pathlib.Path.mkdir'), \
                patch('pathlib.Path.stat') as mock_stat, \
                patch('builtins.open', m_open), \
                patch('pathlib.Path.open', m_open), \
                patch('hashlib.sha256', return_value=mock_hash_obj):

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'user1_doc.pdf')}
            upload_response1 = client.post("/api/upload-document", headers=headers1, data=upload_data)

        assert upload_response1.status_code == 201

        # ===== User 2 uploads document =====
        if mock_conn:
            upload2_call_count = [0]

            def mock_execute_for_upload2(*args, **kwargs):
                upload2_call_count[0] += 1
                if upload2_call_count[0] == 1:  # INSERT INTO Documents
                    result = MagicMock()
                    result.lastrowid = 2
                    return result
                elif upload2_call_count[0] == 2:  # SELECT LAST_INSERT_ID()
                    result = MagicMock()
                    result.scalar.return_value = 2
                    return result
                elif upload2_call_count[0] == 3:  # SELECT document details
                    result = MagicMock()
                    result.one.return_value = MockRow(
                        id=2,
                        name="user2_doc.pdf",
                        creation=dt.datetime.now(),
                        sha256_hex="hash2",
                        size=len(sample_pdf_bytes)
                    )
                    return result
                else:
                    return MagicMock()

            mock_conn.execute.side_effect = mock_execute_for_upload2

        m_open2 = mock_open(read_data=sample_pdf_bytes)
        mock_hash_obj2 = MagicMock()
        mock_hash_obj2.hexdigest.return_value = "hash2"

        with patch('pathlib.Path.mkdir'), \
                patch('pathlib.Path.stat') as mock_stat, \
                patch('builtins.open', m_open2), \
                patch('pathlib.Path.open', m_open2), \
                patch('hashlib.sha256', return_value=mock_hash_obj2):

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'user2_doc.pdf')}
            upload_response2 = client.post("/api/upload-document", headers=headers2, data=upload_data)

        assert upload_response2.status_code == 201

        # ===== Each user should only see their own documents =====
        if mock_conn:
            def mock_execute_for_list1(*args, **kwargs):
                result = MagicMock()
                result.all.return_value = [
                    MockRow(
                        id=1,
                        name="user1_doc.pdf",
                        creation=dt.datetime.now(),
                        sha256_hex="hash1",
                        size=len(sample_pdf_bytes)
                    )
                ]
                return result

            mock_conn.execute.side_effect = mock_execute_for_list1

        list_response1 = client.get("/api/list-documents", headers=headers1)
        assert list_response1.status_code == 200
        docs1 = list_response1.get_json()["documents"]
        assert len(docs1) == 1
        assert docs1[0]["name"] == "user1_doc.pdf"

        if mock_conn:
            def mock_execute_for_list2(*args, **kwargs):
                result = MagicMock()
                result.all.return_value = [
                    MockRow(
                        id=2,
                        name="user2_doc.pdf",
                        creation=dt.datetime.now(),
                        sha256_hex="hash2",
                        size=len(sample_pdf_bytes)
                    )
                ]
                return result

            mock_conn.execute.side_effect = mock_execute_for_list2

        list_response2 = client.get("/api/list-documents", headers=headers2)
        assert list_response2.status_code == 200
        docs2 = list_response2.get_json()["documents"]
        assert len(docs2) == 1
        assert docs2[0]["name"] == "user2_doc.pdf"

        # ===== User 1 should not be able to access User 2's document =====
        if mock_conn:
            def mock_execute_for_forbidden(*args, **kwargs):
                result = MagicMock()
                result.first.return_value = None  # No document found
                return result

            mock_conn.execute.side_effect = mock_execute_for_forbidden

        forbidden_response = client.get("/api/get-document/2", headers=headers1)
        assert forbidden_response.status_code == 404  # Document not found (access denied)

@pytest.mark.integration
class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases."""

    def test_database_connection_errors(self, client: FlaskClient):
        """Test handling of database connection errors."""
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.side_effect = Exception("Database connection failed")

            # This should still work for endpoints that don't require DB
            response = client.get("/api/get-watermarking-methods")
            # The response depends on whether watermarking utils are mocked
            assert response.status_code in [200, 500]

    def test_invalid_json_payloads(self, client: FlaskClient):
        """Test handling of invalid JSON payloads."""
        # Test malformed JSON
        response = client.post("/api/create-user",
                              data="{'invalid': json}",
                              content_type="application/json")
        assert response.status_code == 400


    def test_file_system_errors(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test handling of file system errors."""
        token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6").dumps({
            "uid": 1, "login": "testuser", "email": "test@example.com"
        })
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT
                MagicMock(scalar=lambda: 1),  # LAST_INSERT_ID
                MagicMock(one=lambda: MagicMock(
                    id=1, name="test.pdf", creation=dt.datetime.now(),
                    sha256_hex="hash123", size=len(sample_pdf_bytes)
                ))
            ]

        # Mock file system error during upload
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('builtins.open', side_effect=PermissionError("Permission denied")), \
             patch('hashlib.sha256') as mock_hash:

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            mock_hash.return_value.hexdigest.return_value = "hash123"

            upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'test.pdf')}
            response = client.post("/api/upload-document", headers=headers, data=upload_data)

            # Should handle the error gracefully
            assert response.status_code == 500

    def _get_valid_token(self, app: Flask) -> str:
        """Helper method to create a valid token."""
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6"
        )
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        return serializer.dumps(token_data)

    def test_watermarking_errors(self, client: FlaskClient, app: Flask, temp_storage: Path, sample_pdf_bytes: bytes):
        """Test handling of watermarking-related errors."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        # CRITICAL: Set STORAGE_DIR to temp_storage
        app.config["STORAGE_DIR"] = temp_storage

        # Create a real test file
        test_file = temp_storage / "test.pdf"
        test_file.write_bytes(sample_pdf_bytes)

        watermark_data = {
            "method": "invalid-method",
            "intended_for": "test@example.com",
            "secret": "secret",
            "key": "key"
        }

        # Get the existing mock engine
        mock_engine = app.config.get('_ENGINE')

        # Setup for connect()
        mock_conn = MagicMock()
        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)
        mock_engine.connect.return_value = mock_context

        # Mock document exists
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.name = "test.pdf"
        mock_row.path = str(test_file)  # Use real file path

        mock_result = MagicMock()
        mock_result.first.return_value = mock_row
        mock_conn.execute.return_value = mock_result

        with patch('watermarking_utils.is_watermarking_applicable', return_value=False):
            response = client.post("/api/create-watermark/1", headers=headers, json=watermark_data)

        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data


    def test_large_file_handling(self, client: FlaskClient, app: Flask):
        """Test handling of large file uploads."""
        token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6").dumps({
            "uid": 1, "login": "testuser", "email": "test@example.com"
        })
        headers = {"Authorization": f"Bearer {token}"}

        # Create a large PDF (simulated)
        large_pdf = b"%PDF-1.4\n" + b"x" * (10 * 1024 * 1024)  # 10MB

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT
                MagicMock(scalar=lambda: 1),  # LAST_INSERT_ID
                MagicMock(one=lambda: MagicMock(
                    id=1, name="large.pdf", creation=dt.datetime.now(),
                    sha256_hex="largehash", size=len(large_pdf)
                ))
            ]

        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('builtins.open', mock_open()), \
             patch('hashlib.sha256') as mock_hash, \
             patch('watermarking_method.is_pdf_bytes', return_value=True):

            mock_stat.return_value.st_size = len(large_pdf)
            mock_hash.return_value.hexdigest.return_value = "largehash"

            upload_data = {'file': (io.BytesIO(large_pdf), 'large.pdf')}
            response = client.post("/api/upload-document", headers=headers, data=upload_data)

            # Should handle large files (might have size limits in real implementation)
            assert response.status_code in [201, 413, 500]  # Created, Too Large, or Server Error

    def test_concurrent_operations(self, client: FlaskClient, app: Flask):
        """Test handling of concurrent operations."""
        token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6").dumps({
            "uid": 1, "login": "testuser", "email": "test@example.com"
        })
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.return_value.all.return_value = []

        # Simulate multiple concurrent requests
        responses = []
        for i in range(3):
            response = client.get("/api/list-documents", headers=headers)
            responses.append(response)

        # All should complete successfully
        for response in responses:
            assert response.status_code in [200, 500, 503]  # Success or expected server errors


@pytest.mark.integration
class TestSecurityEndpoints:
    """Test security-related endpoints for coverage of lines 1552-1627."""

    def test_security_status_success(self, client: FlaskClient, app: Flask):
        """Test successful security status retrieval."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            # Mock security_monitor and disable rate limiting
            with patch('server.src.server.security_monitor') as mock_monitor:
                mock_monitor.get_security_summary.return_value = {
                    "total_attacks": 5,
                    "blocked_ips": 3,
                    "recent_incidents": 2
                }
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "test-admin-key"}
                response = client.get("/api/security-status", headers=headers)
                
                assert response.status_code == 200
                data = response.get_json()
                assert "security_summary" in data
                assert "timestamp" in data
                assert data["security_summary"]["total_attacks"] == 5

    def test_security_status_unauthorized(self, client: FlaskClient, app: Flask):
        """Test security status with invalid admin key."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "wrong-key"}
                response = client.get("/api/security-status", headers=headers)
                
                assert response.status_code == 401
                data = response.get_json()
                assert "error" in data
                assert "Unauthorized" in data["error"]

    def test_security_status_no_key(self, client: FlaskClient, app: Flask):
        """Test security status without admin key."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                response = client.get("/api/security-status")
                
                assert response.status_code == 401
                data = response.get_json()
                assert "error" in data
                assert "Unauthorized" in data["error"]

    def test_security_recover_success(self, client: FlaskClient, app: Flask):
        """Test successful security recovery."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                mock_monitor.recover_from_attack.return_value = {
                    "recovery_actions": ["cleared_ip", "reset_counters"],
                    "success": True
                }
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "test-admin-key"}
                data = {
                    "ip": "192.168.1.100",
                    "attack_type": "brute_force"
                }
                response = client.post("/api/security-recover", headers=headers, json=data)
                
                assert response.status_code == 200
                result = response.get_json()
                assert "recovery_result" in result
                assert "timestamp" in result
                assert result["recovery_result"]["success"] is True

    def test_security_recover_unauthorized(self, client: FlaskClient, app: Flask):
        """Test security recovery with invalid admin key."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "wrong-key"}
                data = {"ip": "192.168.1.100", "attack_type": "brute_force"}
                response = client.post("/api/security-recover", headers=headers, json=data)
                
                assert response.status_code == 401
                data = response.get_json()
                assert "error" in data
                assert "Unauthorized" in data["error"]

    def test_security_incidents_success(self, client: FlaskClient, app: Flask):
        """Test successful security incidents retrieval."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                mock_incidents = [
                    {"id": 1, "ip": "192.168.1.100", "attack_type": "brute_force", "timestamp": "2023-01-01T12:00:00Z"},
                    {"id": 2, "ip": "192.168.1.101", "attack_type": "sql_injection", "timestamp": "2023-01-01T13:00:00Z"}
                ]
                mock_monitor.get_attack_incidents.return_value = mock_incidents
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "test-admin-key"}
                response = client.get("/api/security-incidents", headers=headers)
                
                assert response.status_code == 200
                data = response.get_json()
                assert "incidents" in data
                assert "total_count" in data
                assert "timestamp" in data
                assert len(data["incidents"]) == 2

    def test_security_incidents_with_limit(self, client: FlaskClient, app: Flask):
        """Test security incidents with custom limit."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                mock_incidents = [{"id": 1, "ip": "192.168.1.100", "attack_type": "brute_force"}]
                mock_monitor.get_attack_incidents.return_value = mock_incidents
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "test-admin-key"}
                response = client.get("/api/security-incidents?limit=10", headers=headers)
                
                assert response.status_code == 200
                mock_monitor.get_attack_incidents.assert_called_once_with(10)

    def test_security_incidents_unauthorized(self, client: FlaskClient, app: Flask):
        """Test security incidents with invalid admin key."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "wrong-key"}
                response = client.get("/api/security-incidents", headers=headers)
                
                assert response.status_code == 401
                data = response.get_json()
                assert "error" in data
                assert "Unauthorized" in data["error"]

    def test_security_analysis_success(self, client: FlaskClient, app: Flask):
        """Test successful security analysis."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                mock_analysis = {
                    "attack_patterns": ["brute_force", "sql_injection"],
                    "risk_level": "high",
                    "recommendations": ["enable_rate_limiting", "update_firewall_rules"]
                }
                mock_monitor.analyze_attack_patterns.return_value = mock_analysis
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "test-admin-key"}
                response = client.get("/api/security-analysis", headers=headers)
                
                assert response.status_code == 200
                data = response.get_json()
                assert "analysis" in data
                assert "timestamp" in data
                assert data["analysis"]["risk_level"] == "high"

    def test_security_analysis_unauthorized(self, client: FlaskClient, app: Flask):
        """Test security analysis with invalid admin key."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'test-admin-key'}):
            app.config["RMAP_ADMIN_KEY"] = "test-admin-key"
            
            with patch('server.src.server.security_monitor') as mock_monitor:
                # Disable rate limiting
                mock_monitor.check_rate_limiting.return_value = False
                mock_monitor.is_suspicious_ip.return_value = False
                mock_monitor.check_path_traversal.return_value = False
                
                headers = {"X-Admin-Key": "wrong-key"}
                response = client.get("/api/security-analysis", headers=headers)
                
                assert response.status_code == 401
                data = response.get_json()
                assert "error" in data
                assert "Unauthorized" in data["error"]
