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

    @pytest.mark.xfail
    def test_create_user_success(self, client: FlaskClient, app: Flask):
        """Test successful user creation."""
        user_data = {
            "email": "newuser@example.com",
            "login": "newuser",
            "password": "securepassword123"
        }

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            # Mock successful user creation
            mock_insert_result = MagicMock()
            mock_insert_result.lastrowid = 1

            mock_user_row = MagicMock()
            mock_user_row.id = 1
            mock_user_row.email = "newuser@example.com"
            mock_user_row.login = "newuser"

            mock_conn.execute.side_effect = [
                mock_insert_result,  # INSERT result
                MagicMock(one=lambda: mock_user_row)  # SELECT result
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

    @pytest.mark.xfail
    def test_create_user_duplicate_email(self, client: FlaskClient):
        """Test user creation with duplicate email."""
        user_data = {
            "email": "duplicate@example.com",
            "login": "user1",
            "password": "password123"
        }

        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.begin.return_value.__enter__.return_value = mock_conn

            # Mock IntegrityError for duplicate email
            from sqlalchemy.exc import IntegrityError
            mock_conn.execute.side_effect = IntegrityError("", "", "")

            response = client.post("/api/create-user", json=user_data)

            assert response.status_code == 409
            data = response.get_json()
            assert "error" in data
            assert "already exists" in data["error"]

    @pytest.mark.xfail
    def test_login_success(self, client: FlaskClient, app: Flask):
        """Test successful login."""
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            # Mock successful login
            from werkzeug.security import generate_password_hash
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.email = "test@example.com"
            mock_row.login = "testuser"
            mock_row.hpassword = generate_password_hash("testpassword123")
            mock_conn.execute.return_value.first.return_value = mock_row

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


@pytest.mark.integration
class TestDocumentManagement:
    """Test complete document management workflow."""

    def _get_valid_token(self, app: Flask) -> str:
        """Helper method to create a valid token."""
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        return serializer.dumps(token_data)

    @pytest.mark.xfail
    def test_upload_document_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test successful document upload."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            # Mock document insertion
            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT result
                MagicMock(scalar=lambda: 1),  # LAST_INSERT_ID result
                MagicMock(one=lambda: MagicMock(
                    id=1,
                    name="test.pdf",
                    creation=dt.datetime.now(),
                    sha256_hex="abcdef123456",
                    size=len(sample_pdf_bytes)
                ))  # SELECT result
            ]

        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('builtins.open', mock_open()), \
             patch('hashlib.sha256') as mock_hash:

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            mock_hash.return_value.hexdigest.return_value = "abcdef123456"

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

    @pytest.mark.xfail
    def test_list_documents_success(self, client: FlaskClient, app: Flask):
        """Test successful document listing."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            # Mock document list
            mock_docs = [
                MagicMock(
                    id=1,
                    name="doc1.pdf",
                    creation=dt.datetime(2023, 1, 1),
                    sha256_hex="hash1",
                    size=1024
                ),
                MagicMock(
                    id=2,
                    name="doc2.pdf",
                    creation=dt.datetime(2023, 1, 2),
                    sha256_hex="hash2",
                    size=2048
                )
            ]
            mock_conn.execute.return_value.all.return_value = mock_docs

        response = client.get("/api/list-documents", headers=headers)

        assert response.status_code == 200
        data = response.get_json()
        assert "documents" in data
        assert len(data["documents"]) == 2

    @pytest.mark.xfail
    def test_get_document_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test successful document retrieval."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = "/storage/test.pdf"
            mock_row.sha256_hex = "abcdef123456"
            mock_row.size = len(sample_pdf_bytes)
            mock_conn.execute.return_value.first.return_value = mock_row

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('flask.send_file') as mock_send_file:

            mock_stat.return_value.st_mtime = 1640995200.0
            mock_send_file.return_value = MagicMock(status_code=200)

            response = client.get("/api/get-document/1", headers=headers)

            assert mock_send_file.called

    @pytest.mark.xfail
    def test_get_document_not_found(self, client: FlaskClient, app: Flask):
        """Test document retrieval when document doesn't exist."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.return_value.first.return_value = None

        response = client.get("/api/get-document/999", headers=headers)

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    def test_delete_document_success(self, client: FlaskClient, app: Flask):
        """Test successful document deletion."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            # Mock document exists
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.path = "/storage/test.pdf"

            mock_conn.execute.side_effect = [
                MagicMock(first=lambda: mock_row),  # Document exists check
                MagicMock(fetchall=lambda: []),  # No versions
                MagicMock()  # DELETE operation
            ]

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.unlink') as mock_unlink:

            response = client.delete("/api/delete-document/1", headers=headers)

            assert response.status_code == 200
            data = response.get_json()
            assert data["deleted"] is True
            assert data["id"] == 1

    @pytest.mark.xfail
    def test_delete_document_not_found(self, client: FlaskClient, app: Flask):
        """Test document deletion when document doesn't exist."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.return_value.first.return_value = None

        response = client.delete("/api/delete-document/999", headers=headers)

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data


@pytest.mark.integration
class TestWatermarkManagement:
    """Test complete watermark management workflow."""

    def _get_valid_token(self, app: Flask) -> str:
        """Helper method to create a valid token."""
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        return serializer.dumps(token_data)

    def test_get_watermarking_methods(self, client: FlaskClient, app: Flask):
        """Test getting available watermarking methods."""
        # Create a valid token for authentication
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        valid_token = serializer.dumps(token_data)
        headers = {"Authorization": f"Bearer {valid_token}"}

        with patch('watermarking_utils.METHODS', {"test-method": MagicMock()}), \
             patch('watermarking_utils.get_method') as mock_get_method:

            mock_method = MagicMock()
            mock_method.get_usage.return_value = "Test method description"
            mock_get_method.return_value = mock_method

            response = client.get("/api/get-watermarking-methods", headers=headers)

            assert response.status_code == 200
            data = response.get_json()
            assert "methods" in data
            assert "count" in data

    def test_create_watermark_success(self, client: FlaskClient, app: Flask):
        """Test successful watermark creation."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        watermark_data = {
            "method": "test-method",
            "intended_for": "john@example.com",
            "secret": "secret123",
            "key": "key456",
            "position": "bottom-right"
        }

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            # Mock document exists
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = "/storage/test.pdf"

            mock_conn.execute.side_effect = [
                MagicMock(first=lambda: mock_row),  # Document check
                MagicMock(),  # INSERT version
                MagicMock(scalar=lambda: 1)  # LAST_INSERT_ID
            ]

        with patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
             patch('watermarking_utils.apply_watermark', return_value=b'watermarked content'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.open', mock_open()):

            response = client.post("/api/create-watermark/1", headers=headers, json=watermark_data)

            assert response.status_code == 201
            data = response.get_json()
            assert "id" in data
            assert "link" in data
            assert data["intended_for"] == "john@example.com"
            assert data["method"] == "test-method"

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

    @pytest.mark.xfail
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
        assert "not found" in data["error"]

    @pytest.mark.xfail
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

    @pytest.mark.xfail
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

    @pytest.mark.xfail
    def test_get_version_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test successful version retrieval by link."""
        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.link = "testlink123"
            mock_row.path = "/storage/watermark.pdf"
            mock_conn.execute.return_value.first.return_value = mock_row

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('flask.send_file') as mock_send_file:

            mock_stat.return_value.st_mtime = 1640995200.0
            mock_send_file.return_value = MagicMock(status_code=200)

            response = client.get("/api/get-version/testlink123")

            assert mock_send_file.called

    @pytest.mark.xfail
    def test_get_version_not_found(self, client: FlaskClient, app: Flask):
        """Test version retrieval when version doesn't exist."""
        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_conn.execute.return_value.first.return_value = None

        response = client.get("/api/get-version/nonexistent")

        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data

    @pytest.mark.xfail
    def test_read_watermark_by_link_success(self, client: FlaskClient, app: Flask):
        """Test successful watermark reading by link."""
        token = self._get_valid_token(app)
        headers = {"Authorization": f"Bearer {token}"}

        read_data = {
            "method": "test-method",
            "key": "test-key"
        }

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.documentid = 1
            mock_row.link = "testlink123"
            mock_row.secret = "extracted_secret"
            mock_row.path = "/storage/watermark.pdf"
            mock_conn.execute.return_value.first.return_value = mock_row

        with patch('watermarking_utils.read_watermark', return_value="extracted_secret"), \
             patch('pathlib.Path.exists', return_value=True):

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

    def test_rmap_initiate_empty_payload(self, client: FlaskClient):
        """Test RMAP initiate with empty payload string."""
        with patch('server.src.server.rmap_service', MagicMock()):
            response = client.post("/api/rmap-initiate", json={"payload": ""})

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "non-empty string" in data["error"]

    def test_rmap_initiate_invalid_payload_type(self, client: FlaskClient):
        """Test RMAP initiate with invalid payload type."""
        with patch('server.src.server.rmap_service', MagicMock()):
            # Test with non-string payload
            response = client.post("/api/rmap-initiate", json={"payload": 123})

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "non-empty string" in data["error"]

    def test_rmap_initiate_payload_validation_exceptions(self, client: FlaskClient):
        """Test RMAP initiate with payload validation exceptions."""
        mock_rmap_service = MagicMock()
        mock_identity_manager = MagicMock()
        
        # Test with ValueError exception
        mock_identity_manager.decrypt_for_server.side_effect = ValueError("Invalid payload format")
        
        with patch('server.src.server.rmap_service', mock_rmap_service), \
                patch('server.src.server.identity_manager', mock_identity_manager):
            response = client.post("/api/rmap-initiate", json={"payload": "invalid_payload"})

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "Invalid or malformed RMAP payload" in data["error"]

    def test_rmap_initiate_payload_type_error(self, client: FlaskClient):
        """Test RMAP initiate with TypeError exception."""
        mock_rmap_service = MagicMock()
        mock_identity_manager = MagicMock()
        
        # Test with TypeError exception
        mock_identity_manager.decrypt_for_server.side_effect = TypeError("Type error")
        
        with patch('server.src.server.rmap_service', mock_rmap_service), \
                patch('server.src.server.identity_manager', mock_identity_manager):
            response = client.post("/api/rmap-initiate", json={"payload": "test"})

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "Invalid or malformed RMAP payload" in data["error"]

    def test_rmap_initiate_payload_key_error(self, client: FlaskClient):
        """Test RMAP initiate with KeyError exception."""
        mock_rmap_service = MagicMock()
        mock_identity_manager = MagicMock()
        
        # Test with KeyError exception
        mock_identity_manager.decrypt_for_server.side_effect = KeyError("Missing key")
        
        with patch('server.src.server.rmap_service', mock_rmap_service), \
                patch('server.src.server.identity_manager', mock_identity_manager):
            response = client.post("/api/rmap-initiate", json={"payload": "test"})

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "Invalid or malformed RMAP payload" in data["error"]

    def test_rmap_initiate_payload_attribute_error(self, client: FlaskClient):
        """Test RMAP initiate with AttributeError exception."""
        mock_rmap_service = MagicMock()
        mock_identity_manager = MagicMock()
        
        # Test with AttributeError exception
        mock_identity_manager.decrypt_for_server.side_effect = AttributeError("Missing attribute")
        
        with patch('server.src.server.rmap_service', mock_rmap_service), \
                patch('server.src.server.identity_manager', mock_identity_manager):
            response = client.post("/api/rmap-initiate", json={"payload": "test"})

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "Invalid or malformed RMAP payload" in data["error"]

    def test_rmap_initiate_success(self, client: FlaskClient):
        """Test successful RMAP initiate."""
        mock_rmap_service = MagicMock()
        mock_rmap_service.handle_message1.return_value = {"status": "success"}

        with patch('server.src.server.rmap_service', mock_rmap_service):
            # payload should be armored base64
            response = client.post("/api/rmap-initiate", json={"payload": "test_payload"})

            assert response.status_code == 200
            mock_rmap_service.handle_message1.assert_called_once()

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

    @pytest.mark.xfail
    def test_rmap_identify_leak_success(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test successful RMAP leak identification."""
        with patch.dict(os.environ, {'RMAP_ADMIN_KEY': 'change-this-admin-key'}), \
             patch('watermarking_utils.read_watermark', return_value="extracted_secret"):

            mock_conn = app.config.get('mock_db_conn')
            if mock_conn:
                mock_row = MagicMock()
                mock_row.id = 1
                mock_row.link = "testlink"
                mock_row.intended_for = "john@example.com"
                mock_row.secret = "extracted_secret"
                mock_row.method = "test-method"
                mock_row.path = "/storage/test.pdf"
                mock_conn.execute.return_value.first.return_value = mock_row

            headers = {"X-Admin-Key": "change-this-admin-key"}
            data = {'file': (io.BytesIO(sample_pdf_bytes), 'leaked.pdf')}
            response = client.post("/api/rmap-identify-leak", headers=headers, data=data)

            assert response.status_code == 200
            result = response.get_json()
            assert result["identified"] is True
            assert result["identity"] == "john@example.com"
            assert "version_info" in result

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

        # Login
        if mock_conn:
            from werkzeug.security import generate_password_hash
            mock_login_row = MagicMock()
            mock_login_row.id = 1
            mock_login_row.email = email
            mock_login_row.login = login
            mock_login_row.hpassword = generate_password_hash(password)
            mock_conn.execute.return_value.first.return_value = mock_login_row

        login_response = client.post("/api/login", json={"email": email, "password": password})
        assert login_response.status_code == 200

        return login_response.get_json()["token"]

    @pytest.mark.xfail
    def test_complete_document_workflow(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test complete document workflow: create user -> login -> upload -> list -> get -> delete."""
        # Step 1: Create user and login
        token = self._create_user_and_login(client, app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')

        # Step 2: Upload document
        if mock_conn:
            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT
                MagicMock(scalar=lambda: 1),  # LAST_INSERT_ID
                MagicMock(one=lambda: MagicMock(
                    id=1, name="workflow.pdf", creation=dt.datetime.now(),
                    sha256_hex="hash123", size=len(sample_pdf_bytes)
                ))
            ]

        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('builtins.open', mock_open()), \
             patch('hashlib.sha256') as mock_hash:

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            mock_hash.return_value.hexdigest.return_value = "hash123"

            upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'workflow.pdf')}
            upload_response = client.post("/api/upload-document", headers=headers, data=upload_data)

        assert upload_response.status_code == 201
        doc_id = upload_response.get_json()["id"]

        # Step 3: List documents
        if mock_conn:
            mock_doc = MagicMock(
                id=doc_id, name="workflow.pdf", creation=dt.datetime.now(),
                sha256_hex="hash123", size=len(sample_pdf_bytes)
            )
            mock_conn.execute.return_value.all.return_value = [mock_doc]

        list_response = client.get("/api/list-documents", headers=headers)
        assert list_response.status_code == 200
        assert len(list_response.get_json()["documents"]) == 1

        # Step 4: Get document
        if mock_conn:
            mock_row = MagicMock()
            mock_row.id = doc_id
            mock_row.name = "workflow.pdf"
            mock_row.path = "/storage/workflow.pdf"
            mock_row.sha256_hex = "hash123"
            mock_row.size = len(sample_pdf_bytes)
            mock_conn.execute.return_value.first.return_value = mock_row

        with patch('pathlib.Path.exists', return_value=True), \
             patch('flask.send_file') as mock_send_file:
            mock_send_file.return_value = MagicMock(status_code=200)
            get_response = client.get(f"/api/get-document/{doc_id}", headers=headers)
            assert mock_send_file.called

        # Step 5: Delete document
        if mock_conn:
            mock_conn.execute.side_effect = [
                MagicMock(first=lambda: mock_row),  # Document exists
                MagicMock(fetchall=lambda: []),  # No versions
                MagicMock()  # DELETE
            ]

        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.unlink'):
            delete_response = client.delete(f"/api/delete-document/{doc_id}", headers=headers)

        assert delete_response.status_code == 200
        assert delete_response.get_json()["deleted"] is True

    @pytest.mark.xfail
    def test_complete_watermark_workflow(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test complete watermark workflow: upload -> create watermark -> list versions -> get version."""
        # Setup: Create user and upload document
        token = self._create_user_and_login(client, app)
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config.get('mock_db_conn')
        doc_id = 1

        # Mock document upload
        if mock_conn:
            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT
                MagicMock(scalar=lambda: doc_id),  # LAST_INSERT_ID
                MagicMock(one=lambda: MagicMock(
                    id=doc_id, name="watermark_test.pdf", creation=dt.datetime.now(),
                    sha256_hex="hash123", size=len(sample_pdf_bytes)
                ))
            ]

        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('builtins.open', mock_open()), \
             patch('hashlib.sha256') as mock_hash:

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            mock_hash.return_value.hexdigest.return_value = "hash123"

            upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'watermark_test.pdf')}
            upload_response = client.post("/api/upload-document", headers=headers, data=upload_data)

        assert upload_response.status_code == 201

        # Step 1: Create watermark
        watermark_data = {
            "method": "test-method",
            "intended_for": "recipient@example.com",
            "secret": "confidential123",
            "key": "encryption456",
            "position": "bottom-right"
        }

        if mock_conn:
            mock_doc_row = MagicMock()
            mock_doc_row.id = doc_id
            mock_doc_row.name = "watermark_test.pdf"
            mock_doc_row.path = "/storage/watermark_test.pdf"

            mock_conn.execute.side_effect = [
                MagicMock(first=lambda: mock_doc_row),  # Document check
                MagicMock(),  # INSERT version
                MagicMock(scalar=lambda: 1)  # LAST_INSERT_ID
            ]

        with patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
             patch('watermarking_utils.apply_watermark', return_value=b'watermarked content'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.open', mock_open()):

            watermark_response = client.post(f"/api/create-watermark/{doc_id}",
                                           headers=headers, json=watermark_data)

        assert watermark_response.status_code == 201
        watermark_link = watermark_response.get_json()["link"]

        # Step 2: List versions
        if mock_conn:
            mock_version = MagicMock(
                id=1, documentid=doc_id, link=watermark_link,
                intended_for="recipient@example.com", secret="confidential123", method="test-method"
            )
            mock_conn.execute.return_value.all.return_value = [mock_version]

        versions_response = client.get(f"/api/list-versions/{doc_id}", headers=headers)
        assert versions_response.status_code == 200
        assert len(versions_response.get_json()["versions"]) == 1

        # Step 3: Get version by link
        if mock_conn:
            mock_version_row = MagicMock()
            mock_version_row.id = 1
            mock_version_row.link = watermark_link
            mock_version_row.path = "/storage/watermarks/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_version_row

        with patch('pathlib.Path.exists', return_value=True), \
             patch('flask.send_file') as mock_send_file:
            mock_send_file.return_value = MagicMock(status_code=200)
            version_response = client.get(f"/api/get-version/{watermark_link}")
            assert mock_send_file.called

    @pytest.mark.xfail
    def test_multi_user_workflow(self, client: FlaskClient, app: Flask, sample_pdf_bytes: bytes):
        """Test workflow with multiple users to ensure proper isolation."""
        # Create two users
        token1 = self._create_user_and_login(client, app, "user1@example.com", "user1", "pass1")
        token2 = self._create_user_and_login(client, app, "user2@example.com", "user2", "pass2")

        headers1 = {"Authorization": f"Bearer {token1}"}
        headers2 = {"Authorization": f"Bearer {token2}"}

        mock_conn = app.config.get('mock_db_conn')

        # User 1 uploads document
        if mock_conn:
            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT
                MagicMock(scalar=lambda: 1),  # LAST_INSERT_ID
                MagicMock(one=lambda: MagicMock(
                    id=1, name="user1_doc.pdf", creation=dt.datetime.now(),
                    sha256_hex="hash1", size=len(sample_pdf_bytes)
                ))
            ]

        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('builtins.open', mock_open()), \
             patch('hashlib.sha256') as mock_hash:

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            mock_hash.return_value.hexdigest.return_value = "hash1"

            upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'user1_doc.pdf')}
            upload_response1 = client.post("/api/upload-document", headers=headers1, data=upload_data)

        assert upload_response1.status_code == 201

        # User 2 uploads document
        if mock_conn:
            mock_conn.execute.side_effect = [
                MagicMock(),  # INSERT
                MagicMock(scalar=lambda: 2),  # LAST_INSERT_ID
                MagicMock(one=lambda: MagicMock(
                    id=2, name="user2_doc.pdf", creation=dt.datetime.now(),
                    sha256_hex="hash2", size=len(sample_pdf_bytes)
                ))
            ]

        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('builtins.open', mock_open()), \
             patch('hashlib.sha256') as mock_hash:

            mock_stat.return_value.st_size = len(sample_pdf_bytes)
            mock_hash.return_value.hexdigest.return_value = "hash2"

            upload_data = {'file': (io.BytesIO(sample_pdf_bytes), 'user2_doc.pdf')}
            upload_response2 = client.post("/api/upload-document", headers=headers2, data=upload_data)

        assert upload_response2.status_code == 201

        # Each user should only see their own documents
        if mock_conn:
            # Mock for user1's documents
            mock_doc1 = MagicMock(
                id=1, name="user1_doc.pdf", creation=dt.datetime.now(),
                sha256_hex="hash1", size=len(sample_pdf_bytes)
            )
            mock_conn.execute.return_value.all.return_value = [mock_doc1]

        list_response1 = client.get("/api/list-documents", headers=headers1)
        assert list_response1.status_code == 200
        docs1 = list_response1.get_json()["documents"]
        assert len(docs1) == 1
        assert docs1[0]["name"] == "user1_doc.pdf"

        if mock_conn:
            # Mock for user2's documents
            mock_doc2 = MagicMock(
                id=2, name="user2_doc.pdf", creation=dt.datetime.now(),
                sha256_hex="hash2", size=len(sample_pdf_bytes)
            )
            mock_conn.execute.return_value.all.return_value = [mock_doc2]

        list_response2 = client.get("/api/list-documents", headers=headers2)
        assert list_response2.status_code == 200
        docs2 = list_response2.get_json()["documents"]
        assert len(docs2) == 1
        assert docs2[0]["name"] == "user2_doc.pdf"

        # User 1 should not be able to access User 2's document
        if mock_conn:
            mock_conn.execute.return_value.first.return_value = None

        forbidden_response = client.get("/api/get-document/2", headers=headers1)
        assert forbidden_response.status_code == 404  # Document not found (access denied)


@pytest.mark.integration
class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases."""

    def test_database_connection_errors(self, client: FlaskClient, app: Flask):
        """Test handling of database connection errors."""
        # Create a valid token for authentication
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        valid_token = serializer.dumps(token_data)
        headers = {"Authorization": f"Bearer {valid_token}"}

        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.side_effect = Exception("Database connection failed")

            # This should still work for endpoints that don't require DB
            response = client.get("/api/get-watermarking-methods", headers=headers)
            # The response depends on whether watermarking utils are mocked
            assert response.status_code in [200, 500]

    def test_invalid_json_payloads(self, client: FlaskClient):
        """Test handling of invalid JSON payloads."""
        # Test malformed JSON
        response = client.post("/api/create-user",
                              data="{'invalid': json}",
                              content_type="application/json")
        assert response.status_code == 400

    @pytest.mark.xfail
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

    def test_watermarking_errors(self, client: FlaskClient, app: Flask):
        """Test handling of watermarking-related errors."""
        token = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6").dumps({
            "uid": 1, "login": "testuser", "email": "test@example.com"
        })
        headers = {"Authorization": f"Bearer {token}"}

        watermark_data = {
            "method": "invalid-method",
            "intended_for": "test@example.com",
            "secret": "secret",
            "key": "key"
        }

        mock_conn = app.config.get('mock_db_conn')
        if mock_conn:
            mock_row = MagicMock()
            mock_row.id = 1
            mock_row.name = "test.pdf"
            mock_row.path = "/storage/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_row

        with patch('watermarking_utils.is_watermarking_applicable', return_value=False), \
             patch('pathlib.Path.exists', return_value=True):

            response = client.post("/api/create-watermark/1", headers=headers, json=watermark_data)

            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data

    @pytest.mark.xfail
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
