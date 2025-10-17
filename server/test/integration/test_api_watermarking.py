"""Integration tests for watermarking endpoints.

This module tests the complete watermarking functionality including creating
watermarks, reading watermarks, and version management.
"""

import io
import json
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import pytest
from flask import Flask
from flask.testing import FlaskClient


@pytest.mark.integration
class TestWatermarkingFunctionality:
    """Test watermarking functionality."""
    
    def test_create_watermark_success(self, client: FlaskClient, app: Flask):
        """Test successful watermark creation."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456",
            "position": "bottom-right"
        }
        
        test_pdf_content = b"%PDF-1.4\noriginal content\n%%EOF"
        watermarked_content = b"%PDF-1.4\noriginal content\nwatermarked\n%%EOF"
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.is_absolute', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.open', mock_open()) as mock_file, \
             patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
             patch('watermarking_utils.apply_watermark', return_value=watermarked_content):
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.begin.return_value.__enter__.return_value = mock_conn
            
            # Mock document lookup
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "files/testuser/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            
            # Mock version creation
            mock_conn.execute.side_effect = [
                mock_doc,  # Document lookup
                None,  # INSERT version
                MagicMock(scalar=lambda: 1)  # LAST_INSERT_ID
            ]
            
            response = client.post("/api/create-watermark/1", 
                                 json=watermark_data, 
                                 headers=headers)
            
            assert response.status_code == 201
            result = response.get_json()
            assert result["id"] == 1
            assert result["documentid"] == 1
            assert result["intended_for"] == "john.doe@example.com"
            assert result["method"] == "add-after-eof"

    def test_create_watermark_without_auth(self, client: FlaskClient):
        """Test create_watermark without authentication."""
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        response = client.post("/api/create-watermark/1", json=watermark_data)
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
        assert "Authorization" in result["error"]

    def test_create_watermark_invalid_document_id(self, client: FlaskClient):
        """Test create_watermark with invalid document ID validation."""
        from itsdangerous import URLSafeTimedSerializer
        
        serializer = URLSafeTimedSerializer(
            "test-secret-key",
            salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        test_cases = [
            # Test with document_id = 0 (should be rejected)
            ("/api/create-watermark/0", "document_id must be a positive integer"),
            # Test with negative document_id
            ("/api/create-watermark/-1", "document_id must be a positive integer"),
            # Test with non-numeric document_id
            ("/api/create-watermark/abc", "document_id (int) is required"),
            # Test with missing document_id
            ("/api/create-watermark", "document id required"),
        ]
        
        for endpoint, expected_error in test_cases:
            response = client.post(endpoint, json=watermark_data, headers=headers)
            assert response.status_code == 400, f"Failed for endpoint: {endpoint}"
            result = response.get_json()
            assert "error" in result
            assert expected_error in result["error"]

    def test_create_watermark_invalid_document_id_in_json(self, client: FlaskClient):
        """Test create_watermark with invalid document ID in JSON payload."""
        from itsdangerous import URLSafeTimedSerializer
        
        serializer = URLSafeTimedSerializer(
            "test-secret-key",
            salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        test_cases = [
            # Test with id = 0 in JSON
            {
                "id": 0,
                "method": "add-after-eof",
                "intended_for": "john.doe@example.com",
                "secret": "confidential-info-123",
                "key": "encryption-key-456"
            },
            # Test with negative id in JSON
            {
                "id": -5,
                "method": "add-after-eof",
                "intended_for": "john.doe@example.com",
                "secret": "confidential-info-123",
                "key": "encryption-key-456"
            },
            # Test with non-numeric id in JSON
            {
                "id": "invalid",
                "method": "add-after-eof",
                "intended_for": "john.doe@example.com",
                "secret": "confidential-info-123",
                "key": "encryption-key-456"
            }
        ]
        
        for watermark_data in test_cases:
            response = client.post("/api/create-watermark", json=watermark_data, headers=headers)
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "positive integer" in result["error"] or "int" in result["error"]

    def test_create_watermark_expired_token(self, client: FlaskClient, app: Flask):
        """Test create_watermark with expired token."""
        from itsdangerous import URLSafeTimedSerializer
        import time
        
        # Create an expired token
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6"
        )
        
        # Create token that's already expired
        with patch('time.time', return_value=time.time() - 3700):  # 1 hour + 1 minute ago
            expired_token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        
        headers = {"Authorization": f"Bearer {expired_token}"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        response = client.post("/api/create-watermark/1", json=watermark_data, headers=headers)
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
        assert "expired" in result["error"].lower()

    def test_create_watermark_invalid_token(self, client: FlaskClient):
        """Test create_watermark with invalid token."""
        headers = {"Authorization": "Bearer invalid_token"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        response = client.post("/api/create-watermark/1", json=watermark_data, headers=headers)
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
        assert "Invalid token" in result["error"]

    def test_create_watermark_missing_bearer(self, client: FlaskClient):
        """Test create_watermark with missing Bearer prefix."""
        headers = {"Authorization": "invalid_token"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        response = client.post("/api/create-watermark/1", json=watermark_data, headers=headers)
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
        assert "Authorization header" in result["error"]

    def test_get_watermarking_methods_without_auth(self, client: FlaskClient):
        """Test get_watermarking_methods without authentication."""
        response = client.get("/api/get-watermarking-methods")
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
        assert "Authorization" in result["error"]

    def test_get_watermarking_methods_with_auth(self, client: FlaskClient, app: Flask):
        """Test get_watermarking_methods with valid authentication."""
        from itsdangerous import URLSafeTimedSerializer
        
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('watermarking_utils.METHODS', {'method1': MagicMock(), 'method2': MagicMock()}), \
             patch('watermarking_utils.get_method') as mock_get_method:
            
            mock_method1 = MagicMock()
            mock_method1.get_usage.return_value = "Method 1 description"
            mock_method2 = MagicMock()
            mock_method2.get_usage.return_value = "Method 2 description"
            
            mock_get_method.side_effect = [mock_method1, mock_method2]
            
            response = client.get("/api/get-watermarking-methods", headers=headers)
            
            assert response.status_code == 200
            result = response.get_json()
            assert "methods" in result
            assert "count" in result
            assert result["count"] == 2
            assert len(result["methods"]) == 2

    def test_create_watermark_no_auth(self, client: FlaskClient):
        """Test watermark creation without authentication."""
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        response = client.post("/api/create-watermark/1", json=watermark_data)
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
    
    def test_create_watermark_missing_fields(self, client: FlaskClient, app: Flask):
        """Test watermark creation with missing required fields."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        test_cases = [
            {},  # Empty payload
            {"method": "add-after-eof"},  # Missing other fields
            {"intended_for": "test@example.com"},  # Missing method
            {"secret": "secret123"},  # Missing method and intended_for
            {"key": "key123"},  # Missing other fields
            {
                "method": "add-after-eof",
                "intended_for": "test@example.com",
                "secret": "secret123"
                # Missing key
            },
            {
                "method": "add-after-eof",
                "intended_for": "test@example.com",
                "key": "key123"
                # Missing secret
            }
        ]
        
        for watermark_data in test_cases:
            response = client.post("/api/create-watermark/1", 
                                 json=watermark_data, 
                                 headers=headers)
            
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "required" in result["error"]
    
    def test_create_watermark_document_not_found(self, client: FlaskClient, app: Flask):
        """Test watermark creation for non-existent document."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        # Use the mock engine from conftest.py
        mock_engine = app.config['mock_db_engine']
        mock_conn = app.config['mock_db_conn']
        
        # Reset mock state completely
        mock_conn.reset_mock()
        mock_engine.reset_mock()
        
        # Mock document not found
        mock_conn.execute.return_value.first.return_value = None
        
        response = client.post("/api/create-watermark/999", 
                             json=watermark_data, 
                             headers=headers)
        
        assert response.status_code == 404
        result = response.get_json()
        assert "error" in result
        assert "not found" in result["error"]
    
    def test_create_watermark_not_applicable(self, client: FlaskClient, app: Flask):
        """Test watermark creation when method is not applicable."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "unsupported-method",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        with patch('pathlib.Path.is_absolute', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('watermarking_utils.is_watermarking_applicable', return_value=False):
            
            # Use the mock engine from conftest.py
            mock_engine = app.config['mock_db_engine']
            mock_conn = app.config['mock_db_conn']
            
            # Mock document lookup
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "files/testuser/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            
            response = client.post("/api/create-watermark/1", 
                                 json=watermark_data, 
                                 headers=headers)
            
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "not applicable" in result["error"]
    
    def test_create_watermark_file_missing(self, client: FlaskClient, app: Flask):
        """Test watermark creation when document file is missing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        with patch('pathlib.Path.is_absolute', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.exists', return_value=False):
            
            # Use the mock engine from conftest.py
            mock_engine = app.config['mock_db_engine']
            mock_conn = app.config['mock_db_conn']
            
            # Mock document lookup
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "files/testuser/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            
            response = client.post("/api/create-watermark/1", 
                                 json=watermark_data, 
                                 headers=headers)
            
            assert response.status_code == 410
            result = response.get_json()
            assert "error" in result
            assert "missing on disk" in result["error"]

    def test_list_versions_success(self, client: FlaskClient, app: Flask):
        """Test successful version listing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        # Use the mock engine from conftest.py
        mock_engine = app.config['mock_db_engine']
        mock_conn = app.config['mock_db_conn']
        
        # Reset mock state completely
        mock_conn.reset_mock()
        mock_engine.reset_mock()
        
        # Mock version list
        mock_versions = [
            MagicMock(id=1, documentid=1, link="abc123", intended_for="john@example.com", 
                     secret="secret1", method="add-after-eof"),
            MagicMock(id=2, documentid=1, link="def456", intended_for="jane@example.com", 
                     secret="secret2", method="add-after-eof")
        ]
        mock_conn.execute.return_value.all.return_value = mock_versions
        
        response = client.get("/api/list-versions/1", headers=headers)
        
        assert response.status_code == 200
        result = response.get_json()
        assert "versions" in result
        assert len(result["versions"]) == 2
        assert result["versions"][0]["id"] == 1
        assert result["versions"][0]["intended_for"] == "john@example.com"
        assert result["versions"][1]["id"] == 2
        assert result["versions"][1]["intended_for"] == "jane@example.com"
    
    def test_list_versions_no_auth(self, client: FlaskClient):
        """Test version listing without authentication."""
        response = client.get("/api/list-versions/1")
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
    
    def test_list_all_versions_success(self, client: FlaskClient, app: Flask):
        """Test successful listing of all versions for user."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        # Use the mock engine from conftest.py
        mock_engine = app.config['mock_db_engine']
        mock_conn = app.config['mock_db_conn']
        
        # Reset mock state completely
        mock_conn.reset_mock()
        mock_engine.reset_mock()
        
        # Mock version list across all documents
        mock_versions = [
            MagicMock(id=1, documentid=1, link="abc123", intended_for="john@example.com", 
                     method="add-after-eof"),
            MagicMock(id=2, documentid=1, link="def456", intended_for="jane@example.com", 
                     method="add-after-eof"),
            MagicMock(id=3, documentid=2, link="ghi789", intended_for="bob@example.com", 
                     method="text-overlay")
        ]
        mock_conn.execute.return_value.all.return_value = mock_versions
        
        response = client.get("/api/list-all-versions", headers=headers)
        
        assert response.status_code == 200
        result = response.get_json()
        assert "versions" in result
        assert len(result["versions"]) == 3
        assert result["versions"][0]["documentid"] == 1
        assert result["versions"][2]["documentid"] == 2
    
    def test_get_version_success(self, client: FlaskClient, app: Flask):
        """Test successful version retrieval by link."""
        test_pdf_content = b"%PDF-1.4\nwatermarked content\n%%EOF"
        
        with patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('werkzeug.utils.send_file') as mock_send_file:
            
            # Use the mock engine from conftest.py
            mock_engine = app.config['mock_db_engine']
            mock_conn = app.config['mock_db_conn']
            
            # Mock version data
            mock_version = MagicMock()
            mock_version.link = "abc123"
            mock_version.path = "/storage/files/testuser/watermarks/test__john.pdf"
            mock_conn.execute.return_value.first.return_value = mock_version
            
            # Mock file system operations
            mock_resolve.return_value = Path("/storage/files/testuser/watermarks/test__john.pdf")
            mock_stat.return_value.st_mtime = 1640995200.0
            mock_send_file.return_value = MagicMock(status_code=200)
            
            response = client.get("/api/get-version/abc123")
            
            # Should return 200 status code
            assert response.status_code == 200
    
    def test_get_version_not_found(self, client: FlaskClient, app: Flask):
        """Test version retrieval for non-existent link."""
        # Use the mock engine from conftest.py
        mock_engine = app.config['mock_db_engine']
        mock_conn = app.config['mock_db_conn']
        
        # Reset mock state completely
        mock_conn.reset_mock()
        mock_engine.reset_mock()
        
        # Mock version not found
        mock_conn.execute.return_value.first.return_value = None
        
        response = client.get("/api/get-version/nonexistent")
        
        assert response.status_code == 404
        result = response.get_json()
        assert "error" in result
        assert "not found" in result["error"]
    
    def test_complete_watermarking_workflow(self, client: FlaskClient, app: Flask):
        """Test complete watermarking workflow: create -> list -> get -> read."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456",
            "position": "bottom-right"
        }
        
        test_pdf_content = b"%PDF-1.4\noriginal content\n%%EOF"
        watermarked_content = b"%PDF-1.4\noriginal content\nwatermarked\n%%EOF"
        
        # Use the mock engine from conftest.py
        mock_engine = app.config['mock_db_engine']
        mock_conn = app.config['mock_db_conn']
        
        # Reset mock state completely
        mock_conn.reset_mock()
        mock_engine.reset_mock()
        
        with patch('pathlib.Path.is_absolute', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.open', mock_open()) as mock_file, \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
             patch('watermarking_utils.apply_watermark', return_value=watermarked_content), \
             patch('watermarking_utils.read_watermark', return_value="confidential-info-123"), \
             patch('werkzeug.utils.send_file') as mock_send_file:
            
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            mock_stat.return_value.st_mtime = 1640995200.0
            mock_send_file.return_value = MagicMock(status_code=200)
            
            # Step 1: Create watermark
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "files/testuser/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            create_response = client.post("/api/create-watermark/1", 
                                        json=watermark_data, 
                                        headers=headers)
            assert create_response.status_code == 201
            result = create_response.get_json()
            version_link = result["link"]
            
            # Step 2: List versions
            mock_versions = [
                MagicMock(id=1, documentid=1, link=version_link, 
                         intended_for="john.doe@example.com", 
                         secret="confidential-info-123", method="add-after-eof")
            ]
            mock_conn.execute.return_value.all.return_value = mock_versions
            
            list_response = client.get("/api/list-versions/1", headers=headers)
            assert list_response.status_code == 200
            versions = list_response.get_json()["versions"]
            assert len(versions) == 1
            assert versions[0]["link"] == version_link
            
            # Step 3: Get version file
            mock_version = MagicMock()
            mock_version.link = version_link
            mock_version.path = "/storage/files/testuser/watermarks/test__john.pdf"
            mock_conn.execute.return_value.first.return_value = mock_version
            
            get_response = client.get(f"/api/get-version/{version_link}")
            assert get_response.status_code == 200
            
            # Step 4: Read watermark
            read_data = {
                "method": "add-after-eof",
                "key": "encryption-key-456"
            }

            # Mock version lookup for read
            mock_version = MagicMock()
            mock_version.id = 1
            mock_version.documentid = 1
            mock_version.link = version_link
            mock_version.secret = "confidential-info-123"
            mock_version.path = "/storage/files/testuser/watermarks/test__john.pdf"
            mock_conn.execute.return_value.first.return_value = mock_version

            read_response = client.post(f"/api/read-watermark-by-link/{version_link}",
                                        json=read_data,
                                        headers=headers)
            assert read_response.status_code == 200  # Changed from 201
            read_result = read_response.get_json()
            assert read_result["secret"] == "confidential-info-123"

    def test_create_watermark_db_error_on_document_lookup_returns_503(self, client: FlaskClient, app: Flask):
        """覆盖 920-923: 文档查询数据库异常 -> 503"""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        payload = {"method": "add-after-eof", "intended_for": "a", "secret": "s", "key": "k"}

        mock_conn = app.config['mock_db_conn']
        mock_conn.execute.side_effect = Exception("db failure")

        resp = client.post("/api/create-watermark/1", json=payload, headers=headers)
        assert resp.status_code == 503
        mock_conn.execute.side_effect = None

    def test_create_watermark_is_applicable_raises_returns_400(self, client: FlaskClient, app: Flask):
        """覆盖 948-951: 适用性检查抛异常 -> 400"""
        from itsdangerous import URLSafeTimedSerializer
        from unittest.mock import MagicMock, patch
        from pathlib import Path

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        payload = {"method": "add-after-eof", "intended_for": "a", "secret": "s", "key": "k"}

        mock_conn = app.config['mock_db_conn']
        doc = MagicMock()
        doc.id = 1
        doc.name = "t.pdf"
        doc.path = "files/testuser/t.pdf"
        mock_conn.execute.return_value.first.return_value = doc

        with patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('watermarking_utils.is_watermarking_applicable', side_effect=Exception("boom")):
            mock_resolve.return_value = Path(str(Path(app.config['STORAGE_DIR']) / 'files' / 'testuser' / 't.pdf'))
            resp = client.post("/api/create-watermark/1", json=payload, headers=headers)
            assert resp.status_code == 400

    def test_create_watermark_apply_watermark_raises_returns_500(self, client: FlaskClient, app: Flask):
        """覆盖 963-967: 打水印抛异常 -> 500"""
        from itsdangerous import URLSafeTimedSerializer
        from unittest.mock import MagicMock, patch
        from pathlib import Path

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        payload = {"method": "add-after-eof", "intended_for": "a", "secret": "s", "key": "k"}

        mock_conn = app.config['mock_db_conn']
        doc = MagicMock()
        doc.id = 1
        doc.name = "t.pdf"
        doc.path = "files/testuser/t.pdf"
        mock_conn.execute.return_value.first.return_value = doc

        with patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
             patch('watermarking_utils.apply_watermark', side_effect=Exception("fail")):
            mock_resolve.return_value = Path(str(Path(app.config['STORAGE_DIR']) / 'files' / 'testuser' / 't.pdf'))
            resp = client.post("/api/create-watermark/1", json=payload, headers=headers)
            assert resp.status_code == 500

    def test_create_watermark_write_bytes_fails_returns_500(self, client: FlaskClient, app: Flask):
        """覆盖 984-985: 保存水印文件失败 -> 500"""
        from itsdangerous import URLSafeTimedSerializer
        from unittest.mock import MagicMock, patch, mock_open
        from pathlib import Path

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        payload = {"method": "add-after-eof", "intended_for": "a", "secret": "s", "key": "k"}

        mock_conn = app.config['mock_db_conn']
        doc = MagicMock()
        doc.id = 1
        doc.name = "t.pdf"
        doc.path = "files/testuser/t.pdf"
        mock_conn.execute.return_value.first.return_value = doc

        wm_bytes = b"%PDF-1.4\nwm\n%%EOF"

        with patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.mkdir'), \
             patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
             patch('watermarking_utils.apply_watermark', return_value=wm_bytes), \
             patch('pathlib.Path.open', side_effect=IOError("disk full")):
            mock_resolve.return_value = Path(str(Path(app.config['STORAGE_DIR']) / 'files' / 'testuser' / 't.pdf'))
            resp = client.post("/api/create-watermark/1", json=payload, headers=headers)
            assert resp.status_code == 500

    def test_create_watermark_db_insert_fails_cleans_up_and_returns_503(self, client: FlaskClient, app: Flask):
        """覆盖 1014-1020: DB 插入失败 -> 清理已写入文件并返回 503"""
        from itsdangerous import URLSafeTimedSerializer
        from unittest.mock import MagicMock, patch
        from pathlib import Path

        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        payload = {"method": "add-after-eof", "intended_for": "a", "secret": "s", "key": "k"}

        mock_conn = app.config['mock_db_conn']
        doc = MagicMock()
        doc.id = 1
        doc.name = "t.pdf"
        doc.path = "files/testuser/t.pdf"
        mock_conn.execute.return_value.first.return_value = doc

        wm_bytes = b"%PDF-1.4\nwm\n%%EOF"

        with patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.mkdir'), \
             patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
             patch('watermarking_utils.apply_watermark', return_value=wm_bytes), \
             patch('pathlib.Path.open') as mock_open_file, \
             patch('pathlib.Path.unlink') as mock_unlink:
            # 写入成功
            mock_resolve.return_value = Path(str(Path(app.config['STORAGE_DIR']) / 'files' / 'testuser' / 't.pdf'))
            class DummyFile:
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc, tb):
                    return False
                def write(self, b):
                    return len(b)
            mock_open_file.return_value = DummyFile()

            # DB 插入抛异常
            mock_conn.execute.side_effect = [
                MagicMock(),  # SELECT document
                Exception("insert failed")
            ]

            resp = client.post("/api/create-watermark/1", json=payload, headers=headers)
            assert resp.status_code == 503
            mock_unlink.assert_called()

    def _auth_headers(self, app: Flask) -> dict:
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        return {"Authorization": f"Bearer {token}"}

    def test_read_by_link_db_error_returns_503(self, client: FlaskClient, app: Flask):
        """覆盖 1158-1161: 数据库异常 -> 503"""
        headers = self._auth_headers(app)
        mock_conn = app.config['mock_db_conn']
        mock_conn.execute.side_effect = Exception("db error")
        resp = client.post("/api/read-watermark-by-link/LX", json={"method": "add-after-eof", "key": "k"}, headers=headers)
        assert resp.status_code == 503
        mock_conn.execute.side_effect = None

    def test_read_by_link_not_found_returns_404(self, client: FlaskClient, app: Flask):
        """覆盖 1164-1166: 未找到 -> 404"""
        headers = self._auth_headers(app)
        mock_conn = app.config['mock_db_conn']
        mock_conn.execute.return_value.first.return_value = None
        resp = client.post("/api/read-watermark-by-link/LX", json={"method": "add-after-eof", "key": "k"}, headers=headers)
        assert resp.status_code == 404

    def test_read_by_link_invalid_path_returns_500(self, client: FlaskClient, app: Flask):
        """覆盖 1174-1177: 路径非法 -> 500"""
        from unittest.mock import MagicMock, patch
        headers = self._auth_headers(app)
        mock_conn = app.config['mock_db_conn']
        row = MagicMock()
        row.path = "../../etc/passwd"
        mock_conn.execute.return_value.first.return_value = row
        with patch('pathlib.Path.resolve', side_effect=RuntimeError("escape")):
            resp = client.post("/api/read-watermark-by-link/LX", json={"method": "add-after-eof", "key": "k"}, headers=headers)
            assert resp.status_code == 500

    def test_read_by_link_missing_on_disk_returns_410(self, client: FlaskClient, app: Flask):
        """覆盖 1179: 文件缺失 -> 410"""
        from unittest.mock import MagicMock, patch
        from pathlib import Path
        headers = self._auth_headers(app)
        mock_conn = app.config['mock_db_conn']
        row = MagicMock()
        row.path = str(Path(app.config['STORAGE_DIR']) / 'files' / 'testuser' / 't.pdf')
        mock_conn.execute.return_value.first.return_value = row
        with patch('pathlib.Path.resolve', return_value=Path(row.path)), \
             patch('pathlib.Path.exists', return_value=False):
            resp = client.post("/api/read-watermark-by-link/LX", json={"method": "add-after-eof", "key": "k"}, headers=headers)
            assert resp.status_code == 410

    def test_read_by_link_read_exception_returns_400(self, client: FlaskClient, app: Flask):
        """覆盖 1185-1188: 读取异常 -> 400"""
        from unittest.mock import MagicMock, patch
        from pathlib import Path
        headers = self._auth_headers(app)
        mock_conn = app.config['mock_db_conn']
        row = MagicMock()
        row.secret = "S1"
        row.path = str(Path(app.config['STORAGE_DIR']) / 'files' / 'testuser' / 't.pdf')
        mock_conn.execute.return_value.first.return_value = row
        with patch('pathlib.Path.resolve', return_value=Path(row.path)), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('watermarking_utils.read_watermark', side_effect=Exception("boom")):
            resp = client.post("/api/read-watermark-by-link/LX", json={"method": "add-after-eof", "key": "k"}, headers=headers)
            assert resp.status_code == 400

    def test_read_by_link_secret_mismatch_returns_400(self, client: FlaskClient, app: Flask):
        """覆盖 1191-1193: 密钥不匹配 -> 400"""
        from unittest.mock import MagicMock, patch
        from pathlib import Path
        headers = self._auth_headers(app)
        mock_conn = app.config['mock_db_conn']
        row = MagicMock()
        row.secret = "EXPECTED"
        row.path = str(Path(app.config['STORAGE_DIR']) / 'files' / 'testuser' / 't.pdf')
        mock_conn.execute.return_value.first.return_value = row
        with patch('pathlib.Path.resolve', return_value=Path(row.path)), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('watermarking_utils.read_watermark', return_value="DIFF"):
            resp = client.post("/api/read-watermark-by-link/LX", json={"method": "add-after-eof", "key": "k"}, headers=headers)
            assert resp.status_code == 400