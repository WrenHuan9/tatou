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
    
    @pytest.mark.xfail
    def test_create_watermark_success(self, client: FlaskClient, app: Flask):
        """Test successful watermark creation."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
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
            assert result["position"] == "bottom-right"
            assert "link" in result
            assert "filename" in result
            assert result["size"] == len(watermarked_content)
    
    @pytest.mark.xfail
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
    
    @pytest.mark.xfail
    def test_create_watermark_missing_fields(self, client: FlaskClient, app: Flask):
        """Test watermark creation with missing required fields."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
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
    
    @pytest.mark.xfail
    def test_create_watermark_document_not_found(self, client: FlaskClient, app: Flask):
        """Test watermark creation for non-existent document."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock document not found
            mock_conn.execute.return_value.first.return_value = None
            
            response = client.post("/api/create-watermark/999", 
                                 json=watermark_data, 
                                 headers=headers)
            
            assert response.status_code == 404
            result = response.get_json()
            assert "error" in result
            assert "not found" in result["error"]
    
    @pytest.mark.xfail
    def test_create_watermark_not_applicable(self, client: FlaskClient, app: Flask):
        """Test watermark creation when method is not applicable."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "unsupported-method",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.is_absolute', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('watermarking_utils.is_watermarking_applicable', return_value=False):
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
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
    
    @pytest.mark.xfail
    def test_create_watermark_file_missing(self, client: FlaskClient, app: Flask):
        """Test watermark creation when document file is missing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        watermark_data = {
            "method": "add-after-eof",
            "intended_for": "john.doe@example.com",
            "secret": "confidential-info-123",
            "key": "encryption-key-456"
        }
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.is_absolute', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.exists', return_value=False):
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
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
    
    @pytest.mark.xfail
    def test_read_watermark_success(self, client: FlaskClient, app: Flask):
        """Test successful watermark reading."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        read_data = {
            "method": "add-after-eof",
            "key": "encryption-key-456",
            "position": "bottom-right"
        }
        
        expected_secret = "confidential-info-123"
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.is_absolute', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('watermarking_utils.read_watermark', return_value=expected_secret):
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock document lookup
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "files/testuser/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            
            response = client.post("/api/read-watermark/1", 
                                 json=read_data, 
                                 headers=headers)
            
            assert response.status_code == 201
            result = response.get_json()
            assert result["documentid"] == 1
            assert result["secret"] == expected_secret
            assert result["method"] == "add-after-eof"
            assert result["position"] == "bottom-right"
    
    @pytest.mark.xfail
    def test_read_watermark_no_auth(self, client: FlaskClient):
        """Test watermark reading without authentication."""
        read_data = {
            "method": "add-after-eof",
            "key": "encryption-key-456"
        }
        
        response = client.post("/api/read-watermark/1", json=read_data)
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
    
    @pytest.mark.xfail
    def test_read_watermark_missing_fields(self, client: FlaskClient, app: Flask):
        """Test watermark reading with missing required fields."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        test_cases = [
            {},  # Empty payload
            {"method": "add-after-eof"},  # Missing key
            {"key": "key123"},  # Missing method
        ]
        
        for read_data in test_cases:
            response = client.post("/api/read-watermark/1", 
                                 json=read_data, 
                                 headers=headers)
            
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "required" in result["error"]
    
    @pytest.mark.xfail
    def test_read_watermark_document_not_found(self, client: FlaskClient, app: Flask):
        """Test watermark reading for non-existent document."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        read_data = {
            "method": "add-after-eof",
            "key": "encryption-key-456"
        }
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock document not found
            mock_conn.execute.return_value.first.return_value = None
            
            response = client.post("/api/read-watermark/999", 
                                 json=read_data, 
                                 headers=headers)
            
            assert response.status_code == 404
            result = response.get_json()
            assert "error" in result
            assert "not found" in result["error"]
    
    @pytest.mark.xfail
    def test_read_watermark_error(self, client: FlaskClient, app: Flask):
        """Test watermark reading when extraction fails."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        read_data = {
            "method": "add-after-eof",
            "key": "wrong-key-456"
        }
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.is_absolute', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('watermarking_utils.read_watermark', side_effect=Exception("Invalid key")):
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock document lookup
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "files/testuser/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            
            response = client.post("/api/read-watermark/1", 
                                 json=read_data, 
                                 headers=headers)
            
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "Error when attempting to read watermark" in result["error"]
    
    @pytest.mark.xfail
    def test_list_versions_success(self, client: FlaskClient, app: Flask):
        """Test successful version listing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
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
    
    @pytest.mark.xfail
    def test_list_versions_no_auth(self, client: FlaskClient):
        """Test version listing without authentication."""
        response = client.get("/api/list-versions/1")
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
    
    @pytest.mark.xfail
    def test_list_all_versions_success(self, client: FlaskClient, app: Flask):
        """Test successful listing of all versions for user."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
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
    
    @pytest.mark.xfail
    def test_get_version_success(self, client: FlaskClient):
        """Test successful version retrieval by link."""
        test_pdf_content = b"%PDF-1.4\nwatermarked content\n%%EOF"
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('flask.send_file') as mock_send_file:
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
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
            
            # send_file should be called
            mock_send_file.assert_called_once()
    
    @pytest.mark.xfail
    def test_get_version_not_found(self, client: FlaskClient):
        """Test version retrieval for non-existent link."""
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock version not found
            mock_conn.execute.return_value.first.return_value = None
            
            response = client.get("/api/get-version/nonexistent")
            
            assert response.status_code == 404
            result = response.get_json()
            assert "error" in result
            assert "not found" in result["error"]
    
    @pytest.mark.xfail
    def test_complete_watermarking_workflow(self, client: FlaskClient, app: Flask):
        """Test complete watermarking workflow: create -> list -> get -> read."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
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
             patch('pathlib.Path.stat') as mock_stat, \
             patch('watermarking_utils.is_watermarking_applicable', return_value=True), \
             patch('watermarking_utils.apply_watermark', return_value=watermarked_content), \
             patch('watermarking_utils.read_watermark', return_value="confidential-info-123"), \
             patch('flask.send_file') as mock_send_file:
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.begin.return_value.__enter__.return_value = mock_conn
            
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            mock_stat.return_value.st_mtime = 1640995200.0
            mock_send_file.return_value = MagicMock(status_code=200)
            
            # Step 1: Create watermark
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "files/testuser/test.pdf"
            mock_conn.execute.side_effect = [
                mock_doc,  # Document lookup
                None,  # INSERT version
                MagicMock(scalar=lambda: 1)  # LAST_INSERT_ID
            ]
            
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
            mock_send_file.assert_called()
            
            # Step 4: Read watermark
            read_data = {
                "method": "add-after-eof",
                "key": "encryption-key-456"
            }
            
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            read_response = client.post("/api/read-watermark/1", 
                                      json=read_data, 
                                      headers=headers)
            assert read_response.status_code == 201
            read_result = read_response.get_json()
            assert read_result["secret"] == "confidential-info-123"