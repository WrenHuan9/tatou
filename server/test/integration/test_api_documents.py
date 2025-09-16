"""Integration tests for document management endpoints.

This module tests the complete document lifecycle including upload, listing,
retrieval, and deletion of documents.
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
class TestDocumentManagement:
    """Test document management functionality."""
    
    def test_upload_document_success(self, client: FlaskClient, app: Flask):
        """Test successful document upload."""
        # Create a valid auth token
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        # Create test PDF data
        pdf_data = b"%PDF-1.4\ntest content\n%%EOF"
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('hashlib.sha256') as mock_sha256:
            
            # Mock database operations
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.begin.return_value.__enter__.return_value = mock_conn
            
            # Mock file operations
            mock_stat.return_value.st_size = len(pdf_data)
            mock_hash = MagicMock()
            mock_hash.hexdigest.return_value = "abcd1234"
            mock_sha256.return_value = mock_hash
            
            # Mock database responses
            mock_conn.execute.side_effect = [
                None,  # INSERT operation
                MagicMock(scalar=lambda: 1),  # LAST_INSERT_ID
                MagicMock(id=1, name="My Test Document", creation="2023-01-01T00:00:00", 
                         sha256_hex="abcd1234", size=len(pdf_data))  # SELECT result
            ]
            
            # Test file upload
            data = {
                'file': (io.BytesIO(pdf_data), 'test.pdf', 'application/pdf'),
                'name': 'My Test Document'
            }
            
            response = client.post("/api/upload-document", 
                                 data=data, 
                                 headers=headers,
                                 content_type='multipart/form-data')
            
            assert response.status_code == 201
            result = response.get_json()
            assert result["id"] == 1
            assert result["name"] == "My Test Document"
            assert result["sha256"] == "abcd1234"
            assert result["size"] == len(pdf_data)
    
    def test_upload_document_no_auth(self, client: FlaskClient):
        """Test document upload without authentication."""
        pdf_data = b"%PDF-1.4\ntest content\n%%EOF"
        data = {
            'file': (io.BytesIO(pdf_data), 'test.pdf', 'application/pdf')
        }
        
        response = client.post("/api/upload-document", 
                             data=data,
                             content_type='multipart/form-data')
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
    
    def test_upload_document_no_file(self, client: FlaskClient, app: Flask):
        """Test document upload without file."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        response = client.post("/api/upload-document", 
                             data={},
                             headers=headers,
                             content_type='multipart/form-data')
        
        assert response.status_code == 400
        result = response.get_json()
        assert "error" in result
        assert "file is required" in result["error"]
    
    def test_upload_document_empty_filename(self, client: FlaskClient, app: Flask):
        """Test document upload with empty filename."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        data = {
            'file': (io.BytesIO(b"content"), '', 'application/pdf')
        }
        
        response = client.post("/api/upload-document", 
                             data=data,
                             headers=headers,
                             content_type='multipart/form-data')
        
        assert response.status_code == 400
        result = response.get_json()
        assert "error" in result
        assert "empty filename" in result["error"]
    
    def test_list_documents_success(self, client: FlaskClient, app: Flask):
        """Test successful document listing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock document list
            mock_docs = [
                MagicMock(id=1, name="doc1.pdf", creation="2023-01-01T00:00:00", 
                         sha256_hex="hash1", size=1000),
                MagicMock(id=2, name="doc2.pdf", creation="2023-01-02T00:00:00", 
                         sha256_hex="hash2", size=2000)
            ]
            mock_conn.execute.return_value.all.return_value = mock_docs
            
            response = client.get("/api/list-documents", headers=headers)
            
            assert response.status_code == 200
            result = response.get_json()
            assert "documents" in result
            assert len(result["documents"]) == 2
            assert result["documents"][0]["id"] == 1
            assert result["documents"][0]["name"] == "doc1.pdf"
            assert result["documents"][1]["id"] == 2
            assert result["documents"][1]["name"] == "doc2.pdf"
    
    def test_list_documents_no_auth(self, client: FlaskClient):
        """Test document listing without authentication."""
        response = client.get("/api/list-documents")
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
    
    def test_list_documents_empty(self, client: FlaskClient, app: Flask):
        """Test document listing with no documents."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock empty document list
            mock_conn.execute.return_value.all.return_value = []
            
            response = client.get("/api/list-documents", headers=headers)
            
            assert response.status_code == 200
            result = response.get_json()
            assert "documents" in result
            assert len(result["documents"]) == 0
    
    def test_get_document_success(self, client: FlaskClient, app: Flask):
        """Test successful document retrieval."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        test_pdf_content = b"%PDF-1.4\ntest document content\n%%EOF"
        
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
            
            # Mock document data
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "/storage/files/testuser/test.pdf"
            mock_doc.sha256_hex = "abcd1234"
            mock_doc.size = len(test_pdf_content)
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            # Mock file system operations
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            mock_stat.return_value.st_mtime = 1640995200.0
            mock_send_file.return_value = MagicMock(status_code=200)
            
            response = client.get("/api/get-document/1", headers=headers)
            
            # send_file should be called
            mock_send_file.assert_called_once()
    
    def test_get_document_not_found(self, client: FlaskClient, app: Flask):
        """Test document retrieval for non-existent document."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock document not found
            mock_conn.execute.return_value.first.return_value = None
            
            response = client.get("/api/get-document/999", headers=headers)
            
            assert response.status_code == 404
            result = response.get_json()
            assert "error" in result
            assert "not found" in result["error"]
    
    def test_get_document_file_missing(self, client: FlaskClient, app: Flask):
        """Test document retrieval when file is missing from disk."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.exists', return_value=False), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'):
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock document data
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = "/storage/files/testuser/test.pdf"
            mock_doc.sha256_hex = "abcd1234"
            mock_doc.size = 1000
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            
            response = client.get("/api/get-document/1", headers=headers)
            
            assert response.status_code == 410
            result = response.get_json()
            assert "error" in result
            assert "missing on disk" in result["error"]
    
    def test_delete_document_success(self, client: FlaskClient):
        """Test successful document deletion."""
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.unlink') as mock_unlink:
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.begin.return_value.__enter__.return_value = mock_conn
            
            # Mock document data
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.path = "/storage/files/testuser/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            response = client.delete("/api/delete-document/1")
            
            assert response.status_code == 200
            result = response.get_json()
            assert result["deleted"] is True
            assert result["id"] == "1"
            assert result["file_deleted"] is True
            
            # Verify file deletion was attempted
            mock_unlink.assert_called_once()
    
    def test_delete_document_not_found(self, client: FlaskClient):
        """Test deletion of non-existent document."""
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock document not found
            mock_conn.execute.return_value.first.return_value = None
            
            response = client.delete("/api/delete-document/999")
            
            assert response.status_code == 404
            result = response.get_json()
            assert "error" in result
            assert "not found" in result["error"]
    
    def test_delete_document_file_missing(self, client: FlaskClient):
        """Test document deletion when file is already missing."""
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.exists', return_value=False):
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.begin.return_value.__enter__.return_value = mock_conn
            
            # Mock document data
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.path = "/storage/files/testuser/test.pdf"
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            response = client.delete("/api/delete-document/1")
            
            assert response.status_code == 200
            result = response.get_json()
            assert result["deleted"] is True
            assert result["file_missing"] is True
    
    def test_complete_document_lifecycle(self, client: FlaskClient, app: Flask):
        """Test complete document lifecycle: upload -> list -> get -> delete."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        pdf_data = b"%PDF-1.4\ntest content\n%%EOF"
        
        with patch('sqlalchemy.create_engine') as mock_create_engine, \
             patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.stat') as mock_stat, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.resolve') as mock_resolve, \
             patch('pathlib.Path.relative_to'), \
             patch('pathlib.Path.unlink') as mock_unlink, \
             patch('hashlib.sha256') as mock_sha256, \
             patch('flask.send_file') as mock_send_file:
            
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.begin.return_value.__enter__.return_value = mock_conn
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Setup common mocks
            mock_stat.return_value.st_size = len(pdf_data)
            mock_stat.return_value.st_mtime = 1640995200.0
            mock_hash = MagicMock()
            mock_hash.hexdigest.return_value = "abcd1234"
            mock_sha256.return_value = mock_hash
            mock_resolve.return_value = Path("/storage/files/testuser/test.pdf")
            mock_send_file.return_value = MagicMock(status_code=200)
            
            # Step 1: Upload document
            mock_conn.execute.side_effect = [
                None,  # INSERT operation
                MagicMock(scalar=lambda: 1),  # LAST_INSERT_ID
                MagicMock(id=1, name="Test Document", creation="2023-01-01T00:00:00", 
                         sha256_hex="abcd1234", size=len(pdf_data))  # SELECT result
            ]
            
            upload_data = {
                'file': (io.BytesIO(pdf_data), 'test.pdf', 'application/pdf'),
                'name': 'Test Document'
            }
            
            upload_response = client.post("/api/upload-document", 
                                        data=upload_data, 
                                        headers=headers,
                                        content_type='multipart/form-data')
            assert upload_response.status_code == 201
            doc_id = upload_response.get_json()["id"]
            
            # Step 2: List documents
            mock_docs = [
                MagicMock(id=1, name="Test Document", creation="2023-01-01T00:00:00", 
                         sha256_hex="abcd1234", size=len(pdf_data))
            ]
            mock_conn.execute.return_value.all.return_value = mock_docs
            
            list_response = client.get("/api/list-documents", headers=headers)
            assert list_response.status_code == 200
            docs = list_response.get_json()["documents"]
            assert len(docs) == 1
            assert docs[0]["id"] == doc_id
            
            # Step 3: Get document
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "Test Document"
            mock_doc.path = "/storage/files/testuser/test.pdf"
            mock_doc.sha256_hex = "abcd1234"
            mock_doc.size = len(pdf_data)
            mock_conn.execute.return_value.first.return_value = mock_doc
            
            get_response = client.get(f"/api/get-document/{doc_id}", headers=headers)
            mock_send_file.assert_called()
            
            # Step 4: Delete document
            delete_response = client.delete(f"/api/delete-document/{doc_id}")
            assert delete_response.status_code == 200
            assert delete_response.get_json()["deleted"] is True