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
from datetime import datetime

class MockRow:
    """模拟数据库返回的行对象"""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


@pytest.mark.integration
class TestDocumentManagement:
    """Test document management functionality."""

    def test_upload_document_success(self, client: FlaskClient, app: Flask):
        """Test successful document upload."""
        # Create a valid auth token
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        # Create test PDF data
        pdf_data = b"%PDF-1.4\ntest content\n%%EOF"

        # Ensure the storage directory structure exists
        storage_dir = Path(app.config["STORAGE_DIR"])
        user_dir = storage_dir / "files" / "testuser"
        user_dir.mkdir(parents=True, exist_ok=True)

        # Mock database connection (use the one from app fixture)
        mock_conn = app.config['mock_db_conn']

        # Mock database responses for the upload operation
        # 1. INSERT operation - returns result with lastrowid
        mock_insert_result = MagicMock()
        mock_insert_result.lastrowid = 1

        # 2. SELECT LAST_INSERT_ID() - returns result that calls .scalar()
        mock_scalar_result = MagicMock()
        mock_scalar_result.scalar.return_value = 1

        # 3. SELECT ... FROM Documents - returns result that calls .one()
        mock_select_result = MagicMock()
        mock_select_result.id = 1
        mock_select_result.name = "My Test Document"
        mock_select_result.creation = "2023-01-01T00:00:00"
        mock_select_result.sha256_hex = "abcd1234"
        mock_select_result.size = len(pdf_data)

        mock_one_result = MagicMock()
        mock_one_result.one.return_value = mock_select_result

        # Set up side_effect for 3 execute calls
        mock_conn.execute.side_effect = [
            mock_insert_result,  # First execute: INSERT
            mock_scalar_result,  # Second execute: SELECT LAST_INSERT_ID()
            mock_one_result  # Third execute: SELECT ... FROM Documents
        ]

        # Test file upload
        data = {
            'file': (io.BytesIO(pdf_data), 'test.pdf', 'application/pdf'),
            'name': 'My Test Document'
        }

        response = client.post(
            "/api/upload-document",
            data=data,
            headers=headers,
            content_type='multipart/form-data'
        )

        # Verify response
        assert response.status_code == 201
        result = response.get_json()
        assert result["id"] == 1
        assert result["name"] == "My Test Document"
        assert result["sha256"] == "abcd1234"
        assert result["size"] == len(pdf_data)

        # Cleanup: remove the saved file
        import glob
        for f in glob.glob(str(user_dir / "*.pdf")):
            Path(f).unlink()
    
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

    @pytest.mark.parametrize("doc_count,expected_docs", [
        (2, [
            {"id": 1, "name": "doc1.pdf", "creation": "2023-01-01T00:00:00", "sha256_hex": "hash1", "size": 1000},
            {"id": 2, "name": "doc2.pdf", "creation": "2023-01-02T00:00:00", "sha256_hex": "hash2", "size": 2000}
        ]),
        (0, [])
    ])
    def test_list_documents_success(self, client: FlaskClient, app: Flask):
        """Test successful document listing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        # Use the mock connection from app fixture
        mock_conn = app.config['mock_db_conn']

        # Mock document list
        mock_docs = []
        for i, data in enumerate([
            {"id": 1, "name": "doc1.pdf", "creation": "2023-01-01T00:00:00", "sha256_hex": "hash1", "size": 1000},
            {"id": 2, "name": "doc2.pdf", "creation": "2023-01-02T00:00:00", "sha256_hex": "hash2", "size": 2000}
        ]):
            mock_doc = MagicMock()
            mock_doc.id = data["id"]
            mock_doc.name = data["name"]
            mock_doc.creation = data["creation"]
            mock_doc.sha256_hex = data["sha256_hex"]
            mock_doc.size = data["size"]
            mock_docs.append(mock_doc)

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
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        # Use the mock connection from app fixture
        mock_conn = app.config['mock_db_conn']

        # Mock empty document list
        mock_conn.execute.return_value.all.return_value = []

        response = client.get("/api/list-documents", headers=headers)

        assert response.status_code == 200
        result = response.get_json()
        assert "documents" in result
        assert len(result["documents"]) == 0

    def test_list_documents_success(self, client: FlaskClient, app: Flask):
        """Test successful document listing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        # Use the mock connection from app fixture
        mock_conn = app.config['mock_db_conn']

        # Mock document list
        mock_docs = []
        for i, data in enumerate([
            {"id": 1, "name": "doc1.pdf", "creation": "2023-01-01T00:00:00", "sha256_hex": "hash1", "size": 1000},
            {"id": 2, "name": "doc2.pdf", "creation": "2023-01-02T00:00:00", "sha256_hex": "hash2", "size": 2000}
        ]):
            mock_doc = MagicMock()
            mock_doc.id = data["id"]
            mock_doc.name = data["name"]
            mock_doc.creation = data["creation"]
            mock_doc.sha256_hex = data["sha256_hex"]
            mock_doc.size = data["size"]
            mock_docs.append(mock_doc)

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
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        # Use the mock connection from app fixture
        mock_conn = app.config['mock_db_conn']

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
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        # Create a real temp PDF file in the app's STORAGE_DIR
        test_pdf_content = b"%PDF-1.4\ntest document content\n%%EOF"
        storage_dir = Path(app.config["STORAGE_DIR"])
        test_file_dir = storage_dir / "files" / "testuser"
        test_file_dir.mkdir(parents=True, exist_ok=True)
        test_file = test_file_dir / "test.pdf"
        test_file.write_bytes(test_pdf_content)

        try:
            # Use the mock connection from app fixture
            mock_conn = app.config['mock_db_conn']

            # Mock document data
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.name = "test.pdf"
            mock_doc.path = str(test_file)  # Use real file path within STORAGE_DIR
            mock_doc.sha256_hex = "abcd1234"
            mock_doc.size = len(test_pdf_content)
            mock_conn.execute.return_value.first.return_value = mock_doc

            response = client.get("/api/get-document/1", headers=headers)

            # Check that the response is successful
            assert response.status_code == 200
            assert response.mimetype == "application/pdf"
            # Optionally check content
            assert response.data == test_pdf_content
        finally:
            # Cleanup
            test_file.unlink(missing_ok=True)

    def test_get_document_not_found(self, client: FlaskClient, app: Flask):
        """Test document retrieval for non-existent document."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        # Use the mock connection from app fixture
        mock_conn = app.config['mock_db_conn']

        # Mock document not found - set to None
        mock_conn.execute.return_value.first.return_value = None

        response = client.get("/api/get-document/999", headers=headers)

        assert response.status_code == 404
        result = response.get_json()
        assert "error" in result
        assert result["error"] == "document not found"

    def test_delete_document_success(self, client: FlaskClient, app, simple_auth_headers: dict):
        """Test successful document deletion."""
        mock_conn = app.config['mock_db_conn']

        with patch('pathlib.Path.exists', return_value=True), \
                patch('pathlib.Path.unlink') as mock_unlink, \
                patch('pathlib.Path.resolve') as mock_resolve:
            # Mock document data
            mock_doc = MagicMock()
            mock_doc.id = 1
            mock_doc.path = "/storage/files/testuser/test.pdf"

            # Mock versions query (no versions to delete)
            mock_versions_result = MagicMock()
            mock_versions_result.fetchall.return_value = []

            # Mock document query
            mock_doc_result = MagicMock()
            mock_doc_result.first.return_value = mock_doc

            # Setup execute to return different results for different queries
            mock_conn.execute.side_effect = [
                mock_doc_result,  # First query: get document
                mock_versions_result,  # Second query: get versions
                MagicMock()  # Third query: delete document
            ]

            # Mock path resolution
            storage_root = Path(app.config["STORAGE_DIR"])
            mock_resolve.return_value = storage_root / "files" / "testuser" / "test.pdf"

            response = client.delete("/api/delete-document/1", headers=simple_auth_headers)

            assert response.status_code == 200
            result = response.get_json()
            assert result["deleted"] is True
            assert result["id"] == 1
            assert result["file_deleted"] is True

            # Verify file deletion was attempted
            mock_unlink.assert_called_once()

    def test_delete_document_not_found(self, client: FlaskClient, app, simple_auth_headers: dict):
        """Test deletion of non-existent document."""
        mock_conn = app.config['mock_db_conn']

        # Mock document not found
        mock_result = MagicMock()
        mock_result.first.return_value = None
        mock_conn.execute.return_value = mock_result

        response = client.delete("/api/delete-document/999", headers=simple_auth_headers)

        assert response.status_code == 404
        result = response.get_json()
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_delete_document_file_missing(self, client: FlaskClient, app: Flask):
        """Test document deletion when file is already missing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        with patch('sqlalchemy.create_engine') as mock_create_engine, \
                patch('pathlib.Path.exists', return_value=False):
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            mock_engine.begin.return_value.__enter__.return_value = mock_conn

            # Mock document data
            mock_doc = MockRow(
                id=1,
                path="/storage/files/testuser/test.pdf"
            )
            mock_conn.execute.return_value.first.return_value = mock_doc
            # Mock fetchall for versions query (no versions)
            mock_conn.execute.return_value.fetchall.return_value = []

            response = client.delete("/api/delete-document/1", headers=headers)

            assert response.status_code == 200
            result = response.get_json()
            assert result["deleted"] is True
            assert result["file_missing"] is True

    def test_delete_document_file_missing(self, client: FlaskClient, app: Flask):
        """Test document deletion when file is already missing."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        mock_conn = app.config['mock_db_conn']

        storage_dir = app.config["STORAGE_DIR"]
        doc_path = storage_dir / "files" / "testuser" / "test.pdf"

        with patch('pathlib.Path.exists', return_value=False):
            mock_doc = MockRow(
                id=1,
                path=str(doc_path)
            )

            mock_doc_result = MagicMock()
            mock_doc_result.first.return_value = mock_doc

            mock_versions_result = MagicMock()
            mock_versions_result.fetchall.return_value = []

            mock_conn.execute.side_effect = [
                mock_doc_result,
                mock_versions_result,
                MagicMock()
            ]

            response = client.delete("/api/delete-document/1", headers=headers)

            assert response.status_code == 200
            result = response.get_json()
            assert result["deleted"] is True
            assert result["file_missing"] is True

    def test_complete_document_lifecycle(self, client: FlaskClient, app: Flask):
        """Test complete document lifecycle: upload -> list -> get -> delete."""
        from itsdangerous import URLSafeTimedSerializer
        import hashlib
        from datetime import datetime

        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="tatou-auth"
        )
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}

        pdf_data = b"%PDF-1.4\ntest content\n%%EOF"
        expected_sha256 = hashlib.sha256(pdf_data).hexdigest()

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_storage = Path(tmpdir)
            app.config["STORAGE_DIR"] = temp_storage

            doc_path = temp_storage / "files" / "testuser"
            doc_path.mkdir(parents=True, exist_ok=True)

            mock_conn = app.config['mock_db_conn']

            # ===== Step 1: Upload document =====
            mock_insert_result = MagicMock()
            mock_insert_result.lastrowid = 1

            mock_scalar_result = MagicMock()
            mock_scalar_result.scalar.return_value = 1

            upload_time = datetime.utcnow()
            upload_row = MockRow(
                id=1,
                name="Test Document",
                creation=upload_time,
                sha256_hex=expected_sha256,
                size=len(pdf_data)
            )
            mock_select_result = MagicMock()
            mock_select_result.one.return_value = upload_row

            mock_conn.execute.side_effect = [
                mock_insert_result,  # INSERT
                mock_scalar_result,  # LAST_INSERT_ID
                mock_select_result  # SELECT
            ]

            upload_data = {
                'file': (io.BytesIO(pdf_data), 'test.pdf', 'application/pdf'),
                'name': 'Test Document'
            }

            upload_response = client.post(
                "/api/upload-document",
                data=upload_data,
                headers=headers,
                content_type='multipart/form-data'
            )
            assert upload_response.status_code == 201
            doc_id = upload_response.get_json()["id"]

            uploaded_files = list(doc_path.glob("*__test.pdf"))
            assert len(uploaded_files) == 1, f"Expected 1 uploaded file, found {len(uploaded_files)}"
            uploaded_file_path = uploaded_files[0]

            assert uploaded_file_path.read_bytes() == pdf_data

            # ===== Step 2: List documents =====
            mock_conn.execute.side_effect = None

            list_row = MockRow(
                id=1,
                name="Test Document",
                creation=upload_time,
                sha256_hex=expected_sha256,
                size=len(pdf_data)
            )
            mock_list_result = MagicMock()
            mock_list_result.all.return_value = [list_row]
            mock_conn.execute.return_value = mock_list_result

            list_response = client.get("/api/list-documents", headers=headers)
            assert list_response.status_code == 200
            docs = list_response.get_json()["documents"]
            assert len(docs) == 1
            assert docs[0]["id"] == doc_id

            # ===== Step 3: Get document =====
            get_doc_row = MockRow(
                id=1,
                name="Test Document",
                path=str(uploaded_file_path),
                sha256_hex=expected_sha256,
                size=len(pdf_data)
            )

            mock_get_result = MagicMock()
            mock_get_result.first.return_value = get_doc_row
            mock_conn.execute.return_value = mock_get_result

            get_response = client.get(f"/api/get-document/{doc_id}", headers=headers)
            assert get_response.status_code == 200
            assert get_response.content_type == 'application/pdf'
            assert get_response.data == pdf_data

            # ===== Step 4: Delete document =====
            delete_doc_row = MockRow(
                id=1,
                path=str(uploaded_file_path)
            )

            mock_delete_doc_result = MagicMock()
            mock_delete_doc_result.first.return_value = delete_doc_row

            mock_delete_versions_result = MagicMock()
            mock_delete_versions_result.fetchall.return_value = []

            mock_conn.execute.side_effect = [
                mock_delete_doc_result,  # SELECT document
                mock_delete_versions_result,  # SELECT versions
                MagicMock()  # DELETE
            ]

            delete_response = client.delete(f"/api/delete-document/{doc_id}", headers=headers)
            assert delete_response.status_code == 200
            assert delete_response.get_json()["deleted"] is True

            assert not uploaded_file_path.exists()