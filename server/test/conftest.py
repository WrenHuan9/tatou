"""Common test fixtures and configuration for Tatou server tests."""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask.testing import FlaskClient


@pytest.fixture(scope="session")
def temp_storage() -> Generator[Path, None, None]:
    """Create a temporary storage directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture(scope="session")
def sample_pdf_bytes() -> bytes:
    """Minimal but valid PDF bytes for testing."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000074 00000 n \n"
        b"0000000120 00000 n \n"
        b"trailer\n"
        b"<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n"
        b"202\n"
        b"%%EOF"
    )

@pytest.fixture(scope="session")
def pdf_without_eof() -> bytes:
    """Minimal but valid PDF bytes for testing."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000074 00000 n \n"
        b"0000000120 00000 n \n"
        b"trailer\n"
        b"<< /Size 4 /Root 1 0 R >>\n"
        b"startxref\n"
        b"202\n"
        # Note: no %%EOF marker
    )

@pytest.fixture(scope="session")
def sample_pdf_file(temp_storage: Path, sample_pdf_bytes: bytes) -> Path:
    """Create a sample PDF file for testing."""
    pdf_file = temp_storage / "sample.pdf"
    pdf_file.write_bytes(sample_pdf_bytes)
    return pdf_file


@pytest.fixture
def test_secret() -> str:
    """Test secret for watermarking."""
    return "test-secret-123"


@pytest.fixture
def test_key() -> str:
    """Test key for watermarking."""
    return "test-key-456"


@pytest.fixture
def app_config() -> dict:
    """Test configuration for Flask app."""
    return {
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "STORAGE_DIR": tempfile.mkdtemp(),
        "TOKEN_TTL_SECONDS": 3600,
        "DB_USER": "test_user",
        "DB_PASSWORD": "test_pass",
        "DB_HOST": "localhost",
        "DB_PORT": 3306,
        "DB_NAME": "test_tatou",
    }


@pytest.fixture
def app(app_config: dict) -> Flask:
    """Create Flask app instance for testing."""
    # Set environment variables for the app
    for key, value in app_config.items():
        os.environ[key] = str(value)

    with patch('sqlalchemy.create_engine') as mock_create_engine:
        mock_conn = MagicMock()
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
    
        # Import and create app after setting env vars
        from server.src.server import create_app
        app = create_app()
        app.config.update(app_config)

        app.config['mock_db_engine'] = mock_engine
        app.config['mock_db_conn'] = mock_conn
    
        yield app
    
    # Cleanup
    for key in app_config.keys():
        os.environ.pop(key, None)


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Create Flask test client."""
    return app.test_client()


@pytest.fixture
def test_user_data() -> dict:
    """Sample user data for testing."""
    return {
        "email": "test@example.com",
        "login": "testuser",
        "password": "testpassword123"
    }


@pytest.fixture
def auth_headers(client: FlaskClient, test_user_data: dict) -> dict:
    """Create authenticated headers for API requests."""
    # First create a user
    client.post("/api/create-user", json=test_user_data)
    
    # Then login to get token
    login_response = client.post("/api/login", json={
        "email": test_user_data["email"],
        "password": test_user_data["password"]
    })
    
    if login_response.status_code == 200:
        token = login_response.get_json()["token"]
        return {"Authorization": f"Bearer {token}"}
    
    return {}


@pytest.fixture
def mock_db_engine():
    """Mock database engine for testing."""
    with patch('sqlalchemy.create_engine') as mock_create_engine:
        mock_conn = MagicMock()
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_engine.connect.return_value.__enter__.return_value = mock_conn
        mock_engine.begin.return_value.__enter__.return_value = mock_conn
        yield mock_engine, mock_conn


@pytest.fixture
def mock_storage_operations():
    """Mock file system operations for testing."""
    with patch('pathlib.Path.mkdir') as mock_mkdir, \
         patch('pathlib.Path.exists') as mock_exists, \
         patch('pathlib.Path.stat') as mock_stat, \
         patch('pathlib.Path.resolve') as mock_resolve, \
         patch('pathlib.Path.relative_to') as mock_relative_to, \
         patch('pathlib.Path.unlink') as mock_unlink, \
         patch('pathlib.Path.open') as mock_open_file:
        
        # Set default return values
        mock_exists.return_value = True
        mock_stat.return_value.st_size = 1024
        mock_stat.return_value.st_mtime = 1640995200.0
        mock_resolve.return_value = Path("/storage/test/file.pdf")
        
        yield {
            'mkdir': mock_mkdir,
            'exists': mock_exists, 
            'stat': mock_stat,
            'resolve': mock_resolve,
            'relative_to': mock_relative_to,
            'unlink': mock_unlink,
            'open': mock_open_file
        }


@pytest.fixture
def mock_watermarking_utils():
    """Mock watermarking utilities for testing."""
    with patch('watermarking_utils.is_watermarking_applicable') as mock_applicable, \
         patch('watermarking_utils.apply_watermark') as mock_apply, \
         patch('watermarking_utils.read_watermark') as mock_read, \
         patch('watermarking_utils.get_method') as mock_get_method, \
         patch('watermarking_utils.METHODS', {}) as mock_methods:
        
        # Set default return values
        mock_applicable.return_value = True
        mock_apply.return_value = b"%PDF-1.4\nwatermarked content\n%%EOF"
        mock_read.return_value = "extracted-secret"
        
        yield {
            'is_applicable': mock_applicable,
            'apply_watermark': mock_apply,
            'read_watermark': mock_read,
            'get_method': mock_get_method,
            'methods_registry': mock_methods
        }


@pytest.fixture
def sample_document_data() -> Dict[str, Any]:
    """Sample document data for testing."""
    return {
        "id": 1,
        "name": "test-document.pdf",
        "path": "/storage/files/testuser/test-document.pdf",
        "owner_id": 1,
        "sha256": "abcd1234567890",
        "size": 1024,
        "creation": "2023-01-01T00:00:00"
    }


@pytest.fixture
def sample_version_data() -> Dict[str, Any]:
    """Sample version data for testing."""
    return {
        "id": 1,
        "document_id": 1,
        "link": "abc123def456",
        "intended_for": "john.doe@example.com",
        "secret": "confidential-info",
        "method": "add-after-eof",
        "position": "bottom-right",
        "path": "/storage/files/testuser/watermarks/test__john.pdf"
    }


@pytest.fixture
def sample_watermark_request() -> Dict[str, Any]:
    """Sample watermark creation request data."""
    return {
        "method": "add-after-eof",
        "intended_for": "john.doe@example.com",
        "secret": "confidential-info-123",
        "key": "encryption-key-456",
        "position": "bottom-right"
    }


@pytest.fixture
def multiple_test_users() -> list[Dict[str, str]]:
    """Multiple test users for testing user interactions."""
    return [
        {
            "email": "alice@example.com",
            "login": "alice",
            "password": "alicepassword123"
        },
        {
            "email": "bob@example.com", 
            "login": "bob",
            "password": "bobpassword123"
        },
        {
            "email": "charlie@example.com",
            "login": "charlie", 
            "password": "charliepassword123"
        }
    ]


@pytest.fixture
def temp_plugin_file(temp_storage: Path) -> Path:
    """Create a temporary plugin file for testing."""
    import pickle
    
    class MockPlugin:
        name = "test-plugin"
        
        def add_watermark(self, pdf, secret, key, position=None):
            return b"watermarked_content"
            
        def read_secret(self, pdf, key):
            return "extracted_secret"
            
        def get_usage(self):
            return "Test plugin for integration tests"
    
    plugin_dir = temp_storage / "plugins"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    
    plugin_file = plugin_dir / "test_plugin.pkl"
    with plugin_file.open("wb") as f:
        pickle.dump(MockPlugin(), f)
    
    return plugin_file


@pytest.fixture(autouse=True)
def cleanup_temp_files():
    """Automatically cleanup temporary files after each test."""
    yield
    # Cleanup logic could go here if needed
    pass


@pytest.fixture
def integration_test_config() -> Dict[str, Any]:
    """Configuration specifically for integration tests."""
    temp_dir = tempfile.mkdtemp()
    return {
        "TESTING": True,
        "SECRET_KEY": "integration-test-secret-key-12345",
        "STORAGE_DIR": temp_dir,
        "TOKEN_TTL_SECONDS": 3600,
        "DB_USER": "integration_test_user",
        "DB_PASSWORD": "integration_test_pass",
        "DB_HOST": "localhost",
        "DB_PORT": 3306,
        "DB_NAME": "integration_test_tatou",
        "WTF_CSRF_ENABLED": False,  # Disable CSRF for testing
        "PRESERVE_CONTEXT_ON_EXCEPTION": False
    }


@pytest.fixture
def isolated_app(integration_test_config: Dict[str, Any]) -> Flask:
    """Create an isolated Flask app instance for integration tests."""
    # Set environment variables
    original_env = {}
    for key, value in integration_test_config.items():
        original_env[key] = os.environ.get(key)
        os.environ[key] = str(value)
    
    try:
        # Import and create app after setting env vars
        from server.src.server import create_app
        app = create_app()
        app.config.update(integration_test_config)
        yield app
    finally:
        # Restore original environment
        for key, original_value in original_env.items():
            if original_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original_value
        
        # Cleanup temp directory
        temp_dir = integration_test_config["STORAGE_DIR"]
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def integration_client(isolated_app: Flask) -> FlaskClient:
    """Create Flask test client for integration tests."""
    return isolated_app.test_client()


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "integration: Integration tests that test full workflows")
    config.addinivalue_line("markers", "unit: Unit tests that test individual components")
    config.addinivalue_line("markers", "slow: Tests that take a long time to run")
    config.addinivalue_line("markers", "database: Tests that require database connectivity")
    config.addinivalue_line("markers", "filesystem: Tests that require filesystem operations")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location."""
    for item in items:
        # Add integration marker to tests in integration directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        # Add unit marker to tests in unit directory  
        elif "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
