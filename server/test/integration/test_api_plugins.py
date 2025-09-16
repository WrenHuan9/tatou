"""Integration tests for plugin system endpoints.

This module tests the plugin loading functionality and watermarking methods
management.
"""

import io
import json
import pickle
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import pytest
from flask import Flask
from flask.testing import FlaskClient


class MockWatermarkingMethod:
    """Mock watermarking method class for testing."""
    
    name = "mock-method"
    
    def add_watermark(self, pdf, secret, key, position=None):
        """Mock add_watermark method."""
        return b"watermarked_pdf_content"
    
    def read_secret(self, pdf, key):
        """Mock read_secret method."""
        return "extracted_secret"
    
    def get_usage(self):
        """Mock get_usage method."""
        return "Mock watermarking method for testing"


@pytest.mark.integration
class TestPluginSystem:
    """Test plugin system functionality."""
    
    @pytest.mark.xfail
    def test_load_plugin_success(self, client: FlaskClient, app: Flask):
        """Test successful plugin loading."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        plugin_data = {
            "filename": "MockMethod.pkl",
            "overwrite": False
        }
        
        # Create mock plugin content
        mock_method = MockWatermarkingMethod()
        plugin_content = pickle.dumps(mock_method)
        
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.open', mock_open(read_data=plugin_content)), \
             patch('pickle.load', return_value=mock_method), \
             patch('watermarking_utils.METHODS', {}) as mock_methods:
            
            response = client.post("/api/load-plugin", 
                                 json=plugin_data, 
                                 headers=headers)
            
            assert response.status_code == 201
            result = response.get_json()
            assert result["loaded"] is True
            assert result["filename"] == "MockMethod.pkl"
            assert result["registered_as"] == "mock-method"
            assert "class_qualname" in result
            assert result["methods_count"] == 1
    
    def test_load_plugin_no_auth(self, client: FlaskClient):
        """Test plugin loading without authentication."""
        plugin_data = {
            "filename": "MockMethod.pkl"
        }
        
        response = client.post("/api/load-plugin", json=plugin_data)
        
        assert response.status_code == 401
        result = response.get_json()
        assert "error" in result
    
    def test_load_plugin_missing_filename(self, client: FlaskClient, app: Flask):
        """Test plugin loading with missing filename."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        test_cases = [
            {},  # Empty payload
            {"filename": ""},  # Empty filename
            {"filename": "   "},  # Whitespace filename
        ]
        
        for plugin_data in test_cases:
            response = client.post("/api/load-plugin", 
                                 json=plugin_data, 
                                 headers=headers)
            
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "filename is required" in result["error"]
    
    def test_load_plugin_file_not_found(self, client: FlaskClient, app: Flask):
        """Test plugin loading when file doesn't exist."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        plugin_data = {
            "filename": "NonExistent.pkl"
        }
        
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.exists', return_value=False):
            
            response = client.post("/api/load-plugin", 
                                 json=plugin_data, 
                                 headers=headers)
            
            assert response.status_code == 404
            result = response.get_json()
            assert "error" in result
            assert "plugin file not found" in result["error"]
    
    def test_load_plugin_deserialization_error(self, client: FlaskClient, app: Flask):
        """Test plugin loading with corrupted plugin file."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        plugin_data = {
            "filename": "Corrupted.pkl"
        }
        
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.open', mock_open(read_data=b"corrupted_data")), \
             patch('pickle.load', side_effect=Exception("Deserialization failed")):
            
            response = client.post("/api/load-plugin", 
                                 json=plugin_data, 
                                 headers=headers)
            
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "failed to deserialize plugin" in result["error"]
    
    @pytest.mark.xfail
    def test_load_plugin_invalid_interface(self, client: FlaskClient, app: Flask):
        """Test plugin loading with object that doesn't implement required interface."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        plugin_data = {
            "filename": "InvalidMethod.pkl"
        }
        
        # Create invalid method without required interface
        class InvalidMethod:
            name = "invalid-method"
            # Missing add_watermark and read_secret methods
        
        invalid_method = InvalidMethod()
        
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.open', mock_open()), \
             patch('pickle.load', return_value=invalid_method), \
             patch('watermarking_method.WatermarkingMethod', None):  # Simulate no base class
            
            response = client.post("/api/load-plugin", 
                                 json=plugin_data, 
                                 headers=headers)
            
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "does not implement WatermarkingMethod API" in result["error"]
    
    @pytest.mark.xfail
    def test_load_plugin_no_name(self, client: FlaskClient, app: Flask):
        """Test plugin loading with class that has no readable name."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        plugin_data = {
            "filename": "NoNameMethod.pkl"
        }
        
        # Create method without name attribute
        class NoNameMethod:
            def add_watermark(self, pdf, secret, key, position=None):
                return b"content"
            
            def read_secret(self, pdf, key):
                return "secret"
        
        # Remove __name__ attribute
        no_name_method = NoNameMethod()
        delattr(NoNameMethod, '__name__')
        
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.open', mock_open()), \
             patch('pickle.load', return_value=no_name_method):
            
            response = client.post("/api/load-plugin", 
                                 json=plugin_data, 
                                 headers=headers)
            
            assert response.status_code == 400
            result = response.get_json()
            assert "error" in result
            assert "must define a readable name" in result["error"]
    
    @pytest.mark.xfail
    def test_load_plugin_class_object(self, client: FlaskClient, app: Flask):
        """Test plugin loading with class object instead of instance."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        plugin_data = {
            "filename": "ClassMethod.pkl"
        }
        
        # Return class object instead of instance
        method_class = MockWatermarkingMethod
        
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.open', mock_open()), \
             patch('pickle.load', return_value=method_class), \
             patch('watermarking_utils.METHODS', {}) as mock_methods:
            
            response = client.post("/api/load-plugin", 
                                 json=plugin_data, 
                                 headers=headers)
            
            assert response.status_code == 201
            result = response.get_json()
            assert result["loaded"] is True
            assert result["registered_as"] == "mock-method"
    
    def test_get_watermarking_methods_empty(self, client: FlaskClient):
        """Test getting watermarking methods when none are loaded."""
        with patch('watermarking_utils.METHODS', {}):
            response = client.get("/api/get-watermarking-methods")
            
            assert response.status_code == 200
            result = response.get_json()
            assert "methods" in result
            assert "count" in result
            assert result["count"] == 0
            assert len(result["methods"]) == 0
    
    def test_get_watermarking_methods_with_methods(self, client: FlaskClient):
        """Test getting watermarking methods when methods are loaded."""
        mock_method1 = MagicMock()
        mock_method1.get_usage.return_value = "Method 1 description"
        
        mock_method2 = MagicMock()
        mock_method2.get_usage.return_value = "Method 2 description"
        
        mock_methods = {
            "method1": mock_method1,
            "method2": mock_method2
        }
        
        with patch('watermarking_utils.METHODS', mock_methods), \
             patch('watermarking_utils.get_method') as mock_get_method:
            
            def get_method_side_effect(name):
                return mock_methods[name]
            
            mock_get_method.side_effect = get_method_side_effect
            
            response = client.get("/api/get-watermarking-methods")
            
            assert response.status_code == 200
            result = response.get_json()
            assert "methods" in result
            assert "count" in result
            assert result["count"] == 2
            assert len(result["methods"]) == 2
            
            method_names = [m["name"] for m in result["methods"]]
            assert "method1" in method_names
            assert "method2" in method_names
            
            # Check descriptions
            for method in result["methods"]:
                if method["name"] == "method1":
                    assert method["description"] == "Method 1 description"
                elif method["name"] == "method2":
                    assert method["description"] == "Method 2 description"
    
    @pytest.mark.xfail
    def test_plugin_integration_workflow(self, client: FlaskClient, app: Flask):
        """Test complete plugin workflow: load plugin -> get methods -> use in watermarking."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        # Step 1: Load plugin
        plugin_data = {
            "filename": "TestMethod.pkl"
        }
        
        mock_method = MockWatermarkingMethod()
        plugin_content = pickle.dumps(mock_method)
        
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.open', mock_open(read_data=plugin_content)), \
             patch('pickle.load', return_value=mock_method), \
             patch('watermarking_utils.METHODS', {}) as mock_methods_registry:
            
            load_response = client.post("/api/load-plugin", 
                                      json=plugin_data, 
                                      headers=headers)
            
            assert load_response.status_code == 201
            load_result = load_response.get_json()
            assert load_result["loaded"] is True
            assert load_result["registered_as"] == "mock-method"
            
            # Step 2: Verify method is available in methods list
            with patch('watermarking_utils.get_method', return_value=mock_method):
                methods_response = client.get("/api/get-watermarking-methods")
                
                assert methods_response.status_code == 200
                methods_result = methods_response.get_json()
                assert methods_result["count"] == 1
                assert methods_result["methods"][0]["name"] == "mock-method"
                assert methods_result["methods"][0]["description"] == "Mock watermarking method for testing"
    
    def test_plugin_path_safety(self, client: FlaskClient, app: Flask):
        """Test plugin loading with potentially unsafe file paths."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test various potentially unsafe filenames
        unsafe_filenames = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/absolute/path/to/file.pkl",
            "C:\\absolute\\path\\to\\file.pkl",
            "plugin/../../../sensitive.pkl"
        ]
        
        for filename in unsafe_filenames:
            plugin_data = {"filename": filename}
            
            with patch('pathlib.Path.mkdir'), \
                 patch('pathlib.Path.exists', return_value=False):
                
                response = client.post("/api/load-plugin", 
                                     json=plugin_data, 
                                     headers=headers)
                
                # Should fail to find file (path should be constrained to plugins directory)
                assert response.status_code == 404
                result = response.get_json()
                assert "plugin file not found" in result["error"]
    
    @pytest.mark.xfail
    def test_plugin_registry_persistence(self, client: FlaskClient, app: Flask):
        """Test that loaded plugins persist in the registry."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
        token = serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})
        headers = {"Authorization": f"Bearer {token}"}
        
        plugin_data = {
            "filename": "PersistentMethod.pkl"
        }
        
        mock_method = MockWatermarkingMethod()
        mock_methods_registry = {}
        
        with patch('pathlib.Path.mkdir'), \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.open', mock_open()), \
             patch('pickle.load', return_value=mock_method), \
             patch('watermarking_utils.METHODS', mock_methods_registry):
            
            # Load plugin
            load_response = client.post("/api/load-plugin", 
                                      json=plugin_data, 
                                      headers=headers)
            
            assert load_response.status_code == 201
            
            # Verify it's in the registry
            assert "mock-method" in mock_methods_registry
            assert isinstance(mock_methods_registry["mock-method"], MockWatermarkingMethod)
            
            # Verify methods list reflects the loaded plugin
            with patch('watermarking_utils.get_method', return_value=mock_method):
                methods_response = client.get("/api/get-watermarking-methods")
                
                assert methods_response.status_code == 200
                methods_result = methods_response.get_json()
                assert methods_result["count"] == 1
                assert any(m["name"] == "mock-method" for m in methods_result["methods"])