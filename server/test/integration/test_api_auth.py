"""Integration tests for authentication endpoints.

This module tests the complete authentication flow including user creation,
login, token validation, and authentication-protected endpoints.
"""

import json
import pytest
from flask import Flask
from flask.testing import FlaskClient
from unittest.mock import patch, MagicMock
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer

@pytest.mark.integration
class TestAuthenticationFlow:
    """Test the complete authentication flow."""

    def test_create_user_success(self, client: FlaskClient, app: Flask):
        """Test successful user creation."""
        user_data = {
            "email": "newuser@example.com",
            "login": "newuser",
            "password": "securepassword123"
        }
        
        mock_conn = app.config['mock_db_conn']
  
        # Mock successful user creation
        mock_insert_result = MagicMock()
        mock_insert_result.lastrowid = 1

        mock_select_result = MagicMock()
        
        user_data_dict = {
            "id": 1,
            "email": "newuser@example.com",
            "login": "newuser"
        }
        mock_user_row = MagicMock(**user_data_dict)
        mock_user_row._asdict.return_value = user_data_dict

        mock_select_result.one.return_value = mock_user_row

        mock_conn.execute.side_effect = [
            mock_insert_result,
            mock_select_result
        ]
        
        response = client.post("/api/create-user", json=user_data)
        
        assert response.status_code == 201
        data = response.get_json()
        assert data["id"] == 1
        assert data["email"] == "newuser@example.com"
        assert data["login"] == "newuser"
    
    def test_create_user_missing_fields(self, client: FlaskClient):
        """Test user creation with missing required fields."""
        test_cases = [
            {},  # Empty payload
            {"email": "test@example.com"},  # Missing login and password
            {"login": "testuser"},  # Missing email and password
            {"password": "password123"},  # Missing email and login
            {"email": "", "login": "testuser", "password": "password123"},  # Empty email
            {"email": "test@example.com", "login": "", "password": "password123"},  # Empty login
            {"email": "test@example.com", "login": "testuser", "password": ""},  # Empty password
        ]
        
        for user_data in test_cases:
            response = client.post("/api/create-user", json=user_data)
            assert response.status_code == 400
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

        mock_conn = app.config['mock_db_conn']

        # Mock IntegrityError for duplicate email
        from sqlalchemy.exc import IntegrityError
        mock_conn.execute.side_effect = IntegrityError("", "", "")

        response = client.post("/api/create-user", json=user_data)

        mock_conn.execute.side_effect = None

        assert response.status_code == 409
        data = response.get_json()
        assert "error" in data
        assert "already exists" in data["error"].lower()

    def test_login_success(self, client: FlaskClient, app: Flask):
        """Test successful login."""
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }

        mock_conn = app.config['mock_db_conn']

        from werkzeug.security import generate_password_hash
        from collections import namedtuple

        UserRow = namedtuple('UserRow', ['id', 'email', 'login', 'hpassword'])
        mock_row = UserRow(
            id=1,
            email="test@example.com",
            login="testuser",
            hpassword=generate_password_hash("testpassword123")
        )

        mock_result = MagicMock()
        mock_result.first.return_value = mock_row
        mock_conn.execute.return_value = mock_result

        response = client.post("/api/login", json=login_data)

        mock_conn.execute.return_value = MagicMock()

        assert response.status_code == 200
        data = response.get_json()
        assert "token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
    

    def test_login_invalid_credentials(self, client: FlaskClient):
        """Test login with invalid credentials."""
        test_cases = [
            {"email": "nonexistent@example.com", "password": "password123"},  # User doesn't exist
            {"email": "test@example.com", "password": "wrongpassword"},  # Wrong password
        ]
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            for login_data in test_cases:
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
                
                assert response.status_code == 401
                data = response.get_json()
                assert "error" in data
                assert "invalid credentials" in data["error"]
    
    def test_login_missing_fields(self, client: FlaskClient):
        """Test login with missing required fields."""
        test_cases = [
            {},  # Empty payload
            {"email": "test@example.com"},  # Missing password
            {"password": "password123"},  # Missing email
            {"email": "", "password": "password123"},  # Empty email
            {"email": "test@example.com", "password": ""},  # Empty password
        ]
        
        for login_data in test_cases:
            response = client.post("/api/login", json=login_data)
            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert "required" in data["error"].lower()
    
    def test_protected_endpoint_without_auth(self, client: FlaskClient):
        """Test accessing protected endpoint without authentication."""
        response = client.get("/api/list-documents")
        
        assert response.status_code == 401
        data = response.get_json()
        assert "error" in data
        assert "Authorization" in data["error"]
    
    def test_protected_endpoint_with_invalid_token(self, client: FlaskClient):
        """Test accessing protected endpoint with invalid token."""
        test_cases = [
            {"Authorization": "Bearer invalid_token"},
            {"Authorization": "Basic dXNlcjpwYXNz"},  # Wrong auth type
            {"Authorization": "Bearer "},  # Empty token
        ]
        
        for headers in test_cases:
            response = client.get("/api/list-documents", headers=headers)
            
            assert response.status_code == 401
            data = response.get_json()
            assert "error" in data
    
    def test_protected_endpoint_with_expired_token(self, client: FlaskClient, app: Flask):
        """Test accessing protected endpoint with expired token."""
        from itsdangerous import URLSafeTimedSerializer
        import time
        
        # Create an expired token
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        
        # Create token that's already expired
        with patch('time.time', return_value=time.time() - 3700):  # 1 hour + 1 minute ago
            expired_token = serializer.dumps(token_data)
        
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = client.get("/api/list-documents", headers=headers)
        
        assert response.status_code == 401
        data = response.get_json()
        assert "error" in data
        assert "expired" in data["error"].lower()

    def test_protected_endpoint_with_valid_token(self, client: FlaskClient, app: Flask):
        """Test accessing protected endpoint with valid token."""
        # Create a valid token
        serializer = URLSafeTimedSerializer(
            app.config["SECRET_KEY"],
            salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6"
        )
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        valid_token = serializer.dumps(token_data)

        headers = {"Authorization": f"Bearer {valid_token}"}

        mock_conn = app.config['mock_db_conn']

        mock_conn.execute.side_effect = None

        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_conn.execute.return_value = mock_result

        response = client.get("/api/list-documents", headers=headers)

        assert response.status_code != 401

        assert response.status_code == 200
        data = response.get_json()
        assert "documents" in data
        assert data["documents"] == []

    def test_complete_auth_flow(self, client: FlaskClient, app: Flask):
        """Test complete authentication flow from user creation to accessing protected endpoint."""
        user_data = {
            "email": "flowtest@example.com",
            "login": "flowtest",
            "password": "flowpassword123"
        }

        mock_conn = app.config['mock_db_conn']

        # Step 1: Create user

        mock_insert_result = MagicMock()
        mock_insert_result.lastrowid = 1

        mock_select_result = MagicMock()
        mock_user_row = MagicMock()
        mock_user_row.id = 1
        mock_user_row.email = "flowtest@example.com"
        mock_user_row.login = "flowtest"
        mock_select_result.one.return_value = mock_user_row

        mock_conn.execute.side_effect = [
            mock_insert_result,  # INSERT INTO Users
            mock_select_result  # SELECT from Users (with .one())
        ]

        create_response = client.post("/api/create-user", json=user_data)
        assert create_response.status_code == 201, f"Expected 201, got {create_response.status_code}"

        response_data = create_response.get_json()
        assert response_data["id"] == 1
        assert response_data["email"] == "flowtest@example.com"
        assert response_data["login"] == "flowtest"

        # Step 2: Login

        mock_conn.execute.side_effect = None

        mock_login_result = MagicMock()
        mock_login_row = MagicMock()
        mock_login_row.id = 1
        mock_login_row.email = "flowtest@example.com"
        mock_login_row.login = "flowtest"
        mock_login_row.hpassword = generate_password_hash("flowpassword123")
        mock_login_result.first.return_value = mock_login_row

        mock_conn.execute.return_value = mock_login_result

        login_response = client.post("/api/login", json={
            "email": user_data["email"],
            "password": user_data["password"]
        })
        assert login_response.status_code == 200, f"Expected 200, got {login_response.status_code}, response: {login_response.get_json()}"

        login_data = login_response.get_json()
        assert "token" in login_data
        assert "token_type" in login_data
        assert login_data["token_type"] == "bearer"
        token = login_data["token"]

        # Step 3: Access protected endpoint
        mock_conn.execute.side_effect = None

        mock_docs_result = MagicMock()
        mock_docs_result.all.return_value = []
        mock_conn.execute.return_value = mock_docs_result

        headers = {"Authorization": f"Bearer {token}"}
        protected_response = client.get("/api/list-documents", headers=headers)

        assert protected_response.status_code == 200, f"Expected 200, got {protected_response.status_code}"
        protected_data = protected_response.get_json()
        assert "documents" in protected_data
        assert protected_data["documents"] == []

    def test_create_user_database_exception(self, client: FlaskClient, app: Flask):
        """Test user creation with database exception."""
        user_data = {
            "email": "test@example.com",
            "login": "testuser",
            "password": "password123"
        }

        mock_conn = app.config['mock_db_conn']

        # Mock database exception (not IntegrityError)
        mock_conn.execute.side_effect = Exception("Database connection failed")

        response = client.post("/api/create-user", json=user_data)

        assert response.status_code == 503
        data = response.get_json()
        assert "error" in data
        assert "Failed to create user" in data["error"]

    def test_login_database_exception(self, client: FlaskClient, app: Flask):
        """Test login with database exception."""
        login_data = {
            "email": "test@example.com",
            "password": "password123"
        }

        mock_conn = app.config['mock_db_conn']

        # Mock database exception
        mock_conn.execute.side_effect = Exception("Database query failed")

        response = client.post("/api/login", json=login_data)

        assert response.status_code == 503
        data = response.get_json()
        assert "error" in data
        assert "Login failed" in data["error"]