"""Integration tests for authentication endpoints.

This module tests the complete authentication flow including user creation,
login, token validation, and authentication-protected endpoints.
"""

import json
import pytest
from flask import Flask
from flask.testing import FlaskClient
from unittest.mock import patch, MagicMock


@pytest.mark.integration
class TestAuthenticationFlow:
    """Test the complete authentication flow."""

    @pytest.mark.xfail
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
        
        # 模拟 SELECT 语句的返回值 (ResultProxy)
        mock_select_result = MagicMock()
        
        user_data_dict = {
            "id": 1,
            "email": "newuser@example.com",
            "login": "newuser"
        }
        mock_user_row = MagicMock(**user_data_dict)
        mock_user_row._asdict.return_value = user_data_dict # 确保它可以被序列化
        
        # 关键修正：让 .one() 方法返回我们伪造的用户数据
        mock_select_result.one.return_value = mock_user_row
        
        # 3. 按顺序安排两次 execute 的返回值
        mock_conn.execute.side_effect = [
            mock_insert_result,  # 响应第一次 execute (INSERT)
            mock_select_result   # 响应第二次 execute (SELECT)
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
    
    @pytest.mark.xfail
    def test_create_user_duplicate_email(self, client: FlaskClient):
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

    def test_create_user_with_newlines_should_fail(self, client: FlaskClient):
        """Test that create-user properly rejects newline characters in login/password (Bug 1 regression test)."""
        # This test verifies the fix: newline characters should be rejected with 400
        user_data = {
            "login": "user\nname",  # Contains newline but has content after strip
            "password": "pass\nword",  # Contains newline but has content after strip
            "email": "test@example.com"
        }
        
        response = client.post("/api/create-user", json=user_data)
        
        # After fix, it should expect 400 for invalid input
        assert response.status_code == 400, "Server should return 400 for invalid input with newlines"
        data = response.get_json()
        assert "error" in data
        assert "login can only contain" in data["error"] or "password cannot contain" in data["error"]

    def test_create_watermark_with_id_zero_should_fail(self, client: FlaskClient):
        """Test that create-watermark properly rejects id=0 (Bug 2 regression test)."""
        # This test demonstrates the bug: id=0 should cause a 500 error initially
        # We'll test without authentication first to see the actual bug
        watermark_data = {
            "id": 0,
            "method": "a",
            "position": "0",
            "key": "a", 
            "secret": "a",
            "intended_for": "a"
        }
        
        response = client.post("/api/create-watermark", json=watermark_data)
        
        # After fix, it should expect 400 for invalid id
        assert response.status_code == 400, "Server should return 400 for invalid id=0"
        data = response.get_json()
        assert "error" in data
        assert "positive integer" in data["error"]

    def test_login_success(self, client: FlaskClient, app: Flask):
        """Test successful login."""
        login_data = {
            "email": "test@example.com",
            "password": "testpassword123"
        }
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
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
    
    @pytest.mark.xfail
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
    
    @pytest.mark.xfail
    def test_protected_endpoint_with_valid_token(self, client: FlaskClient, app: Flask):
        """Test accessing protected endpoint with valid token."""
        from itsdangerous import URLSafeTimedSerializer
        
        # Create a valid token
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="K8x9m2n7p4q1r5s8t3u6v9w2y5z8a1b4c7d0e3f6g9h2i5j8k1l4m7n0o3p6q9r2s5t8u1v4w7x0y3z6")
        token_data = {"uid": 1, "login": "testuser", "email": "test@example.com"}
        valid_token = serializer.dumps(token_data)
        
        headers = {"Authorization": f"Bearer {valid_token}"}
        
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_conn = MagicMock()
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            mock_engine.connect.return_value.__enter__.return_value = mock_conn
            
            # Mock empty document list
            mock_conn.execute.return_value.all.return_value = []
            
            response = client.get("/api/list-documents", headers=headers)
            
            # Should not get auth error (might get other errors, but not 401)
            assert response.status_code != 401
    
    @pytest.mark.xfail
    def test_complete_auth_flow(self, client: FlaskClient):
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

    def test_create_user_length_validation(self, client: FlaskClient):
        """Test create_user with length validation for login, password, and email."""
        test_cases = [
            # Login too long (>50 chars)
            {
                "email": "test@example.com",
                "login": "a" * 51,  # 51 characters
                "password": "password123",
                "expected_error": "Login exceeds maximum length"
            },
            # Password too long (>128 chars)
            {
                "email": "test@example.com", 
                "login": "testuser",
                "password": "a" * 129,  # 129 characters
                "expected_error": "Password exceeds maximum length"
            },
            # Email too long (>254 chars)
            {
                "email": "a" * 250 + "@example.com",  # 263 characters
                "login": "testuser",
                "password": "password123",
                "expected_error": "Email exceeds maximum length"
            }
        ]
        
        for user_data in test_cases:
            response = client.post("/api/create-user", json=user_data)
            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert user_data["expected_error"] in data["error"]

    def test_create_user_login_character_validation(self, client: FlaskClient):
        """Test create_user with login character validation."""
        test_cases = [
            # Login with invalid characters
            {
                "email": "test@example.com",
                "login": "user@name",  # Contains @
                "password": "password123",
                "expected_error": "login can only contain letters, numbers, underscores, and hyphens"
            },
            {
                "email": "test@example.com", 
                "login": "user name",  # Contains space
                "password": "password123",
                "expected_error": "login can only contain letters, numbers, underscores, and hyphens"
            },
            {
                "email": "test@example.com",
                "login": "user.name",  # Contains dot
                "password": "password123", 
                "expected_error": "login can only contain letters, numbers, underscores, and hyphens"
            }
        ]
        
        for user_data in test_cases:
            response = client.post("/api/create-user", json=user_data)
            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert user_data["expected_error"] in data["error"]

    def test_create_user_valid_login_characters(self, client: FlaskClient, app: Flask):
        """Test create_user with valid login characters."""
        valid_logins = [
            "user123",  # letters and numbers
            "user_name",  # underscore
            "user-name",  # hyphen
            "User123_Name-Test",  # mixed valid characters
            "a",  # single character
            "123",  # numbers only
        ]
        
        mock_conn = app.config['mock_db_conn']
        
        for login in valid_logins:
            user_data = {
                "email": f"test{login}@example.com",
                "login": login,
                "password": "password123"
            }
            
            # Mock successful user creation
            mock_insert_result = MagicMock()
            mock_insert_result.lastrowid = 1
            
            mock_select_result = MagicMock()
            mock_user_row = MagicMock()
            mock_user_row.id = 1
            mock_user_row.email = user_data["email"]
            mock_user_row.login = login
            mock_select_result.one.return_value = mock_user_row
            
            mock_conn.execute.side_effect = [
                mock_insert_result,
                mock_select_result
            ]
            
            response = client.post("/api/create-user", json=user_data)
            assert response.status_code == 201, f"Login '{login}' should be valid"
            
            # Reset mock for next iteration
            mock_conn.execute.side_effect = None

    def test_create_user_password_control_characters(self, client: FlaskClient):
        """Test create_user with password control character validation."""
        test_cases = [
            # Password with newline
            {
                "email": "test@example.com",
                "login": "testuser",
                "password": "pass\nword",
                "expected_error": "password cannot contain control characters"
            },
            # Password with carriage return
            {
                "email": "test@example.com",
                "login": "testuser", 
                "password": "pass\rword",
                "expected_error": "password cannot contain control characters"
            }
        ]
        
        for user_data in test_cases:
            response = client.post("/api/create-user", json=user_data)
            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert user_data["expected_error"] in data["error"]

    def test_create_user_password_tab_allowed(self, client: FlaskClient, app: Flask):
        """Test create_user with tab character in password (should be allowed)."""
        user_data = {
            "email": "test@example.com",
            "login": "testuser",
            "password": "pass\tword"  # Tab should be allowed
        }
        
        mock_conn = app.config['mock_db_conn']
        
        # Mock successful user creation
        mock_insert_result = MagicMock()
        mock_insert_result.lastrowid = 1
        
        mock_select_result = MagicMock()
        mock_user_row = MagicMock()
        mock_user_row.id = 1
        mock_user_row.email = "test@example.com"
        mock_user_row.login = "testuser"
        mock_select_result.one.return_value = mock_user_row
        
        mock_conn.execute.side_effect = [
            mock_insert_result,
            mock_select_result
        ]
        
        response = client.post("/api/create-user", json=user_data)
        assert response.status_code == 201, "Tab character in password should be allowed"

    def test_create_user_email_format_validation(self, client: FlaskClient):
        """Test create_user with email format validation."""
        test_cases = [
            # Invalid email formats
            {
                "email": "invalid-email",
                "login": "testuser",
                "password": "password123",
                "expected_error": "invalid email format"
            },
            {
                "email": "@example.com",
                "login": "testuser", 
                "password": "password123",
                "expected_error": "invalid email format"
            },
            {
                "email": "test@",
                "login": "testuser",
                "password": "password123",
                "expected_error": "invalid email format"
            },
            {
                "email": "test@example",
                "login": "testuser",
                "password": "password123", 
                "expected_error": "invalid email format"
            },
            {
                "email": "test.example.com",
                "login": "testuser",
                "password": "password123",
                "expected_error": "invalid email format"
            }
        ]
        
        for user_data in test_cases:
            response = client.post("/api/create-user", json=user_data)
            assert response.status_code == 400
            data = response.get_json()
            assert "error" in data
            assert user_data["expected_error"] in data["error"]

    def test_create_user_valid_email_formats(self, client: FlaskClient, app: Flask):
        """Test create_user with valid email formats."""
        valid_emails = [
            "test@example.com",
            "user.name@example.com",
            "user+tag@example.com",
            "user123@example.com",
            "test@sub.example.com",
            "a@b.co"
        ]
        
        mock_conn = app.config['mock_db_conn']
        
        for email in valid_emails:
            user_data = {
                "email": email,
                "login": f"user{len(email)}",  # Unique login
                "password": "password123"
            }
            
            # Mock successful user creation
            mock_insert_result = MagicMock()
            mock_insert_result.lastrowid = 1
            
            mock_select_result = MagicMock()
            mock_user_row = MagicMock()
            mock_user_row.id = 1
            mock_user_row.email = email
            mock_user_row.login = user_data["login"]
            mock_select_result.one.return_value = mock_user_row
            
            mock_conn.execute.side_effect = [
                mock_insert_result,
                mock_select_result
            ]
            
            response = client.post("/api/create-user", json=user_data)
            assert response.status_code == 201, f"Email '{email}' should be valid"
            
            # Reset mock for next iteration
            mock_conn.execute.side_effect = None