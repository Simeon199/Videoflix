import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from auth_app.api.serializers import LoginSerializer

LOGIN_URL = "/api/login/"
LOGOUT_URL = "/api/logout/"
TOKEN_REFRESH_URL = "/api/token/refresh"

"""
Test module for authentication functionality including login, logout, and token refresh.

This module contains comprehensive tests for the authentication system's core features:
- LoginSerializer validation
- LoginView API endpoint behavior
- LogoutView API endpoint behavior
- TokenRefreshView API endpoint behavior

Tests cover successful operations, error handling, security aspects like token blacklisting,
and proper cookie management for JWT tokens.
"""

@pytest.fixture
def api_client():
    """
    Fixture providing a configured APIClient instance for testing API endpoints.
    """
    return APIClient()

@pytest.fixture
def active_user(create_user):
    """
    Fixture creating an active user for authentication testing.
    """
    return create_user(
        email="active@example.com", 
        password="securePass123!",
        is_active=True
    )

@pytest.fixture
def inactive_user(create_user):
    """
    Fixture creating an inactive user for testing authentication restrictions.
    """
    return create_user(
        email="inactive@example.com",
        password="securePass123!",
        is_active=False
    )

# LoginSerializer

@pytest.mark.django_db
class TestLoginSerializer:
    """
    Test class for LoginSerializer validation logic.
    """

    def test_valid_credentials(self, active_user):
        """
        Test that valid credentials are accepted and user is returned.
        """
        data = {
            "email": "active@example.com",
            "password": "securePass123!"
        }
        serializer = LoginSerializer(data=data)
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data["user"] == active_user

    def test_wrong_password(self, active_user):
        """
        Test that incorrect password is rejected with non_field_errors.
        """
        data = {
            "email": "active@example.com",
            "password": "wrongPassword"
        }
        serializer = LoginSerializer(data=data)
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors

    def test_nonexistent_user(self):
        """
        Test that login with non-existent user email is rejected.
        """
        data = {
            "email": "ghost@example.com",
            "password": "somePass123!"
        }
        serializer=LoginSerializer(data=data)
        assert not serializer.is_valid()

    def test_inactive_user_rejected(self, inactive_user):
        """
        Test that inactive users are rejected during login.
        """
        data = {
            "email": "inactive@example.com",
            "password": "securePass123!"
        }
        serializer = LoginSerializer(data=data)
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors


    def test_missing_email(self):
        """
        Test that missing email field causes validation error.
        """
        serializer = LoginSerializer(data={
            "password": "securePass123!"
        })
        assert not serializer.is_valid()
        assert "email" in serializer.errors

    def test_missing_password(self):
        """
        Test that missing password field causes validation error.
        """
        serializer = LoginSerializer(data={
            "email": "active@example.com"
        })
        assert not serializer.is_valid()
        assert "password" in serializer.errors

# LoginView

@pytest.mark.django_db
class TestLoginView:
    """
    Test class for LoginView API endpoint behavior.
    """

    def test_successfull_login_status(self, api_client, active_user):
        """
        Test that successful login returns 200 status code.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert response.status_code == 200

    def test_successfull_login_response_body(self, api_client, active_user):
        """
        Test that successful login returns correct response body with user details.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert response.data["detail"] == "Login successful"
        assert response.data["user"]["id"] == active_user.id
        assert response.data["user"]["username"] == active_user.username

    def test_access_cookie_set(self, api_client, active_user):
        """
        Test that access token cookie is set after successful login.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert "access_token" in response.cookies

    def test_refresh_token_cookie_set(self, api_client, active_user):
        """
        Test that refresh token cookie is set after successful login.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert "refresh_token" in response.cookies

    def test_cookies_are_httponly(self, api_client, active_user):
        """
        Test that both access and refresh token cookies are HttpOnly.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert response.cookies["access_token"]["httponly"]
        assert response.cookies["refresh_token"]["httponly"]

    def test_wrong_credentials_rejected(self, api_client, active_user):
        """
        Test that wrong credentials result in 400 status code.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "wrongPass!"
            },
            format="json"
        )
        assert response.status_code == 400

    def test_inactive_user_rejected(self, api_client, inactive_user):
        """
        Test that inactive users are rejected with 400 status code.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "inactive@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert response.status_code == 400

    def test_missing_fields_rejected(self, api_client):
        """
        Test that requests with missing fields are rejected.
        """
        response = api_client.post(LOGOUT_URL, {}, format="json")
        assert response.status_code == 400

    def test_no_tokens_in_response_body(self, api_client, active_user):
        """
        Test that tokens are not included in the response body for security.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": "active@example.com",
                "password": "securePass123!"
            },
            format="json"
        )
        assert "access_token" not in response.data
        assert "refresh_token" not in response.data

# LogoutView

@pytest.mark.django_db
class TestLogoutView:
    """
    Test class for LogoutView API endpoint behavior.
    """

    def _login(self, api_client, email, password):
        """
        Helper method to perform login and return refresh token.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": email,
                "password": password
            },
            format="json"
        )
        return response.cookies.get("refresh_token").value
    
    def test_successful_logout_status(self, api_client, active_user):
        """
        Test that successful logout returns 200 status code.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] == refresh_token
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 200

    def test_successful_response_body(self, api_client, active_user):
        """
        Test that successful logout returns appropriate response message.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] == refresh_token
        response = api_client.post(LOGOUT_URL, format="json")
        assert "Logout successful" in response.data["detail"]
        assert "Refresh token is now invalid" in response.data["detail"]

    def test_cookies_deleted_after_logout(self, api_client, active_user):
        """
        Test that cookies are cleared after successful logout.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.cookies["access_token"].value == ""
        assert response.cookies["refresh_token"].value == ""

    def test_logout_without_cookie_returns_400(self, api_client, active_user):
        """
        Test that logout without refresh token cookie returns 400.
        """
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 400
        assert "Refresh-Token fehlt" in response.data["detail"]

    def test_logout_with_invalid_token_returns_400(self, api_client):
        """
        Test that logout with invalid refresh token returns 400.
        """
        api_client.cookies["refresh_token"] = "this.is.not.a.valid.token"
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 400

    def test_token_blacklisted_after_logout(self, api_client, active_user):
        """
        Test that refresh token is blacklisted after logout and cannot be reused.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token

        # Erster Logout - erfolgreich
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 200

        # Zweiter Logout mit demselben Token - muss fehlschlagen
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(LOGOUT_URL, format="json")
        assert response.status_code == 400

# TokenRefreshView

@pytest.mark.django_db
class TokenRefreshView:
    """
    Test class for TokenRefreshView API endpoint behavior.
    """

    def _login(self, api_client, email, password):
        """
        Helper method to perform login and return refresh token.
        """
        response = api_client.post(
            LOGIN_URL,
            {
                "email": email,
                "password": password
            },
            format="json"
        )
        return response.cookies.get("refresh_token").value
    
    def test_successfull_refresh_status(self, api_client, active_user):
        """
        Test that successful token refresh returns 200 status code.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.status_code == 200

    def test_successful_refresh_response_body(self, api_client, active_user):
        """
        Test that successful refresh returns correct response with new access token.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.data["detail"] == "Token refreshed"
        assert "access" in response.data

    def test_new_access_cookie_is_set(self, api_client, active_user):
        """
        Test that a new access token cookie is set after refresh.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert "access_token" in response.cookies
        assert response.cookies["access_token"].value != ""

    def test_new_access_cookie_is_httponly(self, api_client, active_user):
        """
        Test that the new access token cookie is HttpOnly.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.cookies["access_token"]["httponly"]

    def test_refresh_without_cookie_returns_400(self, api_client):
        """
        Test that refresh without refresh token cookie returns 400.
        """
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.status_code == 400
        assert "Refresh-Token fehlt" in response.data["detail"]

    def test_refresh_with_invalid_token_returns_401(self, api_client):
        """
        Test that refresh with invalid token returns 401.
        """
        api_client.cookies["refresh_token"] = "this.is.not.a.valid.token"
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert response.status_code == 401
        assert "Ungültiger Refresh-Token" in response.data["detail"]

    def test_no_token_leakage_in_body(self, api_client, active_user):
        """
        Test that tokens are not leaked in the response body.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert "access_token" not in response.data

    def test_refresh_token_cookie_not_modified(self, api_client, active_user):
        """
        Test that the refresh token cookie is not modified during token refresh.
        """
        refresh_token = self._login(api_client, "active@example.com", "securePass123!")
        api_client.cookies["refresh_token"] = refresh_token
        response = api_client.post(TOKEN_REFRESH_URL, format="json")
        assert "refresh_token" not in response.cookies