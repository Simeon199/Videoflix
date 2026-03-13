import pytest
from rest_framework.test import APIClient

LOGIN_URL = "/api/login/"
TOKEN_REFRESH_URL = "/api/token/refresh/"

"""
Test module for JWT token refresh functionality.

This module contains comprehensive tests for the token refresh system:
- TestTokenRefreshView API endpoint behavior

Tests cover successful refresh operations, error handling, security aspects
like token leakage prevention, and proper cookie management.
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
    Fixture creating an active user for token refresh testing.
    """
    return create_user(
        email="active@example.com",
        password="securePass123!",
        is_active=True
    )

@pytest.mark.django_db
class TestTokenRefreshView:
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
