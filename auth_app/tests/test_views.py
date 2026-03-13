import pytest
from unittest.mock import patch
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework.test import APIClient

"""
Test module for authentication view endpoints.

This module contains comprehensive tests for the authentication system's view endpoints:
- RegistrationView API endpoint behavior
- ActivationView API endpoint behavior

Tests cover successful registration and activation flows, error handling,
validation, email sending, and security aspects like token invalidation.
"""

@pytest.fixture
def api_client():
    """
    Fixture providing a configured APIClient instance for testing API endpoints.
    """
    return APIClient()

REGISTER_URL = "/api/register/"

def _build_activation_url(user):
    """
    Helper function to build account activation URL with user ID and token.
    """
    uibd64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return f"/api/activate/{uibd64}/{token}/"

# === RegistrationView ===

@pytest.mark.django_db
class TestRegistrationView:
    """
    Test class for RegistrationView API endpoint behavior.
    """

    @patch("auth_app.api.views.send_activation_email")
    def test_successfull_registration(self, mock_send_email, api_client):
        """
        Test that successful registration creates inactive user and sends activation email.
        """
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        }
        response = api_client.post(REGISTER_URL, data, format="json")

        assert response.status_code == 201
        assert response.data["user"]["email"] == "new@example.com"
        assert "token" in response.data

        user = User.objects.get(email="new@example.com")
        assert user.is_active is False
        mock_send_email.assert_called_once()

    @patch("auth_app.api.views.send_activation_email")
    def test_registration_creates_inactive_user(self, mock_send_email, api_client):
        """
        Test that registration creates user with inactive status and correct username.
        """
        data = {
            "email": "inactive@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        }
        api_client.post(REGISTER_URL, data, format="json")

        user = User.objects.get(email="inactive@example.com")
        assert user.is_active is False
        assert user.username == "inactive@example.com"

    def test_registration_password_mismatch(self, api_client):
        """
        Test that registration fails when passwords don't match.
        """
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "differentPass!"
        }
        response = api_client.post(REGISTER_URL, data, format="json")
        assert response.status_code == 400

    def test_registration_duplicate_email(self, api_client, create_user):
        """
        Test that registration fails with duplicate email address.
        """
        create_user(email="existing@example.com")
        data = {
            "email": "existing@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        } 
        response = api_client.post(REGISTER_URL, data, format="json")
        assert response.status_code == 400

    def test_registration_missing_fields(self, api_client):
        """
        Test that registration fails when required fields are missing.
        """
        response = api_client.post(REGISTER_URL, {}, format="json")
        assert response.status_code == 400

    def test_registration_invalid_email(self, api_client):
        """
        Test that registration fails with invalid email format.
        """
        data = {
            "email": "not-valid",
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        }
        response = api_client.post(REGISTER_URL, data, format="json")
        assert response.status_code == 400

# === ActivationView ===

@pytest.mark.django_db
class TestActivationView:
    """
    Test class for ActivationView API endpoint behavior.
    """

    def test_successfull_activation(self, api_client, create_user):
        """
        Test that valid activation link successfully activates user account.
        """
        user = create_user(email="activate@example.com", is_active=False)
        url = _build_activation_url(user)
        
        response = api_client.get(url)

        assert response.status_code == 200
        assert response.data["message"] == "Account successfully activated."

        user.refresh_from_db()
        assert user.is_active is True

    def test_invalid_uidb64(self, api_client):
        """
        Test that activation fails with invalid user ID in URL.
        """
        url = "/api/activate/invalid-uid/some-token/"
        response = api_client.get(url)

        assert response.status_code == 400
        assert "error" in response.data

    def test_nonexistent_user(self, api_client):
        """
        Test that activation fails for non-existent user ID.
        """
        uidb64 = urlsafe_base64_encode(force_bytes(99999))
        url = f"/api/activate/{uidb64}/some-token/"
        response = api_client.get(url)

        assert response.status_code == 400

    def test_invalid_token(self, api_client, create_user):
        """
        Test that activation fails with invalid token and user remains inactive.
        """
        user = create_user(email="badtoken@example.com", is_active=False)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        url = f"/api/activate/{uidb64}/invalid-token/"

        response = api_client.get(url)

        assert response.status_code == 400
        assert "error" in response.data

        user.refresh_from_db()
        assert user.is_active is False

    def test_token_invalid_after_activation(self, api_client, create_user):
        """
        Test that activation token becomes invalid after successful activation.
        """
        user = create_user(email="once@example.com", is_active=False)
        url = _build_activation_url(user)

        # First activation
        response = api_client.get(url)
        assert response.status_code == 200

        # Second activation with same token - token is now invalid because user.is_active changed (affects token hash)
        response = api_client.get(url)
        assert response.status_code == 400