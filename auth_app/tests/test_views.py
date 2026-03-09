import pytest
from unittest.mock import patch
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework.test import APIClient

@pytest.fixture
def api_client():
    return APIClient()

REGISTER_URL = "/api/register/"

def _build_activation_url(user):
    uibd64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return f"/api/activate/{uibd64}/{token}/"

# === RegistrationView ===

@pytest.mark.django_db
class TestRegistrationView:

    @patch("auth_app.api.views.send_activation_email")
    def test_successfull_registration(self, mock_send_email, api_client):
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
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "differentPass!"
        }
        response = api_client.post(REGISTER_URL, data, format="json")
        assert response.status_code == 400

    def test_registration_duplicate_email(self, api_client, create_user):
        create_user(email="existing@example.com")
        data = {
            "email": "existing@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        } 
        response = api_client.post(REGISTER_URL, data, format="json")
        assert response.status_code == 400

    def test_registration_missing_fields(self, api_client):
        response = api_client.post(REGISTER_URL, {}, format="json")
        assert response.status_code == 400

    def test_registration_invalid_email(self, api_client):
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

    def test_successfull_activation(self, api_client, create_user):
        user = create_user(email="activate@example.com", is_active=False)
        url = _build_activation_url(user)
        
        response = api_client.get(url)

        assert response.status_code == 200
        assert response.data["message"] == "Account successfully activated"

        user.refresh_from_db()
        assert user.is_active is True

    def test_invalid_uidb64(self, api_client):
        url = "/api/activate/invalid-uid/some-token/"
        response = api_client.get(url)

        assert response.status_code == 400
        assert "error" in response.data

    def test_nonexistent_user(self, api_client):
        uidb64 = urlsafe_base64_encode(force_bytes(99999))
        url = f"/api/activate/{uidb64}/some-token/"
        response = api_client.get(url)

        assert response.status_code == 400

    def test_invalid_token(self, api_client, create_user):
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
        Token should not work a second time (user state changed). 
        """
        user = create_user(email="once@example.com", is_active=False)
        url = _build_activation_url(user)

        # First activation
        response = api_client.get(url)
        assert response.status_code == 200

        # Second activation with same token - token is now invalid because user.is_active changed (affects token hash)
        response = api_client.get(url)
        assert response.status_code == 400