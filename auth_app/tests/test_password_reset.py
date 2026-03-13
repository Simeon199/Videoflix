import pytest
from unittest.mock import patch
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework.test import APIClient

from auth_app.api.serializers import PasswordResetSerializer, PasswordResetConfirmSerializer

PASSWORD_RESET_URL = "/api/password_reset/"

@pytest.fixture
def api_client():
    return APIClient()

def _build_confirm_url(user):
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return f"/api/password_confirm/{uidb64}/{token}/", token

# PasswordResetSerializer

@pytest.mark.django_db
class TestPasswordResetSerializer:
    
    def test_valid_email_existing_user(self, create_user):
        create_user(email="exists@example.com", is_active=True)
        serializer = PasswordResetSerializer(data={"email": "exists@example.com"})
        assert serializer.is_valid(), serializer.errors

    def test_valid_email_nonexistent_user(self):
        serializer = PasswordResetSerializer(data={"email": "ghost@example.com"})
        assert serializer.is_valid(), serializer.errors

    def test_invalid_email_format(self):
        serializer = PasswordResetSerializer(data={"email": "not-an-email"})
        assert not serializer.is_valid()
        assert "email" in serializer.errors

# PasswordResetConfirmSerializer

class TestPasswordResetConfirmSerializer:

    def test_matching_passwords(self):
        data = {
            "new_password": "newSecure123!",
            "confirm_password": "newSecure123!"
        }
        serializer = PasswordResetConfirmSerializer(data=data)
        assert serializer.is_valid(), serializer.errors

    def test_mismatched_passwords(self):
        data = {
            "new_password": "newSecure123!",
            "confirm_password": "different456!"
        }
        serializer = PasswordResetConfirmSerializer(data=data)
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors
    
    def test_missing_new_password(self):
        serializer = PasswordResetConfirmSerializer(data={"confirm_password": "newSecure123!"})
        assert not serializer.is_valid()
        assert "new_password" in serializer.errors

    def test_missing_confirm_password(self):
        serializer = PasswordResetConfirmSerializer(data={"new_password": "newSecure123!"})
        assert not serializer.is_valid()
        assert "confirm_password" in serializer.errors

# PasswordResetView

@pytest.mark.django_db
class TestPasswordResetView:

    @patch("auth_app.api.views.send_password_reset_email")
    def test_returns_200_for_existing_user(self, mock_send_email, api_client, create_user):
        create_user(email="reset@example.com", is_active=True)
        response = api_client.post(PASSWORD_RESET_URL, {"email": "reset@example.com"}, format="json")
        assert response.status_code == 200

    @patch("auth_app.api.views.send_password_reset_email")
    def test_correct_response_body(self, mock_send_email, api_client, create_user):
        create_user(email="reset@example.com", is_active=True)
        response = api_client.post(PASSWORD_RESET_URL, {"email": "reset@example.com"}, format="json")
        assert response.data["detail"] == "An email has been sent to reset your password."

    @patch("auth_app.api.views.send_password_reset_email")
    def test_email_sent_for_existing_user(self, mock_send_email, api_client, create_user):
        create_user(email="reset@example.com", is_active=True)
        api_client.post(PASSWORD_RESET_URL, {"email": "reset@example.com"}, format="json")
        mock_send_email.assert_called_once

    @patch("auth_app.api.views.send_password_reset_email")
    def test_returns_200_for_nonexistent_user(self, mock_send_email, api_client):
        response = api_client.post(PASSWORD_RESET_URL, {"email": "ghost@example.com"}, format="json")
        assert response.status_code == 200

    @patch("auth_app.api.views.send_password_reset_email")
    def test_no_email_sent_for_nonexistent_user(self, mock_send_email, api_client):
        api_client.post(PASSWORD_RESET_URL, {"email": "ghost@example.com"}, format="json")
        mock_send_email.assert_not_called()

    @patch("auth_app.api.views.send_password_reset_email")
    def test_no_email_sent_for_inactive_user(self, mock_send_email, api_client, create_user):
        create_user(email="inactive@example.com", is_active=False)
        api_client.post(PASSWORD_RESET_URL, {"email": "inactive@example.com"}, format="json")
        mock_send_email.assert_not_called()

    def test_invalid_email_format_returns_400(self, api_client):
        response = api_client.post(PASSWORD_RESET_URL, {"email": "not-at-sign"}, format="json")
        assert response.status_code == 400

    def test_missing_email_returns_400(self, api_client):
        response = api_client.post(PASSWORD_RESET_URL, {}, format="json")
        assert response.status_code == 400

# PasswordResetConfirmView

@pytest.mark.django_db
class TestPasswordResetConfirmView:
    
    def test_successful_password_reset(self, api_client, create_user):
        user = create_user(email="confirm@example.com", is_active=True)
        url, _ = _build_confirm_url(user)

        response = api_client.post(url, {
            "new_password": "brandNew456!",
            "confirm_password": "brandNew456!"
        }, format="json")

        assert response.status_code == 200
        assert "detail" in response.data

    def test_password_is_actually_changed(self, api_client, create_user):
        user = create_user(email="changed@example.com", password="oldPass123!", is_active=True)
        url, _ = _build_confirm_url(user)

        api_client.post(url, {
            "new_password": "brandNew456!",
            "confirm_password": "brandNew456!"
        }, format="json")

        user.refresh_from_db()
        assert user.check_password("brandNew456!")
        assert not user.check_password("oldPass123!")

    def test_invalid_uidb64_returns_400(self, api_client):
        url = "/api/password_confirm/invalid-uid/some-token/"
        response = api_client.post(url, {
            "new_password": "brandNew456!",
            "confirm_password": "brandNew456!"
        }, format="json")
        assert response.status_code == 400

    def test_nonexistent_user_returns_400(self, api_client):
        uidb64 = urlsafe_base64_encode(force_bytes(99999))
        url = f"/api/password_confirm/{uidb64}/some-token/"
        response = api_client.post(url, {
            "new_password": "brandNew456!",
            "confirm_password": "brandNew456!"
        }, format="json")
        assert response.status_code == 400

    def test_invalid_token_returns_400(self, api_client, create_user):
        user = create_user(email="badtoken@example.com", is_active=True)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        url = f"/api/password_confirm/{uidb64}/invalid_token/"

        response = api_client.post(url, {
            "new_password": "brandNew456!",
            "confirm_password": "brandNew456!"
        }, format="json")
        assert response.status_code == 400

    def test_mismatched_passwords_returns_400(self, api_client, create_user):
        user = create_user(email="mismatch@example.com", is_active=True)
        url, _ = _build_confirm_url(user)

        response = api_client.post(url, {
            "new_password": "brandNew456!",
            "confirm_password": "different789!"
        }, format="json")
        assert response.status_code == 400

    def test_token_invalid_after_password_change(self, api_client, create_user):
        """Nach erfolgreichem Reset ist der Token nicht mehr gültig."""
        user = create_user(email="once@example.com", is_active=True)
        url, _ = _build_confirm_url(user)

        # Erster Reset - erfolgreich
        api_client.post(url, {
            "new_password": "brandNew456!",
            "confirm_password": "brandNew456!"
        }, format="json")

        # Zweiter Versuch mit demselben Token - Token ist durch Passwortänderung invalidiert
        response = api_client.post(url, {
            "new_password": "anotherPass789!",
            "confirm_password": "anotherPass789!"
        }, format="json")
        assert response.status_code == 400