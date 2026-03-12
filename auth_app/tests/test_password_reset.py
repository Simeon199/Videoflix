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