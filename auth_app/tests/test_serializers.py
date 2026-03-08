import pytest
from django.contrib.auth.models import User
from auth_app.api.serializers import RegistrationSerializer

@pytest.mark.django_db
class TestRegistrationSerializer:

    def test_valid_data(self):
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!"
        }
        serializer = RegistrationSerializer(data=data)
        assert serializer.is_valid(), serializer.errors

    def test_create_user(self):
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        }
        serializer = RegistrationSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        assert user.email == "new@example.com"
        assert user.username == "new@example.com"
        assert user.is_active is False
        assert user.check_password("securePass123!")

    def test_password_mismatch(self):
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "wrongPassword!",
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors

    def test_duplicate_email(self, create_user):
        create_user(email="existing@example.com")
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "email" in serializer.errors

    def test_missing_email(self):
        data = {
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "email" in serializer.errors

    def test_invalid_email_format(self):
        data = {
            "email": "not-an-email",
            "password": "securePass123!",
            "confirmed_password": "securePass123!"
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "email" in serializer.errors

    def test_missing_password(self):
        data = {
            "email": "new@example.com",
            "confirmed_password": "securePass123!"
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "password" in serializer.errors

    def test_missing_confirmed_password(self):
        data = {
            "email": "new@example.com",
            "password": "securePass123!"
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "confirmed_password" in serializer.errors