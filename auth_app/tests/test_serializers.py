import pytest
from django.contrib.auth.models import User
from auth_app.api.serializers import RegistrationSerializer

"""
Test module for serializer validation and functionality.

This module contains comprehensive tests for the authentication system's serializers:
- RegistrationSerializer validation and user creation logic

Tests cover successful registration flows, error handling, validation rules,
and proper user creation with appropriate default settings.
"""

@pytest.mark.django_db
class TestRegistrationSerializer:
    """
    Test class for RegistrationSerializer validation and user creation logic.
    """

    def test_valid_data(self):
        """
        Test that valid registration data passes validation.
        """
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!"
        }
        serializer = RegistrationSerializer(data=data)
        assert serializer.is_valid(), serializer.errors

    def test_create_user(self):
        """
        Test that valid data creates a user with correct attributes.
        """
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
        """
        Test that mismatched passwords are rejected.
        """
        data = {
            "email": "new@example.com",
            "password": "securePass123!",
            "confirmed_password": "wrongPassword!",
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors

    def test_duplicate_email(self, create_user):
        """
        Test that duplicate email addresses are rejected.
        """
        create_user(email="existing@example.com")
        data = {
            "email": "existing@example.com",
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "email" in serializer.errors

    def test_missing_email(self):
        """
        Test that missing email field causes validation error.
        """
        data = {
            "password": "securePass123!",
            "confirmed_password": "securePass123!",
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "email" in serializer.errors

    def test_invalid_email_format(self):
        """
        Test that invalid email format is rejected.
        """
        data = {
            "email": "not-an-email",
            "password": "securePass123!",
            "confirmed_password": "securePass123!"
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "email" in serializer.errors

    def test_missing_password(self):
        """
        Test that missing password field causes validation error.
        """
        data = {
            "email": "new@example.com",
            "confirmed_password": "securePass123!"
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "password" in serializer.errors

    def test_missing_confirmed_password(self):
        """
        Test that missing confirmed_password field causes validation error.
        """
        data = {
            "email": "new@example.com",
            "password": "securePass123!"
        }
        serializer = RegistrationSerializer(data=data)
        assert not serializer.is_valid()
        assert "confirmed_password" in serializer.errors