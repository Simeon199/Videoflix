import pytest
from django.contrib.auth.models import User

@pytest.fixture(autouse=True)
def set_domain(settings):
    """
    Ensure DOMAIN setting exists for send_activation_email.
    """
    settings.DOMAIN = "http://testserver"
    settings.DEFAULT_FROM_EMAIL = "test@videoflix.de"

@pytest.fixture
def create_user(db):
    """
    Factory fixture to create users.
    """
    def _create_user(email="test@example.com", password="securePass123!", is_active=True):
        return User.objects.create_user(
            username=email,
            email=email,
            password=password,
            is_active=is_active
        )
    return _create_user