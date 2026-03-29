import sys
from unittest.mock import MagicMock

# Mock django_rq before any module imports it (RQ uses fork which is unavailable on Windows)
_mock_django_rq = MagicMock()
_mock_queue = MagicMock()
_mock_queue.enqueue.side_effect = lambda fn, *args, **kwargs: fn(*args, **kwargs)
_mock_django_rq.get_queue.return_value = _mock_queue
sys.modules.setdefault("django_rq", _mock_django_rq)

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