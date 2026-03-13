import pytest
from unittest.mock import patch, MagicMock
from auth_app.api.utils import send_activation_email

"""
Test module for utility functions.

This module contains tests for authentication utility functions:
- send_activation_email function for user account activation

Tests cover email sending functionality, proper email content generation,
and activation link construction.
"""

@pytest.mark.django_db
class TestSendActivationEmail:
    """
    Test class for send_activation_email utility function.
    """

    @patch("auth_app.api.utils.EmailMessage")
    def test_email_is_sent(self, MockEmailMessage, create_user, settings):
        """
        Test that activation email is sent with correct parameters.
        """
        settings.DOMAIN = "http://testserver"
        settings.DEFAULT_FROM_EMAIL = "noreply@videoflix.de"
        
        user = create_user(email="mail@example.com")
        mock_instance = MagicMock()
        MockEmailMessage.return_value = mock_instance

        send_activation_email(user, "dWlkYjY0", "test-token")

        MockEmailMessage.assert_called_once()
        call_args = MockEmailMessage.call_args
        assert "Aktiviere dein Videoflix-Konto" in call_args[0][0] # subject
        assert "mail@example.com" in call_args[0][3] # recipient_list
        mock_instance.send.assert_called_once_with(fail_silently=False)

    @patch("auth_app.api.utils.EmailMessage")
    def test_activation_link_in_body(self, MockEmailMessage, create_user, settings):
        """
        Test that activation link is correctly included in email body.
        """
        settings.DOMAIN = "http://testserver"
        settings.DEFAULT_FROM_EMAIL = "noreply@videoflix.de"

        user = create_user(email="link@example.com")
        MockEmailMessage.return_value = MagicMock()

        send_activation_email(user, "abc123", "my-token")

        call_args = MockEmailMessage.call_args
        body = call_args[0][1] # second positional arg = body
        body_str = str(body)
        assert "api/activate/abc123/my-token" in body_str