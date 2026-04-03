import pytest
from unittest.mock import patch, MagicMock
from auth_app.api.utils import send_activation_email, _send_activation_email_task

"""
Test module for utility functions.

This module contains tests for authentication utility functions:
- send_activation_email function for user account activation

Tests cover email enqueueing, proper email content generation,
and activation link construction.
"""

@pytest.mark.django_db
class TestSendActivationEmail:
    """
    Test class for send_activation_email and _send_activation_email_task.
    """

    @patch("auth_app.api.utils.django_rq")
    def test_email_is_enqueued(self, mock_django_rq, create_user):
        """
        Test that send_activation_email enqueues the background task.
        """
        mock_queue = MagicMock()
        mock_django_rq.get_queue.return_value = mock_queue
        user = create_user(email="mail@example.com")
        send_activation_email(user, "dWlkYjY0", "test-token")
        mock_django_rq.get_queue.assert_called_once_with('default')
        mock_queue.enqueue.assert_called_once_with(
            _send_activation_email_task, user.id, "dWlkYjY0", "test-token"
        )

    @patch("auth_app.api.utils.EmailMultiAlternatives")
    @patch("auth_app.api.utils.render_to_string", return_value="<html>activation</html>")
    def test_task_sends_email(self, mock_render, MockEmailMulti, create_user, settings):
        """
        Test that the background task sends the email with correct parameters.
        """
        settings.FRONTEND_DOMAIN = "http://testserver"
        settings.FRONTEND_ACTIVATION_PAGE = "/activate"
        settings.DEFAULT_FROM_EMAIL = "noreply@videoflix.de"
        user = create_user(email="mail@example.com")
        mock_instance = MagicMock()
        MockEmailMulti.return_value = mock_instance
        _send_activation_email_task(user.id, "abc123", "my-token")
        MockEmailMulti.assert_called_once()
        call_args = MockEmailMulti.call_args
        assert call_args[0][0] == "Confirm your email"
        assert "abc123" in call_args[0][1]
        assert "my-token" in call_args[0][1]
        assert call_args[0][2] == "noreply@videoflix.de"
        assert "mail@example.com" in call_args[0][3]
        mock_instance.attach_alternative.assert_called_once()
        mock_instance.send.assert_called_once_with(fail_silently=False)