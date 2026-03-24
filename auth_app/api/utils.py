from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str


def decode_uid_and_get_user(uidb64):
    """
    Decode a base64-encoded user ID and retrieve the user object.
    Shared utility used by ActivationView and PasswordResetConfirmView.
    Args:
        uidb64 (str): Base64-encoded user ID.
    Returns:
        User: The user object if found and valid, None otherwise.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        return User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return None


def send_activation_email(user, uidb64, token):
    """
    Send account activation email to a user.
    Constructs and sends an email containing an activation link that allows
    a user to verify and activate their newly created account.
    Args:
        user: The user object containing the email address to send to.
        uidb64 (str): Base64-encoded user ID for the activation link.
        token (str): Unique activation token for the user.
    Returns:
        None
    Raises:
        Exception: If email sending fails (fail_silently=False).
    """
    activation_link = (
        f"{settings.DOMAIN}/api/activate/{uidb64}/{token}/"
    )
    subject = 'Aktiviere dein Videoflix-Konto'
    body = (
        f"Hallo, \n\n"
        f"bitte klick auf den folgenden Link, um dein Konto zu aktivieren:\n\n"
        f"{activation_link}\n\n"
        f"Viele Grüße,\nDein Videoflix-Team"
    )
    email = EmailMessage(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email])
    email.send(fail_silently=False)

def send_password_reset_email(user, uidb64, token):
    """
    Send password reset email to a user.
    Constructs and sends an email containing a password reset link that allows
    a user to set a new password. Includes a disclaimer that the email can be
    ignored if the reset request was not authorized by the user.
    Args:
        user: The user object containing the email address to send to.
        uidb64 (str): Base64-encoded user ID for the password reset link.
        token (str): Unique password reset token for the user.
    Returns:
        None
    Raises:
        Exception: If email sending fails (fail_silently=False).
    """
    reset_link = (
        f"{settings.DOMAIN}/api/password_confirm/{uidb64}/{token}/"
    )
    subject = 'Passwort zurücksetzen - Videoflix'
    body = (
        f"Hallo, \n\n"
        f"du hast eine Anfrage zum Zurücksetzen deines Passworts gestellt.\n\n"
        f"Klicke auf den folgenden Link, um ein neues Passwort zu vergeben:\n\n"
        f"{reset_link}\n\n"
        f"Falls du diese Anfrage nicht gestellt hast, kannst du diese Email ignorieren.\n\n"
        f"Viele Grüße,\nDein Videoflix-Team"
    )
    email = EmailMessage(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email])
    email.send(fail_silently=False)