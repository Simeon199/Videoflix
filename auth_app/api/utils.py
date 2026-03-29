import django_rq
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
    
def _send_activation_email_task(user_id, uidb64, token):
    """
    RQ background task that sends the account activation email.
    Fetches the user by ID, constructs the activation link, and sends the email
    synchronously within the worker process.
    Args:
        user_id (int): Primary key of the user to activate.
        uidb64 (str): Base64-encoded user ID used in the activation link.
        token (str): Activation token used in the activation link.
    Raises:
        User.DoesNotExist: If no user with the given ID exists.
        Exception: If email sending fails (fail_silently=False).
    """
    user = User.objects.get(pk=user_id)
    activation_link = f"{settings.DOMAIN}/api/activate/{uidb64}/{token}/"
    subject = 'Aktiviere dein Videoflix-Konto'
    body = (
        f"Hallo, \n\n"
        f"bitte klick auf den folgenden Link, um dein Konto zu aktivieren:\n\n"
        f"{activation_link}\n\n"
        f"Viele Grüße,\nDein Videoflix-Team"
    )
    email = EmailMessage(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email])
    email.send(fail_silently=False)

def send_activation_email(user, uidb64, token):
    """
    Enqueue the account activation email as an RQ background task.
    Adds the email sending task to the default RQ queue so that it is
    processed asynchronously by an RQ worker, keeping the request-response
    cycle fast.
    Args:
        user (User): The user object whose account is being activated.
        uidb64 (str): Base64-encoded user ID for the activation link.
        token (str): Activation token for the activation link.
    """
    queue = django_rq.get_queue('default')
    queue.enqueue(_send_activation_email_task, user.id, uidb64, token)

def _send_password_reset_email_task(user_id, uidb64, token):
    """
    RQ background task that sends the password reset email.
    Fetches the user by ID, constructs the password reset link, and sends the
    email synchronously within the worker process.
    Args:
        user_id (int): Primary key of the user requesting the password reset.
        uidb64 (str): Base64-encoded user ID used in the reset link.
        token (str): Password reset token used in the reset link.
    Raises:
        User.DoesNotExist: If no user with the given ID exists.
        Exception: If email sending fails (fail_silently=False).
    """
    user = User.objects.get(pk=user_id)
    reset_link = f"{settings.DOMAIN}/api/password_confirm/{uidb64}/{token}/"
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

def send_password_reset_email(user, uidb64, token):
    """
    Enqueue the password reset email as an RQ background task.
    Adds the email sending task to the default RQ queue so that it is
    processed asynchronously by an RQ worker, keeping the request-response
    cycle fast.
    Args:
        user (User): The user object requesting the password reset.
        uidb64 (str): Base64-encoded user ID for the reset link.
        token (str): Password reset token for the reset link.
    """
    queue = django_rq.get_queue('default')
    queue.enqueue(_send_password_reset_email_task, user.id, uidb64, token)