import django_rq
from django.core.mail import EmailMessage
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.contrib.auth.models import User
from django.template.loader import render_to_string
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
    activation_link = f"{settings.FRONTEND_DOMAIN}{settings.FRONTEND_ACTIVATION_PAGE}?uid={uidb64}&token={token}"
    user_name = user.first_name or user.email
    subject = 'Confirm your email'
    text_body = (
        f"Dear {user_name},\n\n"
        f"Thank you for registering with Videoflix. To complete your registration "
        f"and verify your email address, please click the link below:\n\n"
        f"{activation_link}\n\n"
        f"If you did not create an account with us, please disregard this email.\n\n"
        f"Best regards,\nYour Videoflix Team."
    )
    html_body = render_to_string('auth_app/emails/activation_email.html', {
        'user_name': user_name,
        'activation_link': activation_link,
    })
    email = EmailMultiAlternatives(subject, text_body, settings.DEFAULT_FROM_EMAIL, [user.email])
    email.attach_alternative(html_body, 'text/html')
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
    reset_link = f"{settings.FRONTEND_DOMAIN}{settings.FRONTEND_RESET_PASSWORD_PATH}?uid={uidb64}&token={token}"
    subject = 'Reset your Password'
    text_body = (
        f"Hello,\n\n"
        f"We recently received a request to reset your password. If you made this "
        f"request, please click on the following link to reset your password:\n\n"
        f"{reset_link}\n\n"
        f"Please note that for security reasons, this link is only valid for 24 hours.\n\n"
        f"If you did not request a password reset, please ignore this email.\n\n"
        f"Best regards,\nYour Videoflix team!"
    )
    html_body = render_to_string('auth_app/emails/password_reset_email.html', {
        'reset_link': reset_link,
    })
    email = EmailMultiAlternatives(subject, text_body, settings.DEFAULT_FROM_EMAIL, [user.email])
    email.attach_alternative(html_body, 'text/html')
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