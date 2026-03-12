from django.core.mail import EmailMessage
from django.conf import settings

def send_activation_email(user, uidb64, token):
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