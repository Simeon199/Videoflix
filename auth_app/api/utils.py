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