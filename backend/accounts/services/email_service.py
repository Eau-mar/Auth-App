from django.core.mail import send_mail
from django.conf import settings

class EmailService:

    @staticmethod
    def send_verification_email(email, link):
        send_mail(
            subject="Vérification de votre compte",
            message=f"Cliquez ici : {link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )

    @staticmethod
    def send_password_reset_email(email, link):
        send_mail(
            subject="Réinitialisation du mot de passe",
            message=f"Réinitialiser : {link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )
