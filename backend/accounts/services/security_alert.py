from django.core.mail import send_mail
from django.conf import settings

class SecurityAlertService:

    @staticmethod
    def send_bruteforce_alert(email, ip):
        send_mail(
            subject="Alerte sécurité – Tentatives de connexion suspectes",
            message=(
                f"Des tentatives de connexion répétées ont été détectées.\n\n"
                f"Email ciblé : {email}\n"
                f"Adresse IP : {ip}\n\n"
                f"Si ce n’est pas vous, aucune action n’est requise."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[settings.SECURITY_ALERT_EMAIL],
        )
