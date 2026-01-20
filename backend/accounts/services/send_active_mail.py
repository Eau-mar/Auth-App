from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings


def send_activation_email(user, uid, token):
    subject = "Activez votre compte"
    to_email = user.email

    context = {
        "user": user,
        "uid": uid,
        "token": token,
        "activation_url": f"{settings.FRONTEND_URL}/verify-email/?uid={uid}&token={token}",
    }

    html_content = render_to_string("emails/activate_account.html", context)
    text_content = render_to_string("emails/activate_account.txt", context)

    email = EmailMultiAlternatives(
        subject,
        text_content,
        settings.DEFAULT_FROM_EMAIL,
        [to_email],
    )
    email.attach_alternative(html_content, "text/html")
    email.send()
