from django.contrib.auth import authenticate
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.exceptions import ValidationError
from accounts.managers.exceptions import *
from django.contrib.auth.password_validation import validate_password

from accounts.models import User
from accounts.tokens import email_verification_token, password_reset_token

class AuthManager:

    @staticmethod
    def register(email: str, password: str) -> User:
        validate_password(password)

        if User.objects.filter(email=email).exists():
            raise EmailAlreadyUsed()

        user = User.objects.create_user(
            email=email,
            password=password
        )

        return user

    @staticmethod
    def login(email: str, password: str) -> dict:
        user = authenticate(email=email, password=password)

        if not user:
            raise InvalidCredentials()

        if not user.is_active:
            raise AccountInactive()
        
        if not user.email_verified:
            raise NoVerifiedEmail()

        refresh = RefreshToken.for_user(user)

        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "email": user.email,
            }
        }

    @staticmethod
    def logout(refresh_token: str):
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            raise ValidationError("Token invalide")
        
    @staticmethod
    def request_password_reset(email: str) -> dict:
        user = User.objects.filter(email=email).first()

        if not user:
            return None  # réponse neutre côté API

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = password_reset_token.make_token(user)

        return {
            "uid": uid,
            "token": token,
            "email": user.email
        }

    @staticmethod
    def reset_password(uid: str, token: str, new_password: str):
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except:
            raise ValidationError("Lien invalide")

        if not password_reset_token.check_token(user, token):
            raise ValidationError("Token expiré ou invalide")

        validate_password(new_password)
        user.set_password(new_password)
        user.save()

    @staticmethod
    def verify_email(uid: str, token: str):
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except:
            raise ValidationError("Lien invalide")

        if not email_verification_token.check_token(user, token):
            raise ValidationError("Token invalide")

        user.is_active = True
        user.email_verified = True
        user.save()
