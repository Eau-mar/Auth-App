from rest_framework import serializers
from django.utils import timezone
from accounts.managers.auth_manager import AuthManager
from accounts.managers.exceptions import AuthAPIException
from accounts.models import AuthAudit, LoginAttempt, User
from accounts.services.security_alert import SecurityAlertService
from accounts.services.send_active_mail import send_activation_email
from accounts.tokens import EmailVerificationTokenGenerator


class MeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "date_joined",
            "last_login",
        )
        read_only_fields = fields


class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    is_active = serializers.BooleanField()
    email_verified = serializers.BooleanField()
    is_staff = serializers.BooleanField()
    date_joined = serializers.DateTimeField()

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)

    def create(self, validated_data):
        request = self.context["request"]

        user = AuthManager.register(
            email=validated_data["email"],
            password=validated_data["password"]
        )

        AuthAudit.objects.create(
            user=user,
            email=user.email,
            action="REGISTER",
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", "")
        )

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = EmailVerificationTokenGenerator.make_token(user)

        # Envoi email
        send_activation_email(user, uid, token)

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    MAX_ATTEMPTS = 5
    BLOCK_MINUTES = 15
    ALERT_THRESHOLD = 3  # alerte avant blocage

    def validate(self, data):
        request = self.context["request"]
        email = data["email"]
        ip = request.META.get("REMOTE_ADDR")

        attempt, _ = LoginAttempt.objects.get_or_create(
            email=email,
            ip_address=ip
        )

        if attempt.is_blocked():
            raise RateLimited(
                retry_after=attempt.remaining_seconds()
            )

        try:
            result = AuthManager.login(
                email=email,
                password=data["password"]
            )

            attempt.reset()

            AuthAudit.objects.create(
                user_id=result["user"]["id"],
                email=email,
                action="LOGIN_SUCCESS",
                ip_address=ip,
                user_agent=request.META.get("HTTP_USER_AGENT", "")
            )

            return result

        except AuthAPIException as e:
            attempt.register_failure(
                max_attempts=self.MAX_ATTEMPTS,
                block_minutes=self.BLOCK_MINUTES,
                alert_threshold=self.ALERT_THRESHOLD,
                email=email,
                ip=ip
            )

            AuthAudit.objects.create(
                email=email,
                action="LOGIN_FAILED",
                ip_address=ip,
                user_agent=request.META.get("HTTP_USER_AGENT", "")
            )

            raise e  # ⬅️ ON RELANCE L’EXCEPTION ORIGINALE



class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def save(self):
        request = self.context["request"]
        AuthManager.logout(self.validated_data["refresh"])

        AuthAudit.objects.create(
            user=request.user,
            email=request.user.email,
            action="LOGOUT",
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", "")
        )


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def save(self):
        request = self.context["request"]

        payload = AuthManager.request_password_reset(self.validated_data["email"])

        AuthAudit.objects.create(
            email=self.validated_data["email"],
            action="RESET_REQUEST",
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", "")
        )

        return payload


class ResetPasswordSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=8)

    def save(self):
        request = self.context["request"]

        AuthManager.reset_password(
            uid=self.validated_data["uid"],
            token=self.validated_data["token"],
            new_password=self.validated_data["new_password"]
        )

        AuthAudit.objects.create(
            action="RESET_SUCCESS",
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", "")
        )
