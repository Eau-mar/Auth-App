from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from .managers.user_manager import UserManager
from django.conf import settings
from django.utils import timezone
from datetime import timedelta


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email


class AuthAudit(models.Model):
    ACTION_CHOICES = [
        ("REGISTER", "Register"),
        ("LOGIN_SUCCESS", "Login Success"),
        ("LOGIN_FAILED", "Login Failed"),
        ("LOGOUT", "Logout"),
        ("RESET_REQUEST", "Password Reset Request"),
        ("RESET_SUCCESS", "Password Reset Success"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )
    email = models.EmailField(null=True, blank=True)
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} - {self.email or self.user}"


class LoginAttempt(models.Model):
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    attempts = models.PositiveIntegerField(default=0)
    last_attempt = models.DateTimeField(auto_now=True)
    blocked_until = models.DateTimeField(null=True, blank=True)
    alert_sent = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("email", "ip_address")

    def is_blocked(self) -> bool:
        return self.blocked_until and self.blocked_until > timezone.now()

    def remaining_seconds(self) -> int | None:
        if not self.is_blocked():
            return None
        return int((self.blocked_until - timezone.now()).total_seconds())

    def block(self, minutes: int):
        self.blocked_until = timezone.now() + timedelta(minutes=minutes)

    def reset(self):
        self.attempts = 0
        self.alert_sent = False
        self.blocked_until = None
        self.save(update_fields=[
            "attempts",
            "alert_sent",
            "blocked_until"
        ])

    def register_failure(
        self,
        max_attempts: int,
        block_minutes: int,
        alert_threshold: int,
        email: str,
        ip: str
    ):
        self.attempts += 1

        # Alerte sécurité
        if self.attempts >= alert_threshold and not self.alert_sent:
            from accounts.services.security_alert import SecurityAlertService
            SecurityAlertService.send_bruteforce_alert(email, ip)
            self.alert_sent = True

        # Blocage
        if self.attempts >= max_attempts:
            self.block(block_minutes)

        self.save()

