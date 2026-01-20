from rest_framework.exceptions import APIException
from rest_framework import status


class AuthAPIException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Erreur d'authentification"
    default_code = "auth_error"


class NoVerifiedEmail(AuthAPIException):
    status_code = 400
    default_detail = "Email non vérifier"
    default_code = "no_verified"


class EmailAlreadyUsed(AuthAPIException):
    status_code = 400
    default_detail = "Vous avez déjâ un compte avec cet Email"
    default_code = "email_exists"


class InvalidCredentials(AuthAPIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Identifiants invalides"
    default_code = "invalid_credentials"


class AccountInactive(AuthAPIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Compte non activé"
    default_code = "account_inactive"


class AccountBlocked(AuthAPIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_code = "account_blocked"

    def __init__(self, retry_after=None):
        detail = (
            f"Compte temporairement bloqué ({retry_after} min)"
            if retry_after
            else "Compte temporairement bloqué"
        )
        super().__init__(detail=detail)


class RateLimited(AuthAPIException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_code = "rate_limited"

    def __init__(self, retry_after=None):
        detail = (
            f"Trop de tentatives. Réessayez dans {retry_after} secondes."
            if retry_after
            else "Trop de tentatives. Veuillez patienter."
        )
        super().__init__(detail=detail)
