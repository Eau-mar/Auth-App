from django.contrib import admin
from .models import User, LoginAttempt, AuthAudit

# Register your models here.

tables = [User, LoginAttempt, AuthAudit]
admin.site.register(tables)