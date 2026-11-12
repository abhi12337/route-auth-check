"""Django settings (excerpt)."""
import os

DEBUG = False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
INSTALLED_APPS = ["django.contrib.auth", "corsheaders", "rest_framework", "billing"]
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
CORS_ALLOW_CREDENTIALS = True
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}
