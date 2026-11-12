"""Django settings (excerpt)."""
import os

DEBUG = False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
INSTALLED_APPS = ["django.contrib.auth", "corsheaders", "rest_framework", "billing"]
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
