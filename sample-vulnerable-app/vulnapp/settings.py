import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# VULN: hardcoded secret key committed to source control
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'your-secret-key-placeholder')

# VULN: debug mode left on, would leak stack traces / settings in production
DEBUG = True

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "core",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "vulnapp.urls"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "vulnapp",
        "USER": "vulnapp_admin",
        # VULN: hardcoded database credential
        "PASSWORD": os.environ.get('DB_PASSWORD', 'your-db-password-placeholder'),
        "HOST": "db.internal.example.com",
        "PORT": "5432",
    }
}

# VULN: hardcoded third-party API key
PAYMENTS_API_KEY = os.environ.get('PAYMENTS_API_KEY', 'your-api-key-placeholder')

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
