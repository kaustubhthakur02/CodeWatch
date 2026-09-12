from pathlib import Path



BASE_DIR = Path(__file__).resolve().parent.parent

# VULN: hardcoded secret key committed to source control
SECRET_KEY = "django-insecure-8f3k2n9x7q1w4e6r5t8y2u3i0o9p1a2s3d4f5g6h"

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
        "PASSWORD": "Sup3rSecretDbPass!2024",
        "HOST": "db.internal.example.com",
        "PORT": "5432",
    }
}

# VULN: hardcoded third-party API key
PAYMENTS_API_KEY = "api_key_9f8e7d6c5b4a39281706fedcba9876543210abcd"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
