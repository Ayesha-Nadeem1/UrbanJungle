"""
Django settings for UrbanJungle project.

Generated by 'django-admin startproject' using Django 4.2.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-or7h0i0(9o+@y^1#n&b6o4hk+jkpxymcuu+yt8-e*tqm&&#=xy"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True


#CORS_ALLOWED_ORIGINS = ['*']

CORS_ALLOW_CREDENTIALS = True

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'corsheaders',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django_extensions',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'users',
    'channels',
    'django_q',
    'django_celery_beat',
    'django_celery_results',
]

Q_CLUSTER = {
    'name': 'DjangoQ',
    'workers': 4,
    'recycle': 500,
    'timeout': 60,
    'ack_failures': True,
    'redis': {
        'host': 'localhost',
        'port': 6379,
        'db': 0,
    }
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    'corsheaders.middleware.CorsMiddleware',
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    'csp.middleware.CSPMiddleware',
]

ROOT_URLCONF = "UrbanJungle.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "UrbanJungle.wsgi.application"


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

from config import DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'urbanjungle_db',
        'USER': 'admin',
        'PASSWORD': 'ATmega32u',
        'HOST': 'localhost',
        'PORT': '',
    },
    #  'default': {
    #     'ENGINE': 'django.db.backends.postgresql',  # or your database engine
    #     'NAME': 'urban2',
    #     'USER': 'postgres',
    #     'PASSWORD': 'ATmega32u',
    #     'HOST': 'urban2.ct8sygu0wog4.eu-north-1.rds.amazonaws.com',
    #     'PORT': '5432',
    # },
    #     'default': {
    #     'ENGINE': 'django.db.backends.postgresql',  # or your database engine
    #     'NAME': DB_NAME,
    #     'USER': DB_USER,
    #     'PASSWORD': DB_PASSWORD,
    #     'HOST': DB_HOST,
    #     'PORT': DB_PORT,
    # }
    # 'default': {
    #     'ENGINE': 'django.db.backends.sqlite3',
    #     'NAME': BASE_DIR / 'db.sqlite3',
    # }
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"
CELERY_ENABLE_UTC = True
USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles/")

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

if not os.path.exists(MEDIA_ROOT):
    os.makedirs(MEDIA_ROOT, exist_ok=True)

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=7),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'AUTH_HEADER_TYPES': ('Bearer',),
}

AUTH_USER_MODEL = 'users.User'
CORS_ALLOW_ALL_ORIGINS= True
ASGI_APPLICATION = 'UrbanJungle.asgi.application'

CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [('127.0.0.1', 6379)],
        },
    },
}

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://redis:6379/0',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'hassanmeer941@gmail.com'
EMAIL_HOST_PASSWORD = 'tghc jvmu fqhr vpyr'

# MEDIA_URL = '/media/'
# MEDIA_ROOT = BASE_DIR / 'media'

# Celery Configuration
#CELERY_BROKER_URL = 'redis://redis-server:6379/0'
CELERY_BROKER_URL = "redis://127.0.0.1:6379/0"

CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
#CELERY_RESULT_BACKEND = 'django-db'  # For storing task results
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/0'
CELERY_TIMEZONE = 'UTC'

ALLOWED_HOSTS = ['backend.ai-ponics.com', 'www.backend.ai-ponics.com', 'localhost','13.60.206.225','165.22.5.217','127.0.0.1']

# Enable secure proxy headers
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# SECURE_SSL_REDIRECT = True
# CSRF_COOKIE_SECURE = True
# SESSION_COOKIE_SECURE = True


CSP_CONNECT_SRC = ["'self'", "ws://13.60.206.225:8000"]
CSP_DEFAULT_SRC = ["'self'"]
CSP_FRAME_ANCESTORS = ["'self'"]


# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'handlers': {
#         'mqtt_file': {
#             'level': 'DEBUG',
#             'class': 'logging.FileHandler',
#             'filename': '/var/log/django/mqtt.log',
#             'formatter': 'verbose',
#         },
#         'console': {
#             'level': 'INFO',
#             'class': 'logging.StreamHandler',
#         },
#     },
#     'formatters': {
#         'verbose': {
#             'format': '{asctime} {levelname} {name} {message}',
#             'style': '{',
#         },
#     },
#     'loggers': {
#         'mqtt': {
#             'handlers': ['mqtt_file', 'console'],
#             'level': 'DEBUG',
#             'propagate': False,
#         },
#     },
# }

import os
from pathlib import Path

# Create base directory for logs if it doesn't exist
LOG_DIR = Path('/var/log/django/')
LOG_DIR.mkdir(exist_ok=True, mode=0o755)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'mqtt_file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': str(LOG_DIR / 'mqtt.log'),  # Use pathlib for cross-platform compatibility
            'formatter': 'verbose',
            'mode': 'a',  # Explicitly set append mode
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'null': {  # Add a null handler as fallback
            'class': 'logging.NullHandler',
        },
    },
    'formatters': {
        'verbose': {
            'format': '{asctime} {levelname} {name} {message}',
            'style': '{',
        },
    },
    'loggers': {
        'mqtt': {
            'handlers': ['mqtt_file', 'console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        # Add fallback configuration for other loggers
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
    },
    'root': {  # Root logger configuration as safety net
        'handlers': ['console'],
        'level': 'WARNING',
    },
}