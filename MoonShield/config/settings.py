import os
import sys
from pathlib import Path

import environ


# =============================================================================
# BASE
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
)

# Lê:
# /home/moonshield/MoonShield-Platform/MoonShield/.env
ENV_FILE = BASE_DIR / ".env"

if ENV_FILE.exists():
    environ.Env.read_env(ENV_FILE)


# =============================================================================
# MOONSHIELD
# =============================================================================

SYSTEM_NAME = "MoonShield"
SYSTEM_VERSION = "1.0.0"


# =============================================================================
# SEGURANÇA / DJANGO
# =============================================================================

SECRET_KEY = env(
    "SECRET_KEY",
    default="django-insecure-moonshield-development-key",
)

DEBUG = env.bool(
    "DEBUG",
    default=False,
)


# -----------------------------------------------------------------------------
# Hosts permitidos
# -----------------------------------------------------------------------------

_allowed_hosts_raw = env(
    "ALLOWED_HOSTS",
    default="127.0.0.1,localhost",
)

ALLOWED_HOSTS = [
    host.strip()
    for host in _allowed_hosts_raw.split(",")
    if host.strip()
]


# -----------------------------------------------------------------------------
# CSRF
# -----------------------------------------------------------------------------

_csrf_origins_raw = env(
    "CSRF_TRUSTED_ORIGINS",
    default="",
)

CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in _csrf_origins_raw.split(",")
    if origin.strip()
]


# =============================================================================
# SYS.PATH
# =============================================================================

# Os aplicativos do projeto são utilizados por nome curto:
# autenticacao, painel, firewall, ids etc.
APPS_DIR = BASE_DIR / "aplicativos"

if str(APPS_DIR) not in sys.path:
    sys.path.insert(0, str(APPS_DIR))


# =============================================================================
# APLICAÇÕES
# =============================================================================

INSTALLED_APPS = [
    # Django
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # MoonShield
    "autenticacao",
    "painel",
    "mapa_ameacas",
    "dns",
    "ids",
    "firewall",
    "dispositivos",
    "relatorios",
    "configuracoes",
    "incidentes",
    "MoonShield",
]


# =============================================================================
# MIDDLEWARE
# =============================================================================

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


# =============================================================================
# URLS / WSGI
# =============================================================================

ROOT_URLCONF = "config.urls"

WSGI_APPLICATION = "config.wsgi.application"


# =============================================================================
# TEMPLATES
# =============================================================================

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",

        "DIRS": [
            BASE_DIR / "templates",
        ],

        "APP_DIRS": True,

        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",

                # MoonShield
                "autenticacao.context_processors.user_profile_ctx",
            ],
        },
    },
]


# =============================================================================
# BANCO DE DADOS
# =============================================================================

# O MoonShield V1 utiliza PostgreSQL.
#
# A conexão NÃO fica fixa no código.
#
# É carregada através da variável:
#
# DATABASE_URL=postgresql://usuario:senha@host:porta/banco
#
# Exemplo:
#
# DATABASE_URL=postgresql://moonshield:SENHA@127.0.0.1:5432/moonshield


DATABASES = {
    "default": env.db_url(
        "DATABASE_URL",
        default="postgresql://moonshield@127.0.0.1:5432/moonshield",
    )
}


# -----------------------------------------------------------------------------
# Configurações extras do PostgreSQL
# -----------------------------------------------------------------------------

DATABASES["default"].update(
    {
        # Mantém conexões reutilizáveis.
        # Evita abrir uma conexão PostgreSQL nova a cada request.
        "CONN_MAX_AGE": env.int(
            "DATABASE_CONN_MAX_AGE",
            default=60,
        ),

        # Verifica conexão antes de reutilizá-la.
        "CONN_HEALTH_CHECKS": True,

        "OPTIONS": {
            "connect_timeout": env.int(
                "DATABASE_CONNECT_TIMEOUT",
                default=10,
            ),
        },
    }
)


# =============================================================================
# VALIDAÇÃO DE SENHAS
# =============================================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "UserAttributeSimilarityValidator"
        )
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "MinimumLengthValidator"
        )
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "CommonPasswordValidator"
        )
    },
    {
        "NAME": (
            "django.contrib.auth.password_validation."
            "NumericPasswordValidator"
        )
    },
]


# =============================================================================
# LOCALIZAÇÃO
# =============================================================================

LANGUAGE_CODE = "pt-br"

TIME_ZONE = "America/Sao_Paulo"

USE_I18N = True

USE_TZ = True


# =============================================================================
# STATIC
# =============================================================================

STATIC_URL = "/static/"

STATICFILES_DIRS = [
    BASE_DIR / "static",
]

STATIC_ROOT = BASE_DIR / "staticfiles"


# =============================================================================
# MEDIA
# =============================================================================

MEDIA_URL = "/media/"

MEDIA_ROOT = BASE_DIR / "media"


# =============================================================================
# DEFAULT
# =============================================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# =============================================================================
# MAPBOX
# =============================================================================

MAPBOX_ACCESS_TOKEN = env(
    "MAPBOX_ACCESS_TOKEN",
    default="",
)


# =============================================================================
# SESSÃO / SEGURANÇA WEB
# =============================================================================

SESSION_COOKIE_HTTPONLY = True

CSRF_COOKIE_HTTPONLY = False

X_FRAME_OPTIONS = "DENY"


# -----------------------------------------------------------------------------
# Produção HTTPS
# -----------------------------------------------------------------------------

SECURE_SSL_REDIRECT = env.bool(
    "SECURE_SSL_REDIRECT",
    default=False,
)

SESSION_COOKIE_SECURE = env.bool(
    "SESSION_COOKIE_SECURE",
    default=False,
)

CSRF_COOKIE_SECURE = env.bool(
    "CSRF_COOKIE_SECURE",
    default=False,
)


# =============================================================================
# LOG
# =============================================================================

LOG_DIR = BASE_DIR / "logs"

LOG_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


LOGGING = {
    "version": 1,

    "disable_existing_loggers": False,

    "formatters": {
        "standard": {
            "format": (
                "{asctime} | {levelname} | "
                "{name} | {message}"
            ),
            "style": "{",
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },

        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "moonshield.log",
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
            "formatter": "standard",
        },
    },

    "root": {
        "handlers": [
            "console",
            "file",
        ],
        "level": "INFO",
    },
}