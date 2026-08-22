import sys
from pathlib import Path

import environ


# =============================================================================
# CAMINHOS BASE
# =============================================================================

# Exemplo Linux:
#
# /home/moonshield/MoonShield-Platform/MoonShield
#
BASE_DIR = Path(__file__).resolve().parent.parent


# Raiz do repositório:
#
# /home/moonshield/MoonShield-Platform
#
PROJECT_ROOT = BASE_DIR.parent


# Arquivo:
#
# /home/moonshield/MoonShield-Platform/.env
#
ENV_FILE = PROJECT_ROOT / ".env"


# =============================================================================
# VARIÁVEIS DE AMBIENTE
# =============================================================================

env = environ.Env(
    DEBUG=(bool, False),
)

if ENV_FILE.exists():
    environ.Env.read_env(
        ENV_FILE,
    )


# =============================================================================
# MOONSHIELD
# =============================================================================

SYSTEM_NAME = "MoonShield"

SYSTEM_VERSION = "1.0.0"


# =============================================================================
# DJANGO / SEGURANÇA
# =============================================================================

SECRET_KEY = env(
    "SECRET_KEY",
    default="django-insecure-moonshield-development-only",
)

DEBUG = env.bool(
    "DEBUG",
    default=False,
)


# =============================================================================
# HOSTS
# =============================================================================

_allowed_hosts_raw = env(
    "ALLOWED_HOSTS",
    default="127.0.0.1,localhost",
)

ALLOWED_HOSTS = [
    host.strip()
    for host in _allowed_hosts_raw.split(",")
    if host.strip()
]


# =============================================================================
# CSRF
# =============================================================================

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
# PYTHON PATH — APLICATIVOS
# =============================================================================

APPS_DIR = BASE_DIR / "aplicativos"

if str(APPS_DIR) not in sys.path:
    sys.path.insert(
        0,
        str(APPS_DIR),
    )


# =============================================================================
# APLICAÇÕES
# =============================================================================

INSTALLED_APPS = [
    # -------------------------------------------------------------------------
    # Django
    # -------------------------------------------------------------------------

    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # -------------------------------------------------------------------------
    # MoonShield
    # -------------------------------------------------------------------------

    "autenticacao",
    "painel",

    "mapa_ameacas",

    # Infraestrutura
    "rede.apps.RedeConfig",
    "dns",
    "firewall",
    "dispositivos",

    # Segurança / SOC
    "ids",
    "incidentes",

    # Plataforma
    "relatorios",
    "configuracoes",

    # MoonShield AI
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
        "BACKEND": (
            "django.template.backends.django."
            "DjangoTemplates"
        ),

        "DIRS": [
            BASE_DIR / "templates",
        ],

        "APP_DIRS": True,

        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",

                "django.template.context_processors.request",

                "django.contrib.auth."
                "context_processors.auth",

                "django.contrib.messages."
                "context_processors.messages",

                # MoonShield
                "autenticacao.context_processors."
                "user_profile_ctx",
            ],
        },
    },
]


# =============================================================================
# BANCO DE DADOS — POSTGRESQL
# =============================================================================

# MoonShield utiliza PostgreSQL.
#
# Exemplo no .env:
#
# DATABASE_URL=postgresql://usuario:senha@127.0.0.1:5432/moonshield
#
# Não existe fallback automático para SQLite.


DATABASE_URL = env(
    "DATABASE_URL",
    default=None,
)


if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL não configurada. "
        f"Configure a variável no arquivo: {ENV_FILE}"
    )


DATABASES = {
    "default": env.db_url(
        "DATABASE_URL",
    ),
}


# =============================================================================
# POSTGRESQL — CONEXÕES
# =============================================================================

DATABASES["default"]["CONN_MAX_AGE"] = env.int(
    "DATABASE_CONN_MAX_AGE",
    default=60,
)


DATABASES["default"]["CONN_HEALTH_CHECKS"] = True


_database_options = DATABASES[
    "default"
].get(
    "OPTIONS",
    {},
)


_database_options.update(
    {
        "connect_timeout": env.int(
            "DATABASE_CONNECT_TIMEOUT",
            default=10,
        ),
    }
)


DATABASES["default"]["OPTIONS"] = (
    _database_options
)


# =============================================================================
# VALIDAÇÃO DE SENHAS
# =============================================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": (
            "django.contrib.auth."
            "password_validation."
            "UserAttributeSimilarityValidator"
        ),
    },

    {
        "NAME": (
            "django.contrib.auth."
            "password_validation."
            "MinimumLengthValidator"
        ),
    },

    {
        "NAME": (
            "django.contrib.auth."
            "password_validation."
            "CommonPasswordValidator"
        ),
    },

    {
        "NAME": (
            "django.contrib.auth."
            "password_validation."
            "NumericPasswordValidator"
        ),
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


STATIC_ROOT = (
    BASE_DIR / "staticfiles"
)


# =============================================================================
# MEDIA
# =============================================================================

MEDIA_URL = "/media/"

MEDIA_ROOT = (
    BASE_DIR / "media"
)


# =============================================================================
# DEFAULT AUTO FIELD
# =============================================================================

DEFAULT_AUTO_FIELD = (
    "django.db.models.BigAutoField"
)


# =============================================================================
# MAPBOX
# =============================================================================

MAPBOX_ACCESS_TOKEN = env(
    "MAPBOX_ACCESS_TOKEN",
    default="",
)


# =============================================================================
# SESSÃO / COOKIES
# =============================================================================

SESSION_COOKIE_HTTPONLY = True

CSRF_COOKIE_HTTPONLY = False

X_FRAME_OPTIONS = "DENY"


# =============================================================================
# HTTPS
# =============================================================================

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
# REVERSE PROXY
# =============================================================================

SECURE_PROXY_SSL_HEADER = (
    "HTTP_X_FORWARDED_PROTO",
    "https",
)


# =============================================================================
# LOGS
# =============================================================================

# Desenvolvimento:
#
# MoonShield/logs/
#
# Appliance futuramente:
#
# /var/log/moonshield/


LOG_DIR = BASE_DIR / "logs"


LOG_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


LOGGING = {
    "version": 1,

    "disable_existing_loggers": False,

    # -------------------------------------------------------------------------
    # FORMATADORES
    # -------------------------------------------------------------------------

    "formatters": {
        "standard": {
            "format": (
                "{asctime} | "
                "{levelname} | "
                "{name} | "
                "{message}"
            ),

            "style": "{",
        },
    },

    # -------------------------------------------------------------------------
    # HANDLERS
    # -------------------------------------------------------------------------

    "handlers": {
        "console": {
            "class": (
                "logging.StreamHandler"
            ),

            "formatter": "standard",
        },

        "file": {
            "class": (
                "logging.handlers."
                "RotatingFileHandler"
            ),

            "filename": str(
                LOG_DIR / "moonshield.log"
            ),

            "maxBytes": (
                10 * 1024 * 1024
            ),

            "backupCount": 5,

            "formatter": "standard",
        },
    },

    # -------------------------------------------------------------------------
    # ROOT LOGGER
    # -------------------------------------------------------------------------

    "root": {
        "handlers": [
            "console",
            "file",
        ],

        "level": env(
            "LOG_LEVEL",
            default="INFO",
        ),
    },
}