import os
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
APPLIANCE_CONFIG_DIR = Path("/etc/moonshield")
APPLIANCE_CONF_FILE = APPLIANCE_CONFIG_DIR / "appliance.conf"
APPLIANCE_DATABASE_FILE = APPLIANCE_CONFIG_DIR / "database.env"
APPLIANCE_MODE = APPLIANCE_CONF_FILE.is_file()


# =============================================================================
# VARIÁVEIS DE AMBIENTE
# =============================================================================

env = environ.Env(
    DEBUG=(bool, False),
)

if APPLIANCE_MODE:
    if not APPLIANCE_DATABASE_FILE.is_file():
        raise RuntimeError("Modo appliance ativo, mas /etc/moonshield/database.env está ausente.")
    environ.Env.read_env(APPLIANCE_CONF_FILE, overwrite=True)
    environ.Env.read_env(APPLIANCE_DATABASE_FILE, overwrite=True)
    _secret_key_file = Path(
        os.environ.get(
            "SECRET_KEY_FILE",
            str(APPLIANCE_CONFIG_DIR / "secrets" / "django_secret_key"),
        )
    )
    try:
        _appliance_secret_key = _secret_key_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("SECRET_KEY da appliance não pode ser lida do arquivo externo configurado.") from exc
    if not _appliance_secret_key:
        raise RuntimeError("SECRET_KEY da appliance está vazia.")
    os.environ["SECRET_KEY"] = _appliance_secret_key
elif ENV_FILE.exists():
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

DEBUG = env.bool("DEBUG", default=False)

SECRET_KEY = env("SECRET_KEY", default="")
if not SECRET_KEY:
    if not DEBUG:
        raise RuntimeError("SECRET_KEY não configurada. Configure a variável no arquivo .env em produção!")
    else:
        SECRET_KEY = "django-insecure-moonshield-development-only"
# =============================================================================
# HOSTS
# =============================================================================

_allowed_hosts_raw = env(
    "ALLOWED_HOSTS",
    default="moonshield,moonshield.local,127.0.0.1,localhost",
)

ALLOWED_HOSTS = [host.strip() for host in _allowed_hosts_raw.split(",") if host.strip()]

if DEBUG and "*" not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append("*")
elif not DEBUG:
    ALLOWED_HOSTS = [host for host in ALLOWED_HOSTS if host != "*"]



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
    "autenticacao.middleware.GlobalOnboardingGateMiddleware",
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
# BANCO DE DADOS
# =============================================================================

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

DATABASE_ENGINE = DATABASES["default"].get(
    "ENGINE",
    "",
)

IS_POSTGRESQL = (
    "postgresql" in DATABASE_ENGINE
    or "postgres" in DATABASE_ENGINE
)

IS_SQLITE = (
    "sqlite" in DATABASE_ENGINE
)


# =============================================================================
# CONFIGURAÇÃO DE CONEXÃO
# =============================================================================

if IS_POSTGRESQL:
    DATABASES["default"]["CONN_MAX_AGE"] = env.int(
        "DATABASE_CONN_MAX_AGE",
        default=60,
    )

    DATABASES["default"]["CONN_HEALTH_CHECKS"] = True

    database_options = DATABASES["default"].get(
        "OPTIONS",
        {},
    )

    database_options.update(
        {
            "connect_timeout": env.int(
                "DATABASE_CONNECT_TIMEOUT",
                default=10,
            ),
        }
    )

    DATABASES["default"]["OPTIONS"] = database_options


elif IS_SQLITE:
    DATABASES["default"]["CONN_MAX_AGE"] = 0

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


STATIC_ROOT = Path(
    env("STATIC_ROOT", default=str(Path("/var/lib/moonshield/static") if APPLIANCE_MODE else BASE_DIR / "staticfiles"))
)


# =============================================================================
# MEDIA
# =============================================================================

MEDIA_URL = "/media/"

MEDIA_ROOT = Path(
    env("MEDIA_ROOT", default=str(Path("/var/lib/moonshield/media") if APPLIANCE_MODE else BASE_DIR / "media"))
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
# Removido: O token agora é armazenado via UI em ConfigSistema.mapbox_access_token


# =============================================================================
# SESSÃO / COOKIES
# =============================================================================

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"


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

SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=0)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env.bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", default=False)
SECURE_HSTS_PRELOAD = env.bool("SECURE_HSTS_PRELOAD", default=False)


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


LOG_DIR = Path(
    env(
        "MOONSHIELD_LOG_DIR",
        default=str(Path("/var/log/moonshield/app") if APPLIANCE_MODE else BASE_DIR / "logs"),
    )
)


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
# =============================================================================
# DJANGO ADMIN
# =============================================================================

DJANGO_ADMIN_ENABLED = env.bool("DJANGO_ADMIN_ENABLED", default=False)
DJANGO_ADMIN_PATH = env("DJANGO_ADMIN_PATH", default="admin-moonshield-hidden/")
