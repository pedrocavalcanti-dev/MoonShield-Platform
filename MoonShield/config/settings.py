import os
import sys
import environ
from pathlib import Path

env = environ.Env(DEBUG=(bool, False))
BASE_DIR = Path(__file__).resolve().parent.parent
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

SECRET_KEY = env('SECRET_KEY', default='django-insecure-chave-padrao')
DEBUG = env('DEBUG', default=True)
ALLOWED_HOSTS = ['*']

SYSTEM_NAME    = 'MoonShield'
SYSTEM_VERSION = '1.0.0'

# ── sys.path para os apps ficarem acessíveis pelo nome curto ──────────────────
# Mantemos isso pois todo o projeto usa 'autenticacao', 'painel', etc.
sys.path.insert(0, os.path.join(BASE_DIR, 'aplicativos'))

# ── APPS ─────────────────────────────────────────────────────────────────────
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Apps do MoonShield (nomes curtos, resolvidos pelo sys.path acima)
    'autenticacao',
    'painel',
    'mapa_ameacas',
    'dns',
    'ids',
    'firewall',
    'dispositivos',
    'relatorios',
    'configuracoes',
    'incidentes',
    'MoonShield',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                # Caminho completo do context processor
                'autenticacao.context_processors.user_profile_ctx',
            ],
        },
    },
]

# ── BANCO DE DADOS ────────────────────────────────────────────────────────────
DATABASES = {
    'default': env.db_url('DATABASE_URL', default=f'sqlite:///{os.path.join(BASE_DIR, "banco_dados.sqlite3")}')
}

# ── LOCALIZAÇÃO ───────────────────────────────────────────────────────────────
LANGUAGE_CODE = 'pt-br'
TIME_ZONE     = 'America/Sao_Paulo'
USE_I18N      = True
USE_TZ        = True

# ── STATIC / MEDIA ────────────────────────────────────────────────────────────
STATIC_URL       = 'static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]
STATIC_ROOT      = os.path.join(BASE_DIR, 'staticfiles')

MEDIA_URL  = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
MAPBOX_ACCESS_TOKEN = env('MAPBOX_ACCESS_TOKEN', default='')