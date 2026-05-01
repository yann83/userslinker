# config.py
"""
Centralized configuration for the Flask application.

All sensitive values are read from environment variables.
load_dotenv() is called in app.py BEFORE this module is imported,
so os.environ is already populated when this class is evaluated.

DO NOT call load_dotenv() here — it creates a race condition where Config
attributes are evaluated before the .env file has been read.

Location: config.py  (root of the project, same folder as app.py)
"""

import os


class Config:
    """Base configuration class.

    Every attribute reads its value from an environment variable set by
    the .env file (loaded by app.py before this module is imported).

    IMPORTANT — SECRET_KEY stability:
        Flask uses SECRET_KEY to sign session cookies.  If the key changes
        between server restarts all active sessions are invalidated and
        every logged-in user is silently logged out.
        Flask-Security-Too also derives internal tokens from this key.
        Always keep a fixed value in your .env file.
        Generate a good one with:
            python -c "import secrets; print(secrets.token_hex(32))"

    IMPORTANT — SECURITY_PASSWORD_SALT stability:
        Although Flask-Security-Too 5.x uses bcrypt (which embeds its own
        random salt in every hash), SECURITY_PASSWORD_SALT is still used
        for token generation (password-reset links, confirmation emails...).
        Keep it fixed in .env — changing it invalidates those tokens.
    """

    # -------------------------------------------------------------------------
    # Flask secret key — signs session cookies and Flask-Security tokens.
    # -------------------------------------------------------------------------
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY is not set. Check your .env file.")
    # -------------------------------------------------------------------------
    # PostgreSQL connection settings
    # -------------------------------------------------------------------------
    PG_HOST     = os.environ.get('PG_HOST')     or 'localhost'
    PG_USER     = os.environ.get('PG_USER')     or 'userslinker_app'
    PG_PASSWORD = os.environ.get('PG_PASSWORD') or ''
    PG_DB       = os.environ.get('PG_DB')       or 'bd_userslinker'
    PG_PORT     = os.environ.get('PG_PORT')     or '5432'

    # SQLAlchemy URI — schema is handled by __table_args__ in each model,
    # so no search_path option is needed here.
    SQLALCHEMY_DATABASE_URI = (
        f'postgresql+psycopg2://{PG_USER}:{PG_PASSWORD}'
        f'@{PG_HOST}:{PG_PORT}/{PG_DB}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # -------------------------------------------------------------------------
    # Flask-Security settings
    # -------------------------------------------------------------------------
    SECURITY_PASSWORD_SALT = (
        os.environ.get('SECURITY_PASSWORD_SALT') or 'super-secret-random-salt'
    )
    SECURITY_REGISTERABLE               = False
    SECURITY_SEND_REGISTER_EMAIL        = False
    SECURITY_LOGIN_URL                  = '/login'
    SECURITY_LOGOUT_URL                 = '/logout'
    SECURITY_POST_LOGIN_VIEW            = '/dashboard'
    SECURITY_POST_LOGOUT_VIEW           = '/login'
    SECURITY_LOGIN_WITHOUT_CONFIRMATION = True

    # -------------------------------------------------------------------------
    # Session settings
    # -------------------------------------------------------------------------
    PERMANENT_SESSION_LIFETIME = 3600   # seconds (1 hour)

    # -------------------------------------------------------------------------
    # CSRF — disabled for now to avoid conflicts with Flask-Security forms.
    # -------------------------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_CHECK_DEFAULT = True
    SECURITY_CSRF_PROTECT_FORMS = False
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS = False

    # -------------------------------------------------------------------------
    # Internationalisation (Flask-Babel)
    # Set BABEL_DEFAULT_LOCALE to 'fr' or 'en' to switch the UI language.
    # Available locales must have a compiled .mo file in translations/.
    # -------------------------------------------------------------------------
    BABEL_DEFAULT_LOCALE = 'en'  # <-- change to 'en' pour l'anglais
    BABEL_DEFAULT_TIMEZONE = 'Europe/Paris'