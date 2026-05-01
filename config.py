# config.py
"""
Configuration pour l'application Flask
"""

import os
from dotenv import load_dotenv

# Charge les variables d'environnement depuis le fichier .env
load_dotenv()


class Config:
    """
    Configuration de base pour l'application
    """
    # Clé secrète pour Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'

    # Configuration de la base de données MySQL
    MYSQL_HOST = os.environ.get('MYSQL_HOST') or 'localhost'
    MYSQL_USER = os.environ.get('MYSQL_USER') or 'root'
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or ''
    MYSQL_DB = os.environ.get('MYSQL_DB') or 'bd_userslinker'

    # URI SQLAlchemy
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Configuration Flask-Security
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or 'super-secret-random-salt'
    SECURITY_REGISTERABLE = False  # Seul les admin peuvent créer des comptes
    SECURITY_SEND_REGISTER_EMAIL = False
    SECURITY_LOGIN_URL = '/login'
    SECURITY_LOGOUT_URL = '/logout'
    SECURITY_POST_LOGIN_VIEW = '/dashboard'
    SECURITY_POST_LOGOUT_VIEW = '/login'
    SECURITY_LOGIN_WITHOUT_CONFIRMATION = True

    # Configuration des sessions
    PERMANENT_SESSION_LIFETIME = 3600  # 1 heure

    # Protection CSRF - Temporairement désactivée pour résoudre le conflit
    WTF_CSRF_ENABLED = False
    SECURITY_CSRF_PROTECT_FORMS = []
    SECURITY_CSRF_IGNORE_UNAUTH_ENDPOINTS = True