# db_setup.py
"""
Ce fichier configure la base de données et crée toutes les tables nécessaires pour l'application
Il prend en compte les prérequis de Flask-Security et utilise la configuration centralisée
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemySessionUserDatastore, UserMixin, RoleMixin, hash_password
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
from config import Config

# Charge les variables d'environnement
load_dotenv()

# Initialisation de Flask et SQLAlchemy
app = Flask(__name__)

# Utilisation de la configuration centralisée
app.config.from_object(Config)

# Initialisation de SQLAlchemy
db = SQLAlchemy(app)

# Tables requises pour Flask-Security
# Table de liaison many-to-many pour roles et users
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('app_management.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
                       )


# Modèle Role pour Flask-Security
class Role(db.Model, RoleMixin):
    """
    Table des rôles pour Flask-Security
    """
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


# Modèle User pour Flask-Security (app_management)
class AppManagement(db.Model, UserMixin):
    """
    Table app_management qui sera utilisée pour l'authentification Flask-Security
    """
    __tablename__ = 'app_management'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    GivenName = db.Column(db.String(45))
    Surname = db.Column(db.String(45))
    user = db.Column(db.String(100))
    # Flask-Security nécessite ces champs
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean(), default=True)
    confirmed_at = db.Column(db.DateTime())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    # Relation avec les rôles
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))


# Modèles pour les autres tables de l'application
class Users(db.Model):
    """
    Table des utilisateurs de l'organisation
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    GivenName = db.Column(db.String(45))
    Surname = db.Column(db.String(45))
    Username = db.Column(db.String(100))
    Title = db.Column(db.String(200))
    Department = db.Column(db.String(45))
    Site = db.Column(db.Text)
    date_create = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))
    date_delete = db.Column(db.DateTime)
    is_delete = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class Computers(db.Model):
    """
    Table des ordinateurs
    """
    __tablename__ = 'computers'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255))
    serial = db.Column(db.String(255))
    otherserial = db.Column(db.String(255))
    Username = db.Column(db.String(255))
    date_create = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))
    date_delete = db.Column(db.DateTime)
    is_delete = db.Column(db.Boolean, default=False)
    is_linked = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class Monitors(db.Model):
    """
    Table des moniteurs
    """
    __tablename__ = 'monitors'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255))
    serial = db.Column(db.String(255))
    otherserial = db.Column(db.String(255))
    Username = db.Column(db.String(255))
    date_create = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))
    date_delete = db.Column(db.DateTime)
    is_delete = db.Column(db.Boolean, default=False)
    is_linked = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class Peripherals(db.Model):
    """
    Table des périphériques
    """
    __tablename__ = 'peripherals'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255))
    serial = db.Column(db.String(255))
    otherserial = db.Column(db.String(255))
    Username = db.Column(db.String(255))
    date_create = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))
    date_delete = db.Column(db.DateTime)
    is_delete = db.Column(db.Boolean, default=False)
    is_linked = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class Phones(db.Model):
    """
    Table des téléphones
    """
    __tablename__ = 'phones'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255))
    serial = db.Column(db.String(255))
    otherserial = db.Column(db.String(255))
    Username = db.Column(db.String(255))
    date_create = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))
    date_delete = db.Column(db.DateTime)
    is_delete = db.Column(db.Boolean, default=False)
    is_linked = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class History(db.Model):
    """
    Table de l'historique des opérations
    """
    __tablename__ = 'history'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    app_management_id = db.Column(db.Integer, db.ForeignKey('app_management.id'))
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    computers_id = db.Column(db.Integer, db.ForeignKey('computers.id'))
    monitors_id = db.Column(db.Integer, db.ForeignKey('monitors.id'))
    peripherals_id = db.Column(db.Integer, db.ForeignKey('peripherals.id'))
    phones_id = db.Column(db.Integer, db.ForeignKey('phones.id'))
    date_mod = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_linked = db.Column(db.Boolean, default=False)
    is_delete = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


# Configuration de Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db.session, AppManagement, Role)
security = Security(app, user_datastore)


def create_database():
    """
    Fonction pour créer toutes les tables dans la base de données
    """
    # Important : établit le contexte d'application
    with app.app_context():
        try:
            # Configuration temporaire pour la création de la base
            global user_datastore
            user_datastore = SQLAlchemySessionUserDatastore(db.session, AppManagement, Role)

            # Crée toutes les tables
            db.create_all()

            # Vérifie si les rôles existent déjà
            admin_role = Role.query.filter_by(name='administrateur').first()
            if not admin_role:
                # Crée les rôles par défaut
                administrator_role = user_datastore.create_role(name='administrateur',
                                                                description='Gère les utilisateurs et leurs rôles')
                gestionnaire_role = user_datastore.create_role(name='gestionnaire',
                                                               description='Crée des événements et édite les éléments')
                lecteur_role = user_datastore.create_role(name='lecteur', description='Accès en lecture seule')

                db.session.commit()

            # Vérifie si l'administrateur par défaut existe
            admin_user = AppManagement.query.filter_by(email='admin@example.com').first()
            if not admin_user:
                # Crée un administrateur par défaut
                admin_user = user_datastore.create_user(
                    email='admin@example.com',
                    password=hash_password('admin'),  # Hash le mot de passe
                    GivenName='Admin',
                    Surname='System',
                    user='admin'
                )

                # Ajoute le rôle administrateur à l'utilisateur
                admin_role = Role.query.filter_by(name='administrateur').first()
                user_datastore.add_role_to_user(admin_user, admin_role)

                # Valide les changements
                db.session.commit()

            print("Base de données et tables créées avec succès !")
            print(f"Connexion effectuée avec: {app.config['SQLALCHEMY_DATABASE_URI']}")

        except Exception as e:
            print(f"Erreur lors de la création de la base de données: {e}")
            raise


if __name__ == '__main__':
    # Crée la base de données et les tables
    create_database()

    # Lance l'application Flask pour tester (optionnel)
    print("\nLancement de l'application de test...")
    app.run(debug=True, port=5000)