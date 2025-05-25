# sync_manager.py
"""
Module pour gérer la synchronisation des données depuis des bases externes
vers les tables de l'application UsersLinker.
"""

import os
import json
import mysql.connector
from mysql.connector import Error
from datetime import datetime, timezone
from db_setup import db, Users, Computers, Monitors, Peripherals, Phones


class SyncManager:
    """
    Gestionnaire de synchronisation des données externes
    """

    def __init__(self, config_path, admin_user):
        """
        Initialisation du gestionnaire de synchronisation

        Args:
            config_path (str): Chemin vers le fichier de configuration bdd.json
            admin_user (str): Nom d'utilisateur administrateur effectuant la synchronisation
        """
        self.config_path = config_path
        self.admin_user = admin_user
        self.config = None
        self.results = {
            'status': 'pending',
            'message': '',
            'details': {}
        }

    def load_config(self):
        """
        Charge la configuration depuis le fichier bdd.json

        Returns:
            bool: True si le chargement a réussi, False sinon
        """
        try:
            if not os.path.exists(self.config_path):
                self.results['status'] = 'error'
                self.results['message'] = f"Fichier de configuration introuvable: {self.config_path}"
                return False

            with open(self.config_path, 'r', encoding='utf-8') as file:
                self.config = json.load(file)

            return True

        except json.JSONDecodeError as e:
            self.results['status'] = 'error'
            self.results['message'] = f"Erreur dans le format JSON du fichier de configuration: {str(e)}"
            return False

        except Exception as e:
            self.results['status'] = 'error'
            self.results['message'] = f"Erreur lors du chargement de la configuration: {str(e)}"
            return False

    def connect_to_external_db(self, db_config):
        """
        Établit une connexion à une base de données externe

        Args:
            db_config (dict): Configuration de connexion à la base de données

        Returns:
            connection: Objet de connexion MySQL ou None en cas d'erreur
        """
        try:
            connection = mysql.connector.connect(
                host=db_config['host'],
                user=db_config['user'],
                password=db_config['password'],
                database=db_config['db']
            )
            return connection

        except Error as e:
            error_message = str(e)
            if 'Access denied' in error_message:
                self.results['message'] = f"Accès refusé à la base de données: identifiants incorrects"
            elif 'Unknown database' in error_message:
                self.results['message'] = f"Base de données '{db_config['db']}' introuvable"
            elif "Can't connect to MySQL server" in error_message:
                self.results['message'] = f"Impossible de se connecter au serveur {db_config['host']}"
            else:
                self.results['message'] = f"Erreur de connexion à la base de données: {error_message}"

            return None

    def sync_users(self):
        """
        Synchronise les utilisateurs depuis la base externe

        Returns:
            dict: Statistiques de synchronisation (créés, mis à jour, total)
        """
        if 'users' not in self.config or not self.config['users'].get('connect'):
            return {'created': 0, 'updated': 0, 'total': 0, 'error': 'Configuration manquante'}

        try:
            # Configuration de la base externe
            ext_config = self.config['users']['connect']
            field_mappings = self.config['users']['fields']

            # Connexion à la base externe
            ext_conn = self.connect_to_external_db(ext_config)
            if not ext_conn:
                return {'created': 0, 'updated': 0, 'total': 0, 'error': self.results['message']}

            # Construction de la requête
            ext_cursor = ext_conn.cursor(dictionary=True)
            ext_fields = []
            for app_field, ext_field in field_mappings.items():
                ext_fields.append(f"`{ext_field}` as `{app_field}`")

            query = f"SELECT {', '.join(ext_fields)} FROM `{ext_config['table']}`"
            ext_cursor.execute(query)
            external_users = ext_cursor.fetchall()

            # Récupération des utilisateurs existants
            existing_users = {}
            users_query = Users.query.filter_by(is_delete=False).all()
            for user in users_query:
                existing_users[user.Username] = user

            # Compteurs
            created = 0
            updated = 0
            now = datetime.now(timezone.utc)

            # Traitement des utilisateurs
            for ext_user in external_users:
                if not ext_user.get('Username'):
                    continue  # Ignorer les entrées sans Username

                username = ext_user['Username']

                if username in existing_users:
                    # Mise à jour d'un utilisateur existant
                    user = existing_users[username]
                    user.GivenName = ext_user.get('GivenName', user.GivenName)
                    user.Surname = ext_user.get('Surname', user.Surname)
                    user.Title = ext_user.get('Title', user.Title)
                    user.Department = ext_user.get('Department', user.Department)
                    user.Site = ext_user.get('Site', user.Site)
                    user.date_mod = now
                    user.app_management_user = self.admin_user
                    updated += 1
                else:
                    # Création d'un nouvel utilisateur
                    new_user = Users(
                        GivenName=ext_user.get('GivenName', ''),
                        Surname=ext_user.get('Surname', ''),
                        Username=username,
                        Title=ext_user.get('Title', ''),
                        Department=ext_user.get('Department', ''),
                        Site=ext_user.get('Site', ''),
                        date_create=now,
                        date_mod=now,
                        app_management_user=self.admin_user
                    )
                    db.session.add(new_user)
                    created += 1

            # Validation des changements
            db.session.commit()
            ext_conn.close()

            return {
                'created': created,
                'updated': updated,
                'total': len(external_users)
            }

        except Exception as e:
            db.session.rollback()
            return {
                'created': 0,
                'updated': 0,
                'total': 0,
                'error': f"Erreur lors de la synchronisation des utilisateurs: {str(e)}"
            }

    def sync_material(self, material_type):
        """
        Synchronise le matériel spécifié depuis la base externe

        Args:
            material_type (str): Type de matériel à synchroniser

        Returns:
            dict: Statistiques de synchronisation (créés, mis à jour, total)
        """
        # Mapping des types de matériel vers les modèles
        model_map = {
            'computers': Computers,
            'monitors': Monitors,
            'peripherals': Peripherals,
            'phones': Phones
        }

        if material_type not in model_map:
            return {
                'created': 0,
                'updated': 0,
                'total': 0,
                'error': f"Type de matériel non reconnu: {material_type}"
            }

        if material_type not in self.config or not self.config[material_type].get('connect'):
            return {
                'created': 0,
                'updated': 0,
                'total': 0,
                'error': 'Configuration manquante'
            }

        try:
            # Sélection du modèle approprié
            model = model_map[material_type]

            # Configuration de la base externe
            ext_config = self.config[material_type]['connect']
            field_mappings = self.config[material_type]['fields']

            # Connexion à la base externe
            ext_conn = self.connect_to_external_db(ext_config)
            if not ext_conn:
                return {'created': 0, 'updated': 0, 'total': 0, 'error': self.results['message']}

            # Construction de la requête
            ext_cursor = ext_conn.cursor(dictionary=True)
            ext_fields = []
            for app_field, ext_field in field_mappings.items():
                ext_fields.append(f"`{ext_field}` as `{app_field}`")

            query = f"SELECT {', '.join(ext_fields)} FROM `{ext_config['table']}`"
            ext_cursor.execute(query)
            external_items = ext_cursor.fetchall()

            # Récupération des éléments existants
            existing_items = {}
            items_query = model.query.filter_by(is_delete=False).all()
            for item in items_query:
                if item.serial:  # Ignorer les entrées sans numéro de série
                    existing_items[item.serial] = item

            # Compteurs
            created = 0
            updated = 0
            now = datetime.now(timezone.utc)

            # Traitement des éléments
            for ext_item in external_items:
                # Vérification des champs obligatoires
                if not ext_item.get('name'):
                    continue

                serial = ext_item.get('serial')
                if not serial:
                    # Générer un numéro de série automatique pour les items sans serial
                    serial = f"AUTO_{material_type}_{now.strftime('%Y%m%d%H%M%S')}_{created + updated}"

                if serial in existing_items:
                    # Mise à jour d'un élément existant
                    item = existing_items[serial]
                    item.name = ext_item.get('name')
                    item.otherserial = ext_item.get('otherserial', item.otherserial)
                    item.date_mod = now
                    item.app_management_user = self.admin_user
                    updated += 1
                else:
                    # Création d'un nouvel élément
                    new_item = model(
                        name=ext_item.get('name'),
                        serial=serial,
                        otherserial=ext_item.get('otherserial', ''),
                        date_create=now,
                        date_mod=now,
                        app_management_user=self.admin_user
                    )
                    db.session.add(new_item)
                    created += 1

            # Validation des changements
            db.session.commit()
            ext_conn.close()

            return {
                'created': created,
                'updated': updated,
                'total': len(external_items)
            }

        except Exception as e:
            db.session.rollback()
            return {
                'created': 0,
                'updated': 0,
                'total': 0,
                'error': f"Erreur lors de la synchronisation de {material_type}: {str(e)}"
            }

    def execute_post_sql(self, post_sql_path):
        """
        Exécute les commandes SQL post-import contenues dans un fichier

        Args:
            post_sql_path (str): Chemin vers le fichier SQL post-import

        Returns:
            dict: Résultat de l'exécution des commandes SQL
        """
        try:
            if not os.path.exists(post_sql_path):
                return {
                    'status': 'warning',
                    'message': "Fichier post.sql non trouvé",
                    'commands': 0
                }

            # Lire le fichier SQL
            with open(post_sql_path, 'r', encoding='utf-8') as f:
                post_sql = f.read()

            # Connexion à la base de données de l'application
            # Utiliser les mêmes paramètres que dans app.py
            from config import Config  # Importer la configuration de l'application

            app_db_config = {
                'host': Config.MYSQL_HOST,
                'user': Config.MYSQL_USER,
                'password': Config.MYSQL_PASSWORD,
                'database': Config.MYSQL_DB
            }

            connection = mysql.connector.connect(**app_db_config)
            cursor = connection.cursor()

            # Suite du code...

            # Diviser le fichier en commandes SQL individuelles
            sql_commands = post_sql.split(';')
            executed_commands = 0

            for command in sql_commands:
                # Ignorer les commandes vides
                command = command.strip()
                if command:
                    cursor.execute(command)
                    executed_commands += 1

            # Valider les changements
            connection.commit()
            cursor.close()
            connection.close()

            return {
                'status': 'success',
                'message': f"Exécuté {executed_commands} commandes SQL post-import",
                'commands': executed_commands
            }

        except Exception as e:
            return {
                'status': 'error',
                'message': f"Erreur lors de l'exécution des commandes SQL: {str(e)}",
                'commands': 0
            }

    def run_sync(self):
        """
        Exécute la synchronisation complète (utilisateurs et matériel)

        Returns:
            dict: Résultats de la synchronisation
        """
        # Charger la configuration
        if not self.load_config():
            return self.results

        self.results['status'] = 'success'
        self.results['message'] = 'Synchronisation réussie'

        # Synchronisation des utilisateurs
        users_result = self.sync_users()
        self.results['details']['users'] = users_result

        if users_result.get('error'):
            self.results['message'] += f" (Attention: {users_result['error']})"

        # Synchronisation du matériel
        material_types = ['computers', 'monitors', 'peripherals', 'phones']
        for material_type in material_types:
            mat_result = self.sync_material(material_type)
            self.results['details'][material_type] = mat_result

            if mat_result.get('error'):
                self.results['message'] += f" (Attention: {mat_result['error']})"

        return self.results