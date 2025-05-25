# db_connector.py
"""
Module pour tester et établir des connexions aux bases de données externes
définies dans le fichier bdd.json
"""

import os
import json
import mysql.connector
from mysql.connector import Error
from flask import current_app


class DBConnector:
    """
    Classe pour gérer les connexions aux bases de données externes
    """

    def __init__(self, json_path='config/bdd.json'):
        """
        Initialise le connecteur en chargeant le fichier de configuration bdd.json

        Args:
            json_path (str): Chemin vers le fichier bdd.json. Par défaut,
                             il cherche dans le répertoire courant.
        """
        """
        Initialise le connecteur en chargeant le fichier de configuration bdd.json

        Args:
            json_path (str): Chemin vers le fichier bdd.json
        """
        self.config = {}
        self.connection_status = {
            'users': {'status': False, 'message': 'Non configuré'},
            'computers': {'status': False, 'message': 'Non configuré'},
            'monitors': {'status': False, 'message': 'Non configuré'},
            'peripherals': {'status': False, 'message': 'Non configuré'},
            'phones': {'status': False, 'message': 'Non configuré'}
        }

        try:
            # Vérifier si le fichier existe
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as file:
                    self.config = json.load(file)

                # Valider la structure du fichier JSON
                self._validate_config()
            else:
                print(f"Fichier {json_path} introuvable.")
        except json.JSONDecodeError as e:
            print(f"Erreur de format JSON dans le fichier {json_path}: {e}")
        except Exception as e:
            print(f"Erreur lors de la lecture du fichier {json_path}: {e}")

    def _validate_config(self):
        """
        Valide la structure du fichier de configuration
        """
        required_sections = ['users', 'computers', 'monitors', 'peripherals', 'phones']
        required_connect_fields = ['host', 'user', 'password', 'db', 'table']

        for section in required_sections:
            # Vérifier si la section existe
            if section not in self.config:
                self.connection_status[section]['message'] = 'Section manquante dans bdd.json'
                continue

            # Vérifier si la clé 'connect' existe
            if 'connect' not in self.config[section]:
                self.connection_status[section]['message'] = 'Clé "connect" manquante'
                continue

            # Vérifier les champs de connexion
            connect_config = self.config[section]['connect']
            missing_fields = [field for field in required_connect_fields if field not in connect_config]

            if missing_fields:
                self.connection_status[section]['message'] = f'Champs manquants: {", ".join(missing_fields)}'
                continue

            # Vérifier si les champs sont vides
            empty_fields = [field for field in required_connect_fields if not connect_config.get(field)]

            if empty_fields:
                self.connection_status[section]['message'] = 'Non configuré (champs vides)'
                continue

            # Vérifier la présence des champs de mapping
            if 'fields' not in self.config[section]:
                self.connection_status[section]['message'] = 'Clé "fields" manquante'

    def test_connection(self, section):
        """
        Teste la connexion à une base de données spécifique

        Args:
            section (str): La section dans le fichier bdd.json (users, computers, etc.)

        Returns:
            dict: Statut de la connexion avec un message
        """
        # Vérifier si la section existe dans la configuration
        if section not in self.config:
            return {'status': False, 'message': 'Non configuré'}

        # Vérifier si la section contient les informations de connexion
        if 'connect' not in self.config[section]:
            return {'status': False, 'message': 'Informations de connexion manquantes'}

        # Récupérer les informations de connexion
        connect_config = self.config[section]['connect']

        try:
            # Tentative de connexion à la base de données
            connection = mysql.connector.connect(
                host=connect_config.get('host', ''),
                user=connect_config.get('user', ''),
                password=connect_config.get('password', ''),
                database=connect_config.get('db', '')
            )

            if connection.is_connected():
                cursor = connection.cursor()

                # Vérifier si la table existe
                table_name = connect_config.get('table', '')
                cursor.execute(f"SHOW TABLES LIKE '{table_name}'")
                table_exists = cursor.fetchone()

                if not table_exists:
                    connection.close()
                    return {'status': False, 'message': f"Table '{table_name}' introuvable"}

                # Vérifier si les champs existent
                if 'fields' in self.config[section]:
                    fields_config = self.config[section]['fields']
                    cursor.execute(f"DESCRIBE {table_name}")
                    table_fields = [row[0] for row in cursor.fetchall()]

                    missing_fields = [field for field in fields_config.values() if field not in table_fields]

                    if missing_fields:
                        connection.close()
                        return {'status': False,
                                'message': f"Champs manquants dans la table: {', '.join(missing_fields)}"}

                connection.close()
                return {'status': True, 'message': 'Connecté avec succès'}

        except Error as e:
            error_message = str(e)
            if 'Access denied' in error_message:
                return {'status': False, 'message': 'Accès refusé - identifiants incorrects'}
            elif 'Unknown database' in error_message:
                return {'status': False, 'message': f"Base de données '{connect_config.get('db', '')}' introuvable"}
            elif 'Can\'t connect to MySQL server' in error_message:
                return {'status': False,
                        'message': f"Impossible de se connecter au serveur {connect_config.get('host', '')}"}
            else:
                return {'status': False, 'message': f"Erreur: {error_message[:50]}..."}

        except Exception as e:
            return {'status': False, 'message': f"Erreur inattendue: {str(e)[:50]}..."}

    def test_all_connections(self):
        """
        Teste toutes les connexions définies dans le fichier bdd.json

        Returns:
            dict: Statut de toutes les connexions
        """
        for section in self.connection_status.keys():
            if section in self.config:
                self.connection_status[section] = self.test_connection(section)

        return self.connection_status


# Exemple d'utilisation si exécuté directement
if __name__ == "__main__":
    connector = DBConnector()
    results = connector.test_all_connections()

    print("Résultats des tests de connexion:")
    for section, status in results.items():
        print(f"{section}: {'✓' if status['status'] else '✗'} - {status['message']}")

    # Exemple d'accès aux données si la connexion est réussie
    if connector.connection_status['users']['status']:
        try:
            connect_config = connector.config['users']['connect']
            connection = mysql.connector.connect(
                host=connect_config.get('host', ''),
                user=connect_config.get('user', ''),
                password=connect_config.get('password', ''),
                database=connect_config.get('db', '')
            )

            if connection.is_connected():
                cursor = connection.cursor(dictionary=True)
                cursor.execute(f"SELECT * FROM {connect_config['table']} LIMIT 5")
                users = cursor.fetchall()
                print(f"\nExemple de données ({len(users)} utilisateurs):")
                for user in users:
                    print(user)

                connection.close()
        except Exception as e:
            print(f"Erreur lors de la récupération des données: {e}")