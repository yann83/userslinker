# app.py
"""
Application principale Flask avec authentification
"""

from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemySessionUserDatastore, login_required, current_user, roles_accepted, \
    roles_required, hash_password, verify_password
from flask_bootstrap import Bootstrap5
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime, timezone
from dotenv import load_dotenv
from config import Config
from db_setup import db, Role, AppManagement, Users, History, Computers, Monitors, Peripherals, Phones
from users_import_export import export_users_csv, import_users_csv
import os
import mysql.connector
import re



# Charge les variables d'environnement
load_dotenv()

# Initialisation de Flask
app = Flask(__name__)

# Utilisation de la configuration centralisée
app.config.from_object(Config)

# Initialisation des extensions
db.init_app(app)
Bootstrap5(app)

# CSRF doit être initialisé avant Flask-Security
csrf = CSRFProtect(app)

# Configuration Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db.session, AppManagement, Role)
security = Security(app, user_datastore)


# Ajoute csrf_token au contexte global de Jinja2
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


# Page de connexion (sera gérée par Flask-Security)
@app.route('/')
def index():
    """
    Page d'accueil - redirige vers le login ou le dashboard
    """
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('security.login'))


# Page d'accueil après connexion
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Page principale après connexion - affiche "Bienvenue"
    """
    # Récupère les rôles de l'utilisateur pour l'affichage
    user_roles = [role.name for role in current_user.roles]
    return render_template('dashboard.html', user_roles=user_roles)


# Page de gestion des utilisateurs (administrateur uniquement)
@app.route('/admin/users')
@login_required
@roles_required('administrateur')
def admin_users():
    """
    Page de gestion des utilisateurs - Administrateur seulement
    """
    users = AppManagement.query.all()
    return render_template('admin/users.html', users=users)


# Création d'un nouvel utilisateur
@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@roles_required('administrateur')
def create_user():
    """
    Création d'un nouvel utilisateur
    """
    if request.method == 'POST':
        try:
            # Récupération des données du formulaire
            email = request.form.get('email')
            password = request.form.get('password')
            given_name = request.form.get('given_name')
            surname = request.form.get('surname')
            username = request.form.get('username')
            role_id = request.form.get('role_id')

            # Vérification si l'utilisateur existe déjà
            existing_user = AppManagement.query.filter_by(email=email).first()
            if existing_user:
                flash('Cet email est déjà utilisé.', 'danger')
                return redirect(url_for('create_user'))

            # Création de l'utilisateur avec Flask-Security user_datastore
            # Cette méthode gère automatiquement le fs_uniquifier
            new_user = user_datastore.create_user(
                email=email,
                password=hash_password(password),
                GivenName=given_name,
                Surname=surname,
                user=username
            )

            # Attribution du rôle
            if role_id:
                role = Role.query.get(role_id)
                if role:
                    user_datastore.add_role_to_user(new_user, role)

            db.session.commit()
            flash('Utilisateur créé avec succès.', 'success')
            return redirect(url_for('admin_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de la création : {str(e)}', 'danger')
            return redirect(url_for('create_user'))

    # GET : afficher le formulaire
    roles = Role.query.all()
    return render_template('admin/create_user.html', roles=roles)


# Modification d'un utilisateur
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('administrateur')
def edit_user(user_id):
    """
    Modification d'un utilisateur existant
    """
    user = AppManagement.query.get_or_404(user_id)

    if request.method == 'POST':
        try:
            # Mise à jour des données de base
            user.email = request.form.get('email')
            user.GivenName = request.form.get('given_name')
            user.Surname = request.form.get('surname')
            user.user = request.form.get('username')

            # Mise à jour du mot de passe si fourni
            new_password = request.form.get('password')
            if new_password:
                user.password = hash_password(new_password)

            # CORRECTION : Gestion correcte du champ 'active'
            # Si la checkbox n'est pas cochée, elle n'apparaît pas dans request.form
            # On vérifie explicitement sa présence
            user.active = 'active' in request.form

            # Alternative plus explicite :
            # active_value = request.form.get('active')
            # user.active = active_value == 'on' if active_value else False

            # Mise à jour des rôles
            # Supprimer tous les rôles actuels
            for role in user.roles:
                user_datastore.remove_role_from_user(user, role)

            # Ajouter les nouveaux rôles sélectionnés
            role_ids = request.form.getlist('role_ids')
            for role_id in role_ids:
                role = Role.query.get(role_id)
                if role:
                    user_datastore.add_role_to_user(user, role)

            db.session.commit()

            # Message de feedback plus informatif
            status_text = "actif" if user.active else "inactif"
            flash(f'Utilisateur modifié avec succès. Statut : {status_text}', 'success')
            return redirect(url_for('admin_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Erreur lors de la modification : {str(e)}', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

    # GET : afficher le formulaire
    roles = Role.query.all()
    return render_template('admin/edit_user.html', user=user, roles=roles)

# Suppression d'un utilisateur
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@roles_required('administrateur')
def delete_user(user_id):
    """
    Suppression d'un utilisateur
    """
    try:
        user = AppManagement.query.get_or_404(user_id)

        # Empêcher la suppression du dernier administrateur
        if 'administrateur' in [role.name for role in user.roles]:
            admin_count = AppManagement.query.join(AppManagement.roles).filter(Role.name == 'administrateur').count()
            if admin_count <= 1:
                flash('Impossible de supprimer le dernier administrateur.', 'danger')
                return redirect(url_for('admin_users'))

        # Empêcher la suppression de soi-même
        if user.id == current_user.id:
            flash('Vous ne pouvez pas supprimer votre propre compte.', 'danger')
            return redirect(url_for('admin_users'))

        db.session.delete(user)
        db.session.commit()
        flash('Utilisateur supprimé avec succès.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Erreur lors de la suppression : {str(e)}', 'danger')

    return redirect(url_for('admin_users'))


# Route pour afficher le profil utilisateur
@app.route('/profile')
@login_required
def user_profile():
    """
    Page de profil de l'utilisateur connecté
    Permet de voir ses informations et changer son mot de passe
    """
    return render_template('profile.html')


# Route pour changer le mot de passe
@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    """
    Permet à un utilisateur de changer son propre mot de passe
    Nécessite de connaître l'ancien mot de passe pour sécurité
    """
    try:
        # Récupération des données du formulaire
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Validation des données
        if not current_password or not new_password or not confirm_password:
            flash('Tous les champs sont obligatoires.', 'danger')
            return redirect(url_for('user_profile'))

        # Vérifier que le nouveau mot de passe est assez long
        if len(new_password) < 6:
            flash('Le nouveau mot de passe doit contenir au moins 6 caractères.', 'danger')
            return redirect(url_for('user_profile'))

        # Vérifier que les nouveaux mots de passe correspondent
        if new_password != confirm_password:
            flash('Les nouveaux mots de passe ne correspondent pas.', 'danger')
            return redirect(url_for('user_profile'))

        # Vérifier l'ancien mot de passe
        if not verify_password(current_password, current_user.password):
            flash('Le mot de passe actuel est incorrect.', 'danger')
            return redirect(url_for('user_profile'))

        # Vérifier que le nouveau mot de passe est différent de l'ancien
        if verify_password(new_password, current_user.password):
            flash('Le nouveau mot de passe doit être différent de l\'ancien.', 'warning')
            return redirect(url_for('user_profile'))

        # Mettre à jour le mot de passe
        current_user.password = hash_password(new_password)
        db.session.commit()

        # Message de succès
        flash('Votre mot de passe a été modifié avec succès. '
              'Vous devrez utiliser ce nouveau mot de passe lors de votre prochaine connexion.',
              'success')

        # Log de sécurité (optionnel - pour tracer les changements de mot de passe)
        app.logger.info(f'Password changed for user: {current_user.email} ({current_user.user})')

        return redirect(url_for('user_profile'))

    except Exception as e:
        # En cas d'erreur, annuler les changements
        db.session.rollback()
        app.logger.error(f'Error changing password for user {current_user.email}: {str(e)}')
        flash(f'Erreur lors du changement de mot de passe : {str(e)}', 'danger')
        return redirect(url_for('user_profile'))


# Route API pour vérifier la force du mot de passe (optionnelle)
@app.route('/api/check_password_strength', methods=['POST'])
@login_required
def check_password_strength():
    """
    API pour vérifier la force d'un mot de passe côté serveur
    Peut être utilisée pour des validations supplémentaires
    """
    try:
        password = request.json.get('password', '')

        # Critères de validation
        criteria = {
            'length': len(password) >= 8,
            'lowercase': bool(re.search(r'[a-z]', password)),
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }

        # Calcul du score
        score = sum(criteria.values())

        # Détermination de la force
        if score < 2:
            strength = {'level': 'weak', 'message': 'Très faible'}
        elif score < 3:
            strength = {'level': 'fair', 'message': 'Faible'}
        elif score < 4:
            strength = {'level': 'good', 'message': 'Correct'}
        else:
            strength = {'level': 'strong', 'message': 'Fort'}

        return jsonify({
            'status': 'success',
            'strength': strength,
            'criteria': criteria,
            'score': score
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ---- Workflow d'événements ----

@app.route('/events/create', methods=['GET'])
@login_required
@roles_required('gestionnaire')
def create_event():
    """
    Première étape du workflow de création d'événements
    """
    return render_template('events/create.html')


@app.route('/events/select_user', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def select_user():
    """
    Étape 1: Sélectionner un utilisateur pour créer un événement
    Version modifiée pour supporter la recherche dynamique
    """
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')

        if not user_id:
            flash("Veuillez sélectionner un utilisateur", 'warning')
            return redirect(url_for('select_user'))

        # Vérifier si l'utilisateur existe
        user = Users.query.get(user_id)
        if not user:
            flash("L'utilisateur sélectionné n'existe pas", 'danger')
            return redirect(url_for('select_user'))

        # Redirection en fonction de l'action choisie
        if action == 'link':
            return redirect(url_for('select_material_to_link', user_id=user_id))
        elif action == 'unlink':
            return redirect(url_for('select_material_to_unlink', user_id=user_id))
        else:
            flash("Action non valide", 'danger')
            return redirect(url_for('select_user'))

    # GET : afficher la page avec la nouvelle interface de recherche
    # Plus besoin de charger tous les utilisateurs d'avance
    return render_template('events/select_user.html')


# Modification de la route select_material_to_link pour supporter la nouvelle interface
@app.route('/events/select_material_to_link/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def select_material_to_link(user_id):
    """
    Étape 2A: Sélectionner le matériel à lier à l'utilisateur
    Version modifiée pour supporter la recherche dynamique
    """
    # Récupérer l'utilisateur
    user = Users.query.get_or_404(user_id)

    if request.method == 'POST':
        material_type = request.form.get('material_type')
        material_ids = request.form.getlist('material_ids')

        if not material_type or not material_ids:
            flash("Veuillez sélectionner au moins un matériel", 'warning')
            return redirect(url_for('select_material_to_link', user_id=user_id))

        # Validation des IDs (s'assurer qu'ils sont des entiers valides)
        try:
            material_ids = [int(mid) for mid in material_ids]
        except ValueError:
            flash("IDs de matériel invalides", 'danger')
            return redirect(url_for('select_material_to_link', user_id=user_id))

        # Création des liens et historique
        try:
            model = get_model_by_type(material_type)
            if not model:
                flash(f"Type de matériel '{material_type}' invalide.", 'danger')
                return redirect(url_for('select_material_to_link', user_id=user_id))

            linked_count = 0
            warnings = []

            for material_id in material_ids:
                material = model.query.get(material_id)
                if material:
                    # Vérifier si le matériel est déjà lié à un autre utilisateur
                    if material.is_linked and material.Username and material.Username != user.Username:
                        warnings.append(f"Le matériel '{material.name}' est déjà lié à {material.Username}")
                        continue

                    # Mettre à jour le matériel
                    material.Username = user.Username
                    material.is_linked = True
                    material.date_mod = datetime.now(timezone.utc)
                    material.app_management_user = current_user.user

                    # Créer une entrée dans l'historique
                    history_entry = History()
                    history_entry.app_management_id = current_user.id
                    history_entry.users_id = user.id
                    history_entry.is_linked = True
                    history_entry.app_management_user = current_user.user

                    # Ajouter l'ID du matériel dans le champ correspondant
                    if material_type == 'computers':
                        history_entry.computers_id = material.id
                    elif material_type == 'monitors':
                        history_entry.monitors_id = material.id
                    elif material_type == 'peripherals':
                        history_entry.peripherals_id = material.id
                    elif material_type == 'phones':
                        history_entry.phones_id = material.id

                    db.session.add(history_entry)
                    linked_count += 1

            db.session.commit()

            # Messages de feedback
            if linked_count > 0:
                flash(f"{linked_count} élément(s) de matériel lié(s) avec succès à {user.GivenName} {user.Surname}",
                      'success')

            for warning in warnings:
                flash(warning, 'warning')

            return redirect(url_for('event_summary', user_id=user_id))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la création du lien : {str(e)}", 'danger')
            return redirect(url_for('select_material_to_link', user_id=user_id))

    # GET : afficher la page avec la nouvelle interface de recherche
    return render_template('events/select_material_to_link.html', user=user)


@app.route('/events/select_material_to_unlink/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def select_material_to_unlink(user_id):
    """
    Étape 2B: Sélectionner le matériel à délier de l'utilisateur
    Version modifiée pour supporter la recherche dynamique
    """
    # Récupérer l'utilisateur
    user = Users.query.get_or_404(user_id)

    if request.method == 'POST':
        material_type = request.form.get('material_type')
        material_ids = request.form.getlist('material_ids')

        if not material_type or not material_ids:
            flash("Veuillez sélectionner au moins un matériel", 'warning')
            return redirect(url_for('select_material_to_unlink', user_id=user_id))

        # Validation des IDs
        try:
            material_ids = [int(mid) for mid in material_ids]
        except ValueError:
            flash("IDs de matériel invalides", 'danger')
            return redirect(url_for('select_material_to_unlink', user_id=user_id))

        # Suppression des liens et historique
        try:
            model = get_model_by_type(material_type)
            if not model:
                flash(f"Type de matériel '{material_type}' invalide.", 'danger')
                return redirect(url_for('select_material_to_unlink', user_id=user_id))

            unlinked_count = 0
            warnings = []

            for material_id in material_ids:
                material = model.query.get(material_id)
                if material:
                    # Vérifier si le matériel est bien lié à cet utilisateur
                    if not material.is_linked or material.Username != user.Username:
                        warnings.append(f"Le matériel '{material.name}' n'est pas lié à cet utilisateur")
                        continue

                    # Mettre à jour le matériel
                    material.Username = None
                    material.is_linked = False
                    material.date_mod = datetime.now(timezone.utc)
                    material.app_management_user = current_user.user

                    # Créer une entrée dans l'historique
                    history_entry = History()
                    history_entry.app_management_id = current_user.id
                    history_entry.users_id = user.id
                    history_entry.is_linked = False
                    history_entry.app_management_user = current_user.user

                    # Ajouter l'ID du matériel dans le champ correspondant
                    if material_type == 'computers':
                        history_entry.computers_id = material.id
                    elif material_type == 'monitors':
                        history_entry.monitors_id = material.id
                    elif material_type == 'peripherals':
                        history_entry.peripherals_id = material.id
                    elif material_type == 'phones':
                        history_entry.phones_id = material.id

                    db.session.add(history_entry)
                    unlinked_count += 1

            db.session.commit()

            # Messages de feedback
            if unlinked_count > 0:
                flash(
                    f"{unlinked_count} élément(s) de matériel délié(s) avec succès de {user.GivenName} {user.Surname}",
                    'success')

            for warning in warnings:
                flash(warning, 'warning')

            return redirect(url_for('event_summary', user_id=user_id))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la suppression du lien : {str(e)}", 'danger')
            return redirect(url_for('select_material_to_unlink', user_id=user_id))

    # GET : afficher la page avec la nouvelle interface
    return render_template('events/select_material_to_unlink.html', user=user)


@app.route('/events/summary/<int:user_id>')
@login_required
@roles_required('gestionnaire')
def event_summary(user_id):
    """
    Étape 3: Résumé de l'événement
    """
    # Récupérer l'utilisateur
    user = Users.query.get_or_404(user_id)

    # Récupérer le matériel lié à cet utilisateur
    computers = Computers.query.filter_by(
        Username=user.Username,
        is_linked=True,
        is_delete=False
    ).all()

    monitors = Monitors.query.filter_by(
        Username=user.Username,
        is_linked=True,
        is_delete=False
    ).all()

    peripherals = Peripherals.query.filter_by(
        Username=user.Username,
        is_linked=True,
        is_delete=False
    ).all()

    phones = Phones.query.filter_by(
        Username=user.Username,
        is_linked=True,
        is_delete=False
    ).all()

    # Récupérer l'historique récent pour cet utilisateur
    history = History.query.filter_by(
        users_id=user.id
    ).order_by(
        History.date_mod.desc()
    ).limit(10).all()

    return render_template('events/summary.html',
                           user=user,
                           computers=computers,
                           monitors=monitors,
                           peripherals=peripherals,
                           phones=phones,
                           history=history,
                           # Ajouter les modèles pour pouvoir les utiliser dans le template
                           Computers=Computers,
                           Monitors=Monitors,
                           Peripherals=Peripherals,
                           Phones=Phones)


# Page des listes (gestionnaire et lecteur)
@app.route('/lists')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def lists():
    """
    Page des listes - Accessible aux gestionnaires et lecteurs
    """
    return render_template('lists.html')


# Page des rapports (gestionnaire et lecteur) - mise à jour
@app.route('/reports')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports():
    """
    Page des rapports - Accessible aux gestionnaires et lecteurs
    """
    return render_template('reports.html')


# Nouveau rapport par service
@app.route('/reports/by_service', methods=['GET', 'POST'])
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports_by_service():
    """
    Rapport des utilisateurs et leurs matériels par service
    """
    # Récupérer tous les services uniques (non vides et non supprimés)
    services_query = db.session.query(Users.Department).filter(
        Users.is_delete == False,
        Users.Department.isnot(None),
        Users.Department != ''
    ).distinct().order_by(Users.Department.asc()).all()

    # Convertir en liste simple
    services = [service[0] for service in services_query if service[0]]

    # Variables pour les résultats
    selected_service = None
    date_from = None
    date_to = None
    users_data = []
    generation_date = datetime.now(timezone.utc)  # Toujours définie

    if request.method == 'POST':
        try:
            # Récupérer les paramètres du formulaire
            selected_service = request.form.get('service')
            date_from_str = request.form.get('date_from')
            date_to_str = request.form.get('date_to')

            # Validation du service (obligatoire)
            if not selected_service:
                flash("Veuillez sélectionner un service", 'warning')
                return render_template('reports/by_service.html',
                                       services=services)

            # Conversion des dates (optionnelles)
            if date_from_str:
                try:
                    date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
                except ValueError:
                    flash("Format de date incorrect pour la date de début", 'warning')
                    date_from = None

            if date_to_str:
                try:
                    date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
                    # Ajouter 23:59:59 pour inclure toute la journée
                    date_to = date_to.replace(hour=23, minute=59, second=59)
                except ValueError:
                    flash("Format de date incorrect pour la date de fin", 'warning')
                    date_to = None

            # Validation de la cohérence des dates
            if date_from and date_to and date_from > date_to:
                flash("La date de début ne peut pas être postérieure à la date de fin", 'warning')
                return render_template('reports/by_service.html',
                                       services=services,
                                       selected_service=selected_service,
                                       date_from=date_from_str,
                                       date_to=date_to_str)

            # Récupérer les utilisateurs du service sélectionné
            users_in_service = Users.query.filter(
                Users.Department == selected_service,
                Users.is_delete == False
            ).order_by(Users.Surname.asc(), Users.GivenName.asc()).all()

            if not users_in_service:
                flash(f"Aucun utilisateur trouvé dans le service '{selected_service}'", 'info')
                return render_template('reports/by_service.html',
                                       services=services,
                                       selected_service=selected_service,
                                       date_from=date_from_str,
                                       date_to=date_to_str)

            # Pour chaque utilisateur, récupérer son matériel et son historique
            for user in users_in_service:
                user_data = {
                    'user': user,
                    'materials': {
                        'computers': [],
                        'monitors': [],
                        'peripherals': [],
                        'phones': []
                    },
                    'history': []
                }

                # Récupérer le matériel lié à l'utilisateur
                user_data['materials']['computers'] = Computers.query.filter(
                    Computers.Username == user.Username,
                    Computers.is_linked == True,
                    Computers.is_delete == False
                ).all()

                user_data['materials']['monitors'] = Monitors.query.filter(
                    Monitors.Username == user.Username,
                    Monitors.is_linked == True,
                    Monitors.is_delete == False
                ).all()

                user_data['materials']['peripherals'] = Peripherals.query.filter(
                    Peripherals.Username == user.Username,
                    Peripherals.is_linked == True,
                    Peripherals.is_delete == False
                ).all()

                user_data['materials']['phones'] = Phones.query.filter(
                    Phones.Username == user.Username,
                    Phones.is_linked == True,
                    Phones.is_delete == False
                ).all()

                # Récupérer l'historique pour cet utilisateur
                history_query = History.query.filter(
                    History.users_id == user.id
                )

                # Appliquer les filtres de date si spécifiés
                if date_from:
                    history_query = history_query.filter(History.date_mod >= date_from)
                if date_to:
                    history_query = history_query.filter(History.date_mod <= date_to)

                # Ordonner par date décroissante (plus récent en premier)
                history_entries = history_query.order_by(History.date_mod.desc()).all()

                # Enrichir l'historique avec les informations du matériel
                for entry in history_entries:
                    material_info = None
                    material_type = None

                    # Identifier le type de matériel et récupérer ses informations
                    if entry.computers_id:
                        material = Computers.query.get(entry.computers_id)
                        material_type = 'Ordinateur'
                    elif entry.monitors_id:
                        material = Monitors.query.get(entry.monitors_id)
                        material_type = 'Moniteur'
                    elif entry.peripherals_id:
                        material = Peripherals.query.get(entry.peripherals_id)
                        material_type = 'Périphérique'
                    elif entry.phones_id:
                        material = Phones.query.get(entry.phones_id)
                        material_type = 'Téléphone'

                    if material:
                        material_info = {
                            'name': material.name,
                            'serial': material.serial,
                            'otherserial': material.otherserial
                        }

                    # Ajouter l'entrée enrichie à l'historique
                    user_data['history'].append({
                        'entry': entry,
                        'material_info': material_info,
                        'material_type': material_type
                    })

                users_data.append(user_data)

            # Message de succès
            flash(f"Rapport généré pour {len(users_data)} utilisateur(s) du service '{selected_service}'", 'success')

        except Exception as e:
            # En cas d'erreur, afficher un message et revenir au formulaire
            flash(f"Erreur lors de la génération du rapport : {str(e)}", 'danger')
            return render_template('reports/by_service.html',
                                   services=services)

    return render_template('reports/by_service.html',
                           services=services,
                           selected_service=selected_service,
                           date_from=date_from.strftime('%Y-%m-%d') if date_from else None,
                           date_to=date_to.strftime('%Y-%m-%d') if date_to else None,
                           users_data=users_data,
                           generation_date=generation_date)


# Nouveau rapport par utilisateur
@app.route('/reports/by_user', methods=['GET', 'POST'])
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports_by_user():
    """
    Rapport détaillé pour un utilisateur spécifique
    Avec recherche dynamique et historique complet
    """
    # Variables pour les résultats
    selected_user = None
    user_data = None
    generation_date = datetime.now(timezone.utc)

    if request.method == 'POST':
        try:
            # Récupérer l'ID utilisateur sélectionné
            user_id = request.form.get('user_id')

            # Validation de l'utilisateur (obligatoire)
            if not user_id:
                flash("Veuillez sélectionner un utilisateur", 'warning')
                return render_template('reports/by_user.html',
                                       generation_date=generation_date)

            # Récupérer l'utilisateur sélectionné
            selected_user = Users.query.filter(
                Users.id == user_id,
                Users.is_delete == False
            ).first()

            if not selected_user:
                flash("L'utilisateur sélectionné n'existe pas ou a été supprimé", 'danger')
                return render_template('reports/by_user.html',
                                       generation_date=generation_date)

            # Construire les données complètes de l'utilisateur
            user_data = {
                'user': selected_user,
                'materials': {
                    'computers': [],
                    'monitors': [],
                    'peripherals': [],
                    'phones': []
                },
                'history': [],
                'statistics': {
                    'total_materials': 0,
                    'total_movements': 0,
                    'last_activity': None,
                    'first_activity': None
                }
            }

            # Récupérer TOUT le matériel lié à l'utilisateur (actuel)
            user_data['materials']['computers'] = Computers.query.filter(
                Computers.Username == selected_user.Username,
                Computers.is_linked == True,
                Computers.is_delete == False
            ).order_by(Computers.name.asc()).all()

            user_data['materials']['monitors'] = Monitors.query.filter(
                Monitors.Username == selected_user.Username,
                Monitors.is_linked == True,
                Monitors.is_delete == False
            ).order_by(Monitors.name.asc()).all()

            user_data['materials']['peripherals'] = Peripherals.query.filter(
                Peripherals.Username == selected_user.Username,
                Peripherals.is_linked == True,
                Peripherals.is_delete == False
            ).order_by(Peripherals.name.asc()).all()

            user_data['materials']['phones'] = Phones.query.filter(
                Phones.Username == selected_user.Username,
                Phones.is_linked == True,
                Phones.is_delete == False
            ).order_by(Phones.name.asc()).all()

            # Compter le total de matériel lié
            total_materials = sum(len(materials) for materials in user_data['materials'].values())
            user_data['statistics']['total_materials'] = total_materials

            # Récupérer TOUT l'historique pour cet utilisateur (toutes dates)
            history_entries = History.query.filter(
                History.users_id == selected_user.id
            ).order_by(History.date_mod.desc()).all()

            user_data['statistics']['total_movements'] = len(history_entries)

            # Enrichir l'historique avec les informations du matériel
            for entry in history_entries:
                material_info = None
                material_type = None
                material_icon = None

                # Identifier le type de matériel et récupérer ses informations
                if entry.computers_id:
                    material = Computers.query.get(entry.computers_id)
                    material_type = 'Ordinateur'
                    material_icon = 'fas fa-laptop'
                elif entry.monitors_id:
                    material = Monitors.query.get(entry.monitors_id)
                    material_type = 'Moniteur'
                    material_icon = 'fas fa-desktop'
                elif entry.peripherals_id:
                    material = Peripherals.query.get(entry.peripherals_id)
                    material_type = 'Périphérique'
                    material_icon = 'fas fa-keyboard'
                elif entry.phones_id:
                    material = Phones.query.get(entry.phones_id)
                    material_type = 'Téléphone'
                    material_icon = 'fas fa-mobile-alt'

                if material:
                    material_info = {
                        'name': material.name,
                        'serial': material.serial,
                        'otherserial': material.otherserial,
                        'is_deleted': material.is_delete  # Savoir si le matériel a été supprimé depuis
                    }

                # Ajouter l'entrée enrichie à l'historique
                user_data['history'].append({
                    'entry': entry,
                    'material_info': material_info,
                    'material_type': material_type,
                    'material_icon': material_icon
                })

            # Calculer les statistiques d'activité
            if history_entries:
                user_data['statistics']['last_activity'] = history_entries[0].date_mod
                user_data['statistics']['first_activity'] = history_entries[-1].date_mod

            # Message de succès
            flash(f"Rapport généré pour {selected_user.GivenName} {selected_user.Surname}", 'success')

        except Exception as e:
            # En cas d'erreur, afficher un message et revenir au formulaire
            flash(f"Erreur lors de la génération du rapport : {str(e)}", 'danger')
            return render_template('reports/by_user.html',
                                   generation_date=generation_date)

    return render_template('reports/by_user.html',
                           selected_user=selected_user,
                           user_data=user_data,
                           generation_date=generation_date)


# Nouveau rapport par type de matériel
@app.route('/reports/by_material_type', methods=['GET', 'POST'])
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports_by_material_type():
    """
    Rapport d'analyse par type de matériel avec graphiques
    Analyse de la répartition et utilisation par type de matériel
    """
    # Variables pour les résultats
    selected_material_type = None
    material_data = None
    generation_date = datetime.now(timezone.utc)

    # Liste des types de matériel disponibles
    material_types = {
        'computers': {'name': 'Ordinateurs', 'icon': 'fas fa-laptop', 'model': Computers},
        'monitors': {'name': 'Moniteurs', 'icon': 'fas fa-desktop', 'model': Monitors},
        'peripherals': {'name': 'Périphériques', 'icon': 'fas fa-keyboard', 'model': Peripherals},
        'phones': {'name': 'Téléphones', 'icon': 'fas fa-mobile-alt', 'model': Phones}
    }

    if request.method == 'POST':
        try:
            # Récupérer le type de matériel sélectionné
            selected_material_type = request.form.get('material_type')

            # Validation du type de matériel (obligatoire)
            if not selected_material_type or selected_material_type not in material_types:
                flash("Veuillez sélectionner un type de matériel valide", 'warning')
                return render_template('reports/by_material_type.html',
                                       material_types=material_types,
                                       generation_date=generation_date)

            # Récupérer le modèle correspondant
            model = material_types[selected_material_type]['model']
            material_name = material_types[selected_material_type]['name']

            # Construire les données complètes du matériel
            material_data = {
                'type': selected_material_type,
                'name': material_name,
                'icon': material_types[selected_material_type]['icon'],
                'statistics': {
                    'total': 0,
                    'linked': 0,
                    'unlinked': 0,
                    'unique_users': 0,
                    'deleted': 0
                },
                'by_status': [],
                'by_service': [],
                'by_user': [],
                'recent_movements': [],
                'top_users': []
            }

            # Statistiques globales
            total_items = model.query.filter_by(is_delete=False).count()
            linked_items = model.query.filter_by(is_delete=False, is_linked=True).count()
            unlinked_items = total_items - linked_items
            deleted_items = model.query.filter_by(is_delete=True).count()

            # Compter les utilisateurs uniques
            unique_users_query = db.session.query(model.Username).filter(
                model.is_delete == False,
                model.is_linked == True,
                model.Username.isnot(None),
                model.Username != ''
            ).distinct().count()

            material_data['statistics'] = {
                'total': total_items,
                'linked': linked_items,
                'unlinked': unlinked_items,
                'unique_users': unique_users_query,
                'deleted': deleted_items
            }

            # Données pour graphique par statut
            material_data['by_status'] = [
                {'label': 'Liés', 'value': linked_items, 'color': '#28a745'},
                {'label': 'Libres', 'value': unlinked_items, 'color': '#6c757d'},
                {'label': 'Supprimés', 'value': deleted_items, 'color': '#dc3545'}
            ]

            # Répartition par service (pour le matériel lié)
            services_query = db.session.query(
                Users.Department,
                db.func.count(model.id).label('count')
            ).join(
                model, Users.Username == model.Username
            ).filter(
                model.is_delete == False,
                model.is_linked == True,
                Users.is_delete == False,
                Users.Department.isnot(None),
                Users.Department != ''
            ).group_by(Users.Department).order_by(
                db.func.count(model.id).desc()
            ).limit(10).all()

            # Couleurs pour les graphiques par service
            service_colors = ['#007bff', '#28a745', '#ffc107', '#dc3545', '#17a2b8',
                              '#6f42c1', '#e83e8c', '#fd7e14', '#20c997', '#6c757d']

            material_data['by_service'] = []
            for i, (service, count) in enumerate(services_query):
                material_data['by_service'].append({
                    'label': service,
                    'value': count,
                    'color': service_colors[i % len(service_colors)]
                })

            # Top 10 des utilisateurs avec le plus de matériel de ce type
            top_users_query = db.session.query(
                model.Username,
                Users.GivenName,
                Users.Surname,
                Users.Department,
                db.func.count(model.id).label('count')
            ).join(
                Users, Users.Username == model.Username
            ).filter(
                model.is_delete == False,
                model.is_linked == True,
                Users.is_delete == False,
                model.Username.isnot(None),
                model.Username != ''
            ).group_by(
                model.Username, Users.GivenName, Users.Surname, Users.Department
            ).order_by(
                db.func.count(model.id).desc()
            ).limit(10).all()

            material_data['top_users'] = []
            for username, given_name, surname, department, count in top_users_query:
                material_data['top_users'].append({
                    'username': username,
                    'full_name': f"{given_name} {surname}",
                    'department': department or 'Non renseigné',
                    'count': count
                })

            # Mouvements récents (30 derniers)
            recent_movements_query = History.query.filter(
                getattr(History, f"{selected_material_type}_id").isnot(None)
            ).order_by(History.date_mod.desc()).limit(30).all()

            material_data['recent_movements'] = []
            for movement in recent_movements_query:
                # Récupérer l'utilisateur
                user = Users.query.get(movement.users_id) if movement.users_id else None

                # Récupérer le matériel
                material_id = getattr(movement, f"{selected_material_type}_id")
                material_item = model.query.get(material_id) if material_id else None

                material_data['recent_movements'].append({
                    'date': movement.date_mod,
                    'action': 'Lié' if movement.is_linked else 'Délié',
                    'user': user,
                    'material': material_item,
                    'manager': movement.app_management_user
                })

            # Message de succès
            flash(f"Rapport généré pour {material_name.lower()}", 'success')

        except Exception as e:
            # En cas d'erreur, afficher un message et revenir au formulaire
            flash(f"Erreur lors de la génération du rapport : {str(e)}", 'danger')
            return render_template('reports/by_material_type.html',
                                   material_types=material_types,
                                   generation_date=generation_date)

    return render_template('reports/by_material_type.html',
                           material_types=material_types,
                           selected_material_type=selected_material_type,
                           material_data=material_data,
                           generation_date=generation_date)


# Ajoutez cette route dans votre app.py

@app.route('/reports/activity', methods=['GET', 'POST'])
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports_activity():
    """
    Rapport d'activité avec analyse des mouvements et activités sur une période donnée
    Inclut des statistiques par gestionnaire et des graphiques de tendance
    """
    # Récupérer tous les gestionnaires uniques pour le filtre
    gestionnaires_query = db.session.query(History.app_management_user).filter(
        History.app_management_user.isnot(None),
        History.app_management_user != ''
    ).distinct().order_by(History.app_management_user.asc()).all()

    # Convertir en liste simple
    gestionnaires = [gest[0] for gest in gestionnaires_query if gest[0]]

    # Variables pour les résultats
    date_from = None
    date_to = None
    selected_gestionnaire = None
    action_filter = None
    activity_data = None
    generation_date = datetime.now(timezone.utc)  # Toujours définie

    if request.method == 'POST':
        try:
            # Récupérer les paramètres du formulaire
            date_from_str = request.form.get('date_from')
            date_to_str = request.form.get('date_to')
            selected_gestionnaire = request.form.get('gestionnaire_filter')
            action_filter = request.form.get('action_filter')

            # Validation des dates (obligatoires)
            if not date_from_str or not date_to_str:
                flash("Les dates de début et de fin sont obligatoires", 'warning')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       generation_date=generation_date)

            # Conversion des dates
            try:
                date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
                date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
                # Ajouter 23:59:59 pour inclure toute la journée de fin
                date_to = date_to.replace(hour=23, minute=59, second=59)
            except ValueError:
                flash("Format de date incorrect", 'warning')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       generation_date=generation_date)

            # Validation de la cohérence des dates
            if date_from > date_to:
                flash("La date de début ne peut pas être postérieure à la date de fin", 'warning')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       date_from=date_from_str,
                                       date_to=date_to_str,
                                       selected_gestionnaire=selected_gestionnaire,
                                       action_filter=action_filter,
                                       generation_date=generation_date)

            # Vérifier que la période n'est pas trop longue (max 1 an pour éviter les problèmes de performance)
            date_diff = date_to - date_from
            if date_diff.days > 365:
                flash("La période sélectionnée ne peut pas dépasser 1 an", 'warning')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       date_from=date_from_str,
                                       date_to=date_to_str,
                                       selected_gestionnaire=selected_gestionnaire,
                                       action_filter=action_filter,
                                       generation_date=generation_date)

            # Construction de la requête principale pour l'historique
            history_query = History.query.filter(
                History.date_mod >= date_from,
                History.date_mod <= date_to
            )

            # Appliquer le filtre gestionnaire si spécifié
            if selected_gestionnaire:
                history_query = history_query.filter(
                    History.app_management_user == selected_gestionnaire
                )

            # Appliquer le filtre d'action si spécifié
            if action_filter == 'link':
                history_query = history_query.filter(History.is_linked == True)
            elif action_filter == 'unlink':
                history_query = history_query.filter(History.is_linked == False)

            # Récupérer toutes les activités pour la période
            all_activities = history_query.order_by(History.date_mod.desc()).all()

            if not all_activities:
                flash("Aucune activité trouvée pour les critères sélectionnés", 'info')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       date_from=date_from_str,
                                       date_to=date_to_str,
                                       selected_gestionnaire=selected_gestionnaire,
                                       action_filter=action_filter,
                                       generation_date=generation_date)

            # Construire les données d'activité
            activity_data = build_activity_data(all_activities, date_from, date_to)

            # Message de succès
            flash(f"Rapport d'activité généré : {len(all_activities)} activité(s) trouvée(s)", 'success')

        except Exception as e:
            # En cas d'erreur, afficher un message et revenir au formulaire
            flash(f"Erreur lors de la génération du rapport : {str(e)}", 'danger')
            return render_template('reports/activity.html',
                                   gestionnaires=gestionnaires,
                                   generation_date=generation_date)

    return render_template('reports/activity.html',
                           gestionnaires=gestionnaires,
                           date_from=date_from.strftime('%Y-%m-%d') if date_from else None,
                           date_to=date_to.strftime('%Y-%m-%d') if date_to else None,
                           selected_gestionnaire=selected_gestionnaire,
                           action_filter=action_filter,
                           activity_data=activity_data,
                           generation_date=generation_date)


def build_activity_data(activities, date_from, date_to):
    """
    Construit les données structurées pour le rapport d'activité

    Args:
        activities: Liste des activités History
        date_from: Date de début
        date_to: Date de fin

    Returns:
        dict: Données structurées pour le template
    """
    from collections import defaultdict, Counter
    import json

    # Statistiques générales
    total_activities = len(activities)
    total_links = sum(1 for activity in activities if activity.is_linked)
    total_unlinks = total_activities - total_links

    # Compteur des utilisateurs uniques impactés
    unique_users = set()
    for activity in activities:
        if activity.users_id:
            unique_users.add(activity.users_id)

    # Données pour les graphiques par jour
    daily_data = defaultdict(lambda: {'total': 0, 'links': 0, 'unlinks': 0})

    # Parcourir toutes les activités pour les statistiques quotidiennes
    for activity in activities:
        date_key = activity.date_mod.strftime('%Y-%m-%d')
        daily_data[date_key]['total'] += 1
        if activity.is_linked:
            daily_data[date_key]['links'] += 1
        else:
            daily_data[date_key]['unlinks'] += 1

    # Créer la liste complète des dates (combler les trous)
    from datetime import timedelta
    current_date = date_from.date()
    end_date = date_to.date()

    dates = []
    totals = []
    links = []
    unlinks = []

    while current_date <= end_date:
        date_str = current_date.strftime('%Y-%m-%d')
        dates.append(current_date.strftime('%d/%m'))

        day_data = daily_data.get(date_str, {'total': 0, 'links': 0, 'unlinks': 0})
        totals.append(day_data['total'])
        links.append(day_data['links'])
        unlinks.append(day_data['unlinks'])

        current_date += timedelta(days=1)

    # Statistiques par type de matériel
    material_stats = {
        'Ordinateurs': 0,
        'Moniteurs': 0,
        'Périphériques': 0,
        'Téléphones': 0
    }

    for activity in activities:
        if activity.computers_id:
            material_stats['Ordinateurs'] += 1
        elif activity.monitors_id:
            material_stats['Moniteurs'] += 1
        elif activity.peripherals_id:
            material_stats['Périphériques'] += 1
        elif activity.phones_id:
            material_stats['Téléphones'] += 1

    # Statistiques par gestionnaire
    manager_stats_raw = defaultdict(lambda: {'total': 0, 'links': 0, 'unlinks': 0})

    for activity in activities:
        manager = activity.app_management_user or 'Inconnu'
        manager_stats_raw[manager]['total'] += 1
        if activity.is_linked:
            manager_stats_raw[manager]['links'] += 1
        else:
            manager_stats_raw[manager]['unlinks'] += 1

    # Calculer la moyenne quotidienne pour chaque gestionnaire
    period_days = (date_to.date() - date_from.date()).days + 1
    manager_stats = []
    manager_chart_labels = []
    manager_chart_links = []
    manager_chart_unlinks = []

    for manager, stats in sorted(manager_stats_raw.items()):
        daily_avg = stats['total'] / period_days if period_days > 0 else 0
        manager_stats.append({
            'manager': manager,
            'total_activities': stats['total'],
            'links': stats['links'],
            'unlinks': stats['unlinks'],
            'daily_average': daily_avg
        })

        # Données pour le graphique
        manager_chart_labels.append(manager)
        manager_chart_links.append(stats['links'])
        manager_chart_unlinks.append(stats['unlinks'])

    # Top des utilisateurs les plus impactés
    user_activity_count = defaultdict(lambda: {'total': 0, 'links': 0, 'unlinks': 0})

    for activity in activities:
        if activity.users_id:
            user_activity_count[activity.users_id]['total'] += 1
            if activity.is_linked:
                user_activity_count[activity.users_id]['links'] += 1
            else:
                user_activity_count[activity.users_id]['unlinks'] += 1

    # Récupérer les informations des utilisateurs les plus actifs
    top_users = []
    sorted_users = sorted(user_activity_count.items(), key=lambda x: x[1]['total'], reverse=True)[:10]

    for user_id, stats in sorted_users:
        user = Users.query.get(user_id)
        if user:
            top_users.append({
                'user_name': f"{user.GivenName} {user.Surname}",
                'username': user.Username,
                'department': user.Department,
                'total_activities': stats['total'],
                'links': stats['links'],
                'unlinks': stats['unlinks']
            })

    # Enrichir les 50 activités les plus récentes avec les informations des matériels et utilisateurs
    recent_activities = []
    for activity in activities[:50]:  # Limiter à 50 pour éviter la surcharge
        # Identifier le type de matériel et récupérer ses informations
        material_info = None
        material_type = None
        material_icon = None

        if activity.computers_id:
            material = Computers.query.get(activity.computers_id)
            material_type = 'Ordinateur'
            material_icon = 'fas fa-laptop'
        elif activity.monitors_id:
            material = Monitors.query.get(activity.monitors_id)
            material_type = 'Moniteur'
            material_icon = 'fas fa-desktop'
        elif activity.peripherals_id:
            material = Peripherals.query.get(activity.peripherals_id)
            material_type = 'Périphérique'
            material_icon = 'fas fa-keyboard'
        elif activity.phones_id:
            material = Phones.query.get(activity.phones_id)
            material_type = 'Téléphone'
            material_icon = 'fas fa-mobile-alt'

        if material:
            material_info = {
                'name': material.name,
                'serial': material.serial,
                'otherserial': material.otherserial
            }

        # Récupérer les informations de l'utilisateur
        user_info = None
        if activity.users_id:
            user = Users.query.get(activity.users_id)
            if user:
                user_info = {
                    'GivenName': user.GivenName,
                    'Surname': user.Surname,
                    'Username': user.Username
                }

        # Ajouter l'activité enrichie
        recent_activities.append({
            'id': activity.id,
            'date_mod': activity.date_mod,
            'is_linked': activity.is_linked,
            'app_management_user': activity.app_management_user,
            'material_info': material_info,
            'material_type': material_type,
            'material_icon': material_icon,
            'user_info': user_info
        })

    # Structurer toutes les données
    activity_data = {
        'statistics': {
            'total_activities': total_activities,
            'total_links': total_links,
            'total_unlinks': total_unlinks,
            'unique_users': len(unique_users)
        },
        'daily_data': {
            'dates': dates,
            'totals': totals,
            'links': links,
            'unlinks': unlinks
        },
        'material_stats': {
            'labels': list(material_stats.keys()),
            'data': list(material_stats.values())
        },
        'manager_stats': manager_stats,
        'manager_chart': {
            'labels': manager_chart_labels,
            'links': manager_chart_links,
            'unlinks': manager_chart_unlinks
        },
        'top_users': top_users,
        'recent_activities': recent_activities
    }

    return activity_data


# API pour rechercher des utilisateurs (spécifique aux rapports)
@app.route('/api/reports/search_users')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_reports_search_users():
    """
    API pour la recherche d'utilisateurs dans les rapports
    Similaire au workflow mais optimisée pour les rapports
    """
    try:
        # Récupérer le terme de recherche depuis les paramètres GET
        search_term = request.args.get('q', '').strip()

        # Vérifier la longueur minimale
        if len(search_term) < 4:
            return jsonify({
                'status': 'success',
                'users': [],
                'message': 'Minimum 4 caractères requis'
            })

        # Recherche optimisée (uniquement dans GivenName, Surname, Username)
        search_pattern = f"%{search_term}%"

        users = Users.query.filter(
            Users.is_delete == False
        ).filter(
            # Rechercher uniquement dans les champs pertinents
            db.or_(
                Users.GivenName.ilike(search_pattern),
                Users.Surname.ilike(search_pattern),
                Users.Username.ilike(search_pattern)
            )
        ).order_by(
            # Priorité : correspondance exacte dans Username, puis ordre alphabétique
            Users.Username.ilike(f"{search_term}%").desc(),
            Users.Surname.asc(),
            Users.GivenName.asc()
        ).limit(10).all()  # Limiter strictement à 10 résultats

        # Convertir les utilisateurs en format JSON avec informations enrichies
        users_data = []
        for user in users:
            # Compter rapidement le matériel lié pour chaque utilisateur
            total_computers = Computers.query.filter_by(Username=user.Username, is_linked=True, is_delete=False).count()
            total_monitors = Monitors.query.filter_by(Username=user.Username, is_linked=True, is_delete=False).count()
            total_peripherals = Peripherals.query.filter_by(Username=user.Username, is_linked=True,
                                                            is_delete=False).count()
            total_phones = Phones.query.filter_by(Username=user.Username, is_linked=True, is_delete=False).count()
            total_materials = total_computers + total_monitors + total_peripherals + total_phones

            # Compter l'historique
            total_history = History.query.filter_by(users_id=user.id).count()

            users_data.append({
                'id': user.id,
                'GivenName': user.GivenName or '',
                'Surname': user.Surname or '',
                'Username': user.Username or '',
                'Title': user.Title or '',
                'Department': user.Department or '',
                'Site': user.Site or '',
                'total_materials': total_materials,
                'total_history': total_history
            })

        return jsonify({
            'status': 'success',
            'users': users_data,
            'count': len(users_data),
            'search_term': search_term
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la recherche : {str(e)}',
            'users': []
        }), 500


# API pour obtenir la liste des services (pour AJAX si nécessaire)
@app.route('/api/services')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_services():
    """
    API pour récupérer la liste des services uniques
    """
    try:
        services_query = db.session.query(Users.Department).filter(
            Users.is_delete == False,
            Users.Department.isnot(None),
            Users.Department != ''
        ).distinct().order_by(Users.Department.asc()).all()

        services = [service[0] for service in services_query if service[0]]

        return jsonify({
            'status': 'success',
            'services': services
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la récupération des services : {str(e)}',
            'services': []
        }), 500


# Page test pour vérifier la connexion aux bases externes
@app.route('/db_check')
@login_required
def db_check():
    """
    Vérifie la connexion aux bases de données externes
    """
    try:
        # Importer le module DBConnector
        from db_connector import DBConnector

        # Chemin vers le fichier bdd.json (ajuster selon l'emplacement réel)
        json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'bdd.json')

        # Tester les connexions
        connector = DBConnector(json_path)
        connection_status = connector.test_all_connections()

        return render_template(
            'db_check.html',
            connection_status=connection_status,
            config_exists=os.path.exists(json_path)
        )
    except Exception as e:
        flash(f"Erreur lors de la vérification des connexions: {str(e)}", 'danger')
        return render_template(
            'db_check.html',
            error=str(e),
            config_exists=False
        )


@app.route('/api/check_connection_status')
@login_required
def check_connection_status():
    """
    API pour vérifier rapidement le statut des connexions aux bases de données externes
    Retourne un JSON avec le statut des connexions
    """
    try:
        # Importer le module DBConnector
        from db_connector import DBConnector

        # Chemin vers le fichier bdd.json
        json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config',  'bdd.json')

        # Vérifier si le fichier existe
        if not os.path.exists(json_path):
            return jsonify({
                'users': {'status': False, 'message': 'Fichier de configuration introuvable'},
                'computers': {'status': False, 'message': 'Fichier de configuration introuvable'},
                'monitors': {'status': False, 'message': 'Fichier de configuration introuvable'},
                'peripherals': {'status': False, 'message': 'Fichier de configuration introuvable'},
                'phones': {'status': False, 'message': 'Fichier de configuration introuvable'}
            })

        # Tester les connexions
        connector = DBConnector(json_path)
        connection_status = connector.test_all_connections()

        return jsonify(connection_status)

    except Exception as e:
        # En cas d'erreur, retourner un statut d'erreur pour toutes les connexions
        error_message = str(e)
        return jsonify({
            'users': {'status': False, 'message': error_message},
            'computers': {'status': False, 'message': error_message},
            'monitors': {'status': False, 'message': error_message},
            'peripherals': {'status': False, 'message': error_message},
            'phones': {'status': False, 'message': error_message}
        })


# Statistiques des utilisateurs
@app.route('/admin/users/stats')
@login_required
@roles_required('administrateur')
def users_stats():
    """
    Page de statistiques des utilisateurs
    """
    # Compter le total des utilisateurs
    total_users = AppManagement.query.count()

    # Compter par rôle
    admin_count = AppManagement.query.join(AppManagement.roles).filter(Role.name == 'administrateur').count()
    gestionnaire_count = AppManagement.query.join(AppManagement.roles).filter(Role.name == 'gestionnaire').count()
    lecteur_count = AppManagement.query.join(AppManagement.roles).filter(Role.name == 'lecteur').count()

    # Compter actifs/inactifs
    active_count = AppManagement.query.filter_by(active=True).count()
    inactive_count = AppManagement.query.filter_by(active=False).count()

    return render_template('admin/users_stats.html',
                           total_users=total_users,
                           admin_count=admin_count,
                           gestionnaire_count=gestionnaire_count,
                           lecteur_count=lecteur_count,
                           active_count=active_count,
                           inactive_count=inactive_count)


# Export des utilisateurs
@app.route('/admin/users/export')
@login_required
@roles_required('administrateur')
def export_users():
    """
    Exporte la liste des utilisateurs au format CSV
    """
    return export_users_csv()


# Import des utilisateurs
@app.route('/admin/users/import', methods=['GET', 'POST'])
@login_required
@roles_required('administrateur')
def import_users():
    """
    Importe des utilisateurs depuis un fichier CSV
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Aucun fichier sélectionné', 'danger')
            return redirect(url_for('import_users'))

        file = request.files['file']
        if file.filename == '':
            flash('Aucun fichier sélectionné', 'danger')
            return redirect(url_for('import_users'))

        if file and file.filename.endswith('.csv'):
            try:
                imported_count, errors = import_users_csv(file)

                if imported_count > 0:
                    flash(f'{imported_count} utilisateur(s) importé(s) avec succès', 'success')

                if errors:
                    for error in errors:
                        flash(error, 'warning')

                return redirect(url_for('admin_users'))

            except Exception as e:
                flash(f'Erreur lors de l\'import : {str(e)}', 'danger')
                return redirect(url_for('import_users'))
        else:
            flash('Le fichier doit être au format CSV', 'danger')
            return redirect(url_for('import_users'))

    # GET : afficher le formulaire
    return render_template('admin/import_users.html')


# ---- Gestion des utilisateurs (table users) ----

@app.route('/users')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def users_list():
    """
    Affiche la liste des utilisateurs de l'organisation avec filtre par service
    """
    # Récupérer le service sélectionné depuis les paramètres GET
    selected_service = request.args.get('service', '').strip()

    # Construire la requête de base (utilisateurs non supprimés)
    query = Users.query.filter_by(is_delete=False)

    # Appliquer le filtre par service si sélectionné
    if selected_service:
        query = query.filter(Users.Department == selected_service)

    # Récupérer les utilisateurs filtrés
    users = query.order_by(Users.Surname.asc(), Users.GivenName.asc()).all()

    # Récupérer tous les services uniques (non vides et non supprimés) pour le filtre
    services_query = db.session.query(Users.Department).filter(
        Users.is_delete == False,
        Users.Department.isnot(None),
        Users.Department != ''
    ).distinct().order_by(Users.Department.asc()).all()

    # Convertir en liste simple
    services = [service[0] for service in services_query if service[0]]

    return render_template('users/list.html',
                         users=users,
                         services=services,
                         selected_service=selected_service)


@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def user_create():
    """
    Création d'un nouvel utilisateur de l'organisation
    """
    if request.method == 'POST':
        try:
            # Récupération des données du formulaire
            given_name = request.form.get('given_name')
            surname = request.form.get('surname')
            username = request.form.get('username')
            title = request.form.get('title')
            department = request.form.get('department')
            site = request.form.get('site')

            # Vérification si l'utilisateur existe déjà
            existing_user = Users.query.filter_by(Username=username).first()
            if existing_user and not existing_user.is_delete:
                flash(f"L'utilisateur {username} existe déjà.", 'warning')
                return redirect(url_for('user_create'))

            # Création du nouvel utilisateur
            new_user = Users(
                GivenName=given_name,
                Surname=surname,
                Username=username,
                Title=title,
                Department=department,
                Site=site,
                app_management_user=current_user.user
            )

            db.session.add(new_user)
            db.session.commit()

            flash(f"L'utilisateur {given_name} {surname} a été créé avec succès.", 'success')
            return redirect(url_for('users_list'))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la création de l'utilisateur : {str(e)}", 'danger')
            return redirect(url_for('user_create'))

    # GET : affichage du formulaire
    return render_template('users/create.html')


@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def user_edit(user_id):
    """
    Modification d'un utilisateur de l'organisation
    """
    user = Users.query.get_or_404(user_id)

    # Vérifier si l'utilisateur est dans la corbeille
    if user.is_delete:
        flash("Cet utilisateur est dans la corbeille et ne peut pas être modifié.", 'warning')
        return redirect(url_for('users_list'))

    if request.method == 'POST':
        try:
            # Mise à jour des données
            user.GivenName = request.form.get('given_name')
            user.Surname = request.form.get('surname')
            user.Username = request.form.get('username')
            user.Title = request.form.get('title')
            user.Department = request.form.get('department')
            user.Site = request.form.get('site')

            # Mettre à jour la date de modification et l'utilisateur qui a fait la modification
            user.date_mod = datetime.now(timezone.utc)
            user.app_management_user = current_user.user

            db.session.commit()

            flash(f"L'utilisateur {user.GivenName} {user.Surname} a été modifié avec succès.", 'success')
            return redirect(url_for('users_list'))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la modification de l'utilisateur : {str(e)}", 'danger')
            return redirect(url_for('user_edit', user_id=user_id))

    # GET : affichage du formulaire pré-rempli
    return render_template('users/edit.html', user=user)


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def user_delete(user_id):
    """
    Placer un utilisateur dans la corbeille (soft delete)
    """
    try:
        user = Users.query.get_or_404(user_id)

        # Soft delete : mettre à jour les champs is_delete et date_delete
        user.is_delete = True
        user.date_delete = datetime.now(timezone.utc)
        user.app_management_user = current_user.user

        db.session.commit()

        flash(f"L'utilisateur {user.GivenName} {user.Surname} a été placé dans la corbeille.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors de la suppression de l'utilisateur : {str(e)}", 'danger')

    return redirect(url_for('users_list'))


@app.route('/users/restore/<int:user_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def user_restore(user_id):
    """
    Restaurer un utilisateur depuis la corbeille
    """
    try:
        user = Users.query.get_or_404(user_id)

        # Restaurer l'utilisateur
        user.is_delete = False
        user.date_delete = None
        user.app_management_user = current_user.user

        db.session.commit()

        flash(f"L'utilisateur {user.GivenName} {user.Surname} a été restauré.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors de la restauration de l'utilisateur : {str(e)}", 'danger')

    return redirect(url_for('users_trash'))


@app.route('/users/trash')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def users_trash():
    """
    Affiche la liste des utilisateurs dans la corbeille
    """
    users = Users.query.filter_by(is_delete=True).all()
    return render_template('users/trash.html', users=users)


@app.route('/users/purge/<int:user_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def user_purge(user_id):
    """
    Suppression définitive d'un utilisateur (hard delete)
    """
    try:
        user = Users.query.get_or_404(user_id)

        # Vérifier si l'utilisateur est dans la corbeille
        if not user.is_delete:
            flash("Cet utilisateur n'est pas dans la corbeille et ne peut pas être supprimé définitivement.", 'warning')
            return redirect(url_for('users_list'))

        # Supprimer les entrées de l'historique associées à cet utilisateur
        History.query.filter_by(users_id=user_id).delete()

        # Suppression définitive
        db.session.delete(user)
        db.session.commit()

        flash(f"L'utilisateur a été supprimé définitivement.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors de la suppression définitive de l'utilisateur : {str(e)}", 'danger')

    return redirect(url_for('users_trash'))


@app.route('/api/search_users')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_search_users():
    """
    API pour rechercher des utilisateurs
    Retourne une liste JSON des utilisateurs qui correspondent aux critères
    """
    try:
        # Récupérer le terme de recherche depuis les paramètres GET
        search_term = request.args.get('q', '').strip()

        # Si aucun terme de recherche, retourner tous les utilisateurs (limité)
        if not search_term:
            users = Users.query.filter_by(is_delete=False).limit(100).all()
        else:
            # Recherche dans plusieurs champs avec LIKE (insensible à la casse)
            search_pattern = f"%{search_term}%"

            users = Users.query.filter(
                Users.is_delete == False
            ).filter(
                # Rechercher dans tous les champs pertinents
                db.or_(
                    Users.GivenName.ilike(search_pattern),
                    Users.Surname.ilike(search_pattern),
                    Users.Username.ilike(search_pattern),
                    Users.Title.ilike(search_pattern),
                    Users.Department.ilike(search_pattern),
                    Users.Site.ilike(search_pattern)
                )
            ).order_by(
                # Tri par pertinence : d'abord par nom/prénom, puis par département
                Users.Surname.asc(),
                Users.GivenName.asc()
            ).limit(500).all()  # Limiter à 500 résultats pour éviter la surcharge

        # Convertir les utilisateurs en format JSON
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'GivenName': user.GivenName or '',
                'Surname': user.Surname or '',
                'Username': user.Username or '',
                'Title': user.Title or '',
                'Department': user.Department or '',
                'Site': user.Site or '',
                'date_create': user.date_create.strftime('%d/%m/%Y') if user.date_create else '',
                'date_mod': user.date_mod.strftime('%d/%m/%Y') if user.date_mod else ''
            })

        return jsonify({
            'status': 'success',
            'count': len(users_data),
            'users': users_data,
            'search_term': search_term
        })

    except Exception as e:
        # En cas d'erreur, retourner un message d'erreur JSON
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la recherche : {str(e)}',
            'users': []
        }), 500


@app.route('/api/search_departments')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_search_departments():
    """
    API pour récupérer la liste des départements/services uniques
    Utilisée pour alimenter le filtre par département
    """
    try:
        # Récupérer tous les départements uniques, non vides et non supprimés
        departments_query = db.session.query(Users.Department).filter(
            Users.is_delete == False,
            Users.Department.isnot(None),
            Users.Department != ''
        ).distinct().order_by(Users.Department.asc()).all()

        # Extraire les noms des départements
        departments = [dept[0] for dept in departments_query if dept[0]]

        return jsonify({
            'status': 'success',
            'departments': departments
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la récupération des départements : {str(e)}',
            'departments': []
        }), 500


# Route alternative pour la recherche avec autocomplétion avancée
@app.route('/api/autocomplete_users')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_autocomplete_users():
    """
    API d'autocomplétion pour les utilisateurs
    Retourne des suggestions basées sur les premiers caractères tapés
    Optimisée pour des réponses rapides
    """
    try:
        search_term = request.args.get('q', '').strip()
        limit = int(request.args.get('limit', 10))  # Limiter les suggestions

        if len(search_term) < 2:
            return jsonify({
                'status': 'success',
                'suggestions': []
            })

        search_pattern = f"{search_term}%"  # Recherche au début des mots

        # Recherche optimisée pour l'autocomplétion
        suggestions = db.session.query(
            Users.id,
            Users.GivenName,
            Users.Surname,
            Users.Username,
            Users.Department
        ).filter(
            Users.is_delete == False
        ).filter(
            db.or_(
                Users.GivenName.ilike(search_pattern),
                Users.Surname.ilike(search_pattern),
                Users.Username.ilike(search_pattern)
            )
        ).order_by(
            Users.Surname.asc(),
            Users.GivenName.asc()
        ).limit(limit).all()

        # Formater les suggestions
        suggestions_data = []
        for suggestion in suggestions:
            suggestions_data.append({
                'id': suggestion.id,
                'label': f"{suggestion.Surname} {suggestion.GivenName} ({suggestion.Username})",
                'value': suggestion.Username,
                'department': suggestion.Department or ''
            })

        return jsonify({
            'status': 'success',
            'suggestions': suggestions_data
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'suggestions': []
        }), 500


# Ajoutez ces routes dans votre app.py pour la recherche de matériel

@app.route('/api/search_materials')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_search_materials():
    """
    API pour rechercher du matériel par type
    Retourne une liste JSON du matériel qui correspond aux critères
    """
    try:
        # Récupérer les paramètres de recherche
        material_type = request.args.get('material_type', '').strip()
        search_term = request.args.get('q', '').strip()

        # Vérifier que le type de matériel est valide
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Type de matériel invalide: {material_type}',
                'materials': []
            }), 400

        # Si aucun terme de recherche, retourner tout le matériel (limité)
        if not search_term:
            materials = model.query.filter_by(is_delete=False).limit(200).all()
        else:
            # Recherche dans plusieurs champs avec LIKE (insensible à la casse)
            search_pattern = f"%{search_term}%"

            materials = model.query.filter(
                model.is_delete == False
            ).filter(
                # Rechercher dans tous les champs pertinents
                db.or_(
                    model.name.ilike(search_pattern),
                    model.serial.ilike(search_pattern),
                    model.otherserial.ilike(search_pattern),
                    model.Username.ilike(search_pattern)
                )
            ).order_by(
                # Tri par pertinence : d'abord par nom, puis par statut lié/non lié
                model.name.asc(),
                model.is_linked.desc()  # Matériel lié en premier
            ).limit(500).all()  # Limiter à 500 résultats

        # Convertir le matériel en format JSON
        materials_data = []
        for material in materials:
            materials_data.append({
                'id': material.id,
                'name': material.name or '',
                'serial': material.serial or '',
                'otherserial': material.otherserial or '',
                'Username': material.Username or '',
                'is_linked': material.is_linked or False,
                'date_create': material.date_create.strftime('%Y-%m-%d') if material.date_create else '',
                'date_mod': material.date_mod.strftime('%Y-%m-%d') if material.date_mod else '',
                'app_management_user': material.app_management_user or ''
            })

        return jsonify({
            'status': 'success',
            'count': len(materials_data),
            'materials': materials_data,
            'search_term': search_term,
            'material_type': material_type
        })

    except Exception as e:
        # En cas d'erreur, retourner un message d'erreur JSON
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la recherche : {str(e)}',
            'materials': []
        }), 500


@app.route('/api/search_material_users/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_search_material_users(material_type):
    """
    API pour récupérer la liste des utilisateurs uniques liés à un type de matériel
    Utilisée pour alimenter le filtre par utilisateur
    """
    try:
        # Vérifier que le type de matériel est valide
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Type de matériel invalide: {material_type}',
                'users': []
            }), 400

        # Récupérer tous les utilisateurs uniques, non vides et non supprimés
        users_query = db.session.query(model.Username).filter(
            model.is_delete == False,
            model.Username.isnot(None),
            model.Username != ''
        ).distinct().order_by(model.Username.asc()).all()

        # Extraire les noms des utilisateurs
        users = [user[0] for user in users_query if user[0]]

        return jsonify({
            'status': 'success',
            'users': users,
            'material_type': material_type
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la récupération des utilisateurs : {str(e)}',
            'users': []
        }), 500


@app.route('/api/material_statistics/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_material_statistics(material_type):
    """
    API pour récupérer les statistiques d'un type de matériel
    """
    try:
        # Vérifier que le type de matériel est valide
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Type de matériel invalide: {material_type}',
                'statistics': {}
            }), 400

        # Calculer les statistiques
        total_count = model.query.filter_by(is_delete=False).count()
        linked_count = model.query.filter_by(is_delete=False, is_linked=True).count()
        unlinked_count = total_count - linked_count

        # Compter les utilisateurs uniques
        unique_users_query = db.session.query(model.Username).filter(
            model.is_delete == False,
            model.Username.isnot(None),
            model.Username != ''
        ).distinct().count()

        # Statistiques par utilisateur (top 10)
        user_stats_query = db.session.query(
            model.Username,
            db.func.count(model.id).label('count')
        ).filter(
            model.is_delete == False,
            model.Username.isnot(None),
            model.Username != ''
        ).group_by(model.Username).order_by(
            db.func.count(model.id).desc()
        ).limit(10).all()

        user_stats = [{'username': stat[0], 'count': stat[1]} for stat in user_stats_query]

        return jsonify({
            'status': 'success',
            'statistics': {
                'total': total_count,
                'linked': linked_count,
                'unlinked': unlinked_count,
                'unique_users': unique_users_query,
                'top_users': user_stats
            },
            'material_type': material_type
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors du calcul des statistiques : {str(e)}',
            'statistics': {}
        }), 500


# Route alternative pour l'autocomplétion du matériel
@app.route('/api/autocomplete_materials/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_autocomplete_materials(material_type):
    """
    API d'autocomplétion pour le matériel
    Retourne des suggestions basées sur les premiers caractères tapés
    Optimisée pour des réponses rapides
    """
    try:
        # Vérifier que le type de matériel est valide
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Type de matériel invalide: {material_type}',
                'suggestions': []
            }), 400

        search_term = request.args.get('q', '').strip()
        limit = int(request.args.get('limit', 15))  # Limiter les suggestions

        if len(search_term) < 3:  # Minimum 3 caractères pour l'autocomplétion
            return jsonify({
                'status': 'success',
                'suggestions': []
            })

        search_pattern = f"{search_term}%"  # Recherche au début des mots

        # Recherche optimisée pour l'autocomplétion
        suggestions = db.session.query(
            model.id,
            model.name,
            model.serial,
            model.otherserial,
            model.Username,
            model.is_linked
        ).filter(
            model.is_delete == False
        ).filter(
            db.or_(
                model.name.ilike(search_pattern),
                model.serial.ilike(search_pattern),
                model.otherserial.ilike(search_pattern)
            )
        ).order_by(
            model.name.asc()
        ).limit(limit).all()

        # Formater les suggestions
        suggestions_data = []
        for suggestion in suggestions:
            # Créer un label descriptif
            label_parts = [suggestion.name or 'Sans nom']
            if suggestion.serial:
                label_parts.append(f"S/N: {suggestion.serial}")
            if suggestion.otherserial:
                label_parts.append(f"Inv: {suggestion.otherserial}")
            if suggestion.Username:
                label_parts.append(f"→ {suggestion.Username}")

            suggestions_data.append({
                'id': suggestion.id,
                'label': ' | '.join(label_parts),
                'name': suggestion.name or '',
                'serial': suggestion.serial or '',
                'otherserial': suggestion.otherserial or '',
                'username': suggestion.Username or '',
                'is_linked': suggestion.is_linked or False,
                'status': 'Lié' if suggestion.is_linked else 'Libre'
            })

        return jsonify({
            'status': 'success',
            'suggestions': suggestions_data,
            'material_type': material_type
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'suggestions': []
        }), 500


# Route pour la recherche avancée de matériel avec filtres multiples
@app.route('/api/advanced_search_materials/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_advanced_search_materials(material_type):
    """
    API pour recherche avancée de matériel avec filtres multiples
    Paramètres supportés:
    - q: terme de recherche
    - status: linked/unlinked
    - user: nom d'utilisateur
    - date_from: date de création depuis (YYYY-MM-DD)
    - date_to: date de création jusqu'à (YYYY-MM-DD)
    - sort_by: name/serial/date_mod/username
    - sort_order: asc/desc
    """
    try:
        # Vérifier que le type de matériel est valide
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Type de matériel invalide: {material_type}',
                'materials': []
            }), 400

        # Récupérer les paramètres de recherche
        search_term = request.args.get('q', '').strip()
        status_filter = request.args.get('status', '').strip()
        user_filter = request.args.get('user', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        sort_by = request.args.get('sort_by', 'name').strip()
        sort_order = request.args.get('sort_order', 'asc').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # Construire la requête de base
        query = model.query.filter(model.is_delete == False)

        # Appliquer le filtre de recherche textuelle
        if search_term:
            search_pattern = f"%{search_term}%"
            query = query.filter(
                db.or_(
                    model.name.ilike(search_pattern),
                    model.serial.ilike(search_pattern),
                    model.otherserial.ilike(search_pattern),
                    model.Username.ilike(search_pattern)
                )
            )

        # Appliquer le filtre de statut
        if status_filter == 'linked':
            query = query.filter(model.is_linked == True)
        elif status_filter == 'unlinked':
            query = query.filter(model.is_linked == False)

        # Appliquer le filtre d'utilisateur
        if user_filter:
            query = query.filter(model.Username.ilike(f"%{user_filter}%"))

        # Appliquer les filtres de date
        if date_from:
            try:
                from datetime import datetime
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(model.date_create >= date_from_obj)
            except ValueError:
                pass  # Ignorer les dates invalides

        if date_to:
            try:
                from datetime import datetime
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
                query = query.filter(model.date_create <= date_to_obj)
            except ValueError:
                pass  # Ignorer les dates invalides

        # Appliquer le tri
        sort_column = getattr(model, sort_by, model.name)
        if sort_order.lower() == 'desc':
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())

        # Appliquer la pagination
        materials = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        # Convertir les résultats en JSON
        materials_data = []
        for material in materials.items:
            materials_data.append({
                'id': material.id,
                'name': material.name or '',
                'serial': material.serial or '',
                'otherserial': material.otherserial or '',
                'Username': material.Username or '',
                'is_linked': material.is_linked or False,
                'date_create': material.date_create.strftime('%Y-%m-%d') if material.date_create else '',
                'date_mod': material.date_mod.strftime('%Y-%m-%d') if material.date_mod else '',
                'app_management_user': material.app_management_user or ''
            })

        return jsonify({
            'status': 'success',
            'materials': materials_data,
            'pagination': {
                'page': materials.page,
                'pages': materials.pages,
                'per_page': materials.per_page,
                'total': materials.total,
                'has_prev': materials.has_prev,
                'has_next': materials.has_next
            },
            'filters': {
                'search_term': search_term,
                'status': status_filter,
                'user': user_filter,
                'date_from': date_from,
                'date_to': date_to,
                'sort_by': sort_by,
                'sort_order': sort_order
            },
            'material_type': material_type
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la recherche avancée : {str(e)}',
            'materials': []
        }), 500


# Route pour l'export des résultats de recherche de matériel
@app.route('/api/export_materials/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_export_materials(material_type):
    """
    API pour exporter les résultats de recherche de matériel en CSV
    Utilise les mêmes paramètres que la recherche avancée
    """
    try:
        import csv
        import io
        from flask import make_response

        # Vérifier que le type de matériel est valide
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Type de matériel invalide: {material_type}'
            }), 400

        # Récupérer les paramètres de recherche (mêmes que pour la recherche avancée)
        search_term = request.args.get('q', '').strip()
        status_filter = request.args.get('status', '').strip()
        user_filter = request.args.get('user', '').strip()

        # Construire la requête (sans pagination pour l'export)
        query = model.query.filter(model.is_delete == False)

        if search_term:
            search_pattern = f"%{search_term}%"
            query = query.filter(
                db.or_(
                    model.name.ilike(search_pattern),
                    model.serial.ilike(search_pattern),
                    model.otherserial.ilike(search_pattern),
                    model.Username.ilike(search_pattern)
                )
            )

        if status_filter == 'linked':
            query = query.filter(model.is_linked == True)
        elif status_filter == 'unlinked':
            query = query.filter(model.is_linked == False)

        if user_filter:
            query = query.filter(model.Username.ilike(f"%{user_filter}%"))

        # Ordonner par nom
        materials = query.order_by(model.name.asc()).all()

        # Créer le fichier CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # En-têtes du CSV
        headers = [
            'ID', 'Nom', 'Numéro de série', 'Numéro d\'inventaire',
            'Utilisateur', 'Statut', 'Date de création', 'Dernière modification',
            'Modifié par'
        ]
        writer.writerow(headers)

        # Données
        for material in materials:
            writer.writerow([
                material.id,
                material.name or '',
                material.serial or '',
                material.otherserial or '',
                material.Username or '',
                'Lié' if material.is_linked else 'Libre',
                material.date_create.strftime('%d/%m/%Y') if material.date_create else '',
                material.date_mod.strftime('%d/%m/%Y') if material.date_mod else '',
                material.app_management_user or ''
            ])

        # Préparer la réponse
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename={material_type}_export.csv'

        return response

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de l\'export : {str(e)}'
        }), 500


# ---- Fonctions génériques pour la gestion du matériel ----

def get_model_by_type(material_type):
    """
    Retourne le modèle en fonction du type de matériel
    """
    models = {
        'computers': Computers,
        'monitors': Monitors,
        'peripherals': Peripherals,
        'phones': Phones
    }
    return models.get(material_type)


@app.route('/material/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def material_list(material_type):
    """
    Affiche la liste du matériel en fonction du type
    """
    # Vérifier si le type de matériel est valide
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type de matériel '{material_type}' invalide.", 'danger')
        return redirect(url_for('dashboard'))

    # Récupérer tous les éléments non supprimés
    items = model.query.filter_by(is_delete=False).all()

    # Titre et description pour l'affichage
    titles = {
        'computers': 'Ordinateurs',
        'monitors': 'Moniteurs',
        'peripherals': 'Périphériques',
        'phones': 'Téléphones'
    }

    return render_template('material/list.html',
                           items=items,
                           material_type=material_type,
                           title=titles.get(material_type, 'Matériel'))


@app.route('/material/<material_type>/create', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def material_create(material_type):
    """
    Création d'un nouveau matériel en fonction du type
    """
    # Vérifier si le type de matériel est valide
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type de matériel '{material_type}' invalide.", 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            # Récupération des données du formulaire
            name = request.form.get('name')
            serial = request.form.get('serial')
            otherserial = request.form.get('otherserial')
            username = request.form.get('username')

            # Vérifier si le matériel existe déjà (par numéro de série)
            if serial:
                existing_item = model.query.filter_by(serial=serial, is_delete=False).first()
                if existing_item:
                    flash(f"Un matériel avec le numéro de série '{serial}' existe déjà.", 'warning')
                    return redirect(url_for('material_create', material_type=material_type))

            # Création du nouveau matériel
            new_item = model(
                name=name,
                serial=serial,
                otherserial=otherserial,
                Username=username,
                app_management_user=current_user.user
            )

            db.session.add(new_item)
            db.session.commit()

            flash(f"Le matériel '{name}' a été créé avec succès.", 'success')
            return redirect(url_for('material_list', material_type=material_type))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la création du matériel : {str(e)}", 'danger')
            return redirect(url_for('material_create', material_type=material_type))

    # Titres pour l'affichage
    titles = {
        'computers': 'Créer un ordinateur',
        'monitors': 'Créer un moniteur',
        'peripherals': 'Créer un périphérique',
        'phones': 'Créer un téléphone'
    }

    # GET : affichage du formulaire
    return render_template('material/create.html',
                           material_type=material_type,
                           title=titles.get(material_type, 'Créer un matériel'))


@app.route('/material/<material_type>/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def material_edit(material_type, item_id):
    """
    Modification d'un matériel en fonction du type
    """
    # Vérifier si le type de matériel est valide
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type de matériel '{material_type}' invalide.", 'danger')
        return redirect(url_for('dashboard'))

    # Récupérer l'élément à modifier
    item = model.query.get_or_404(item_id)

    # Vérifier si l'élément est dans la corbeille
    if item.is_delete:
        flash("Ce matériel est dans la corbeille et ne peut pas être modifié.", 'warning')
        return redirect(url_for('material_list', material_type=material_type))

    if request.method == 'POST':
        try:
            # Mise à jour des données
            item.name = request.form.get('name')
            item.serial = request.form.get('serial')
            item.otherserial = request.form.get('otherserial')
            item.Username = request.form.get('username')

            # Mettre à jour la date de modification et l'utilisateur qui a fait la modification
            item.date_mod = datetime.now(timezone.utc)
            item.app_management_user = current_user.user

            db.session.commit()

            flash(f"Le matériel '{item.name}' a été modifié avec succès.", 'success')
            return redirect(url_for('material_list', material_type=material_type))

        except Exception as e:
            db.session.rollback()
            flash(f"Erreur lors de la modification du matériel : {str(e)}", 'danger')
            return redirect(url_for('material_edit', material_type=material_type, item_id=item_id))

    # Titres pour l'affichage
    titles = {
        'computers': 'Modifier un ordinateur',
        'monitors': 'Modifier un moniteur',
        'peripherals': 'Modifier un périphérique',
        'phones': 'Modifier un téléphone'
    }

    # GET : affichage du formulaire pré-rempli
    return render_template('material/edit.html',
                           item=item,
                           material_type=material_type,
                           title=titles.get(material_type, 'Modifier un matériel'))


@app.route('/material/<material_type>/delete/<int:item_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def material_delete(material_type, item_id):
    """
    Placer un matériel dans la corbeille (soft delete)
    """
    # Vérifier si le type de matériel est valide
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type de matériel '{material_type}' invalide.", 'danger')
        return redirect(url_for('dashboard'))

    try:
        item = model.query.get_or_404(item_id)

        # Soft delete : mettre à jour les champs is_delete et date_delete
        item.is_delete = True
        item.date_delete = datetime.now(timezone.utc)
        item.app_management_user = current_user.user

        db.session.commit()

        flash(f"Le matériel '{item.name}' a été placé dans la corbeille.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors de la suppression du matériel : {str(e)}", 'danger')

    return redirect(url_for('material_list', material_type=material_type))


@app.route('/material/<material_type>/restore/<int:item_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def material_restore(material_type, item_id):
    """
    Restaurer un matériel depuis la corbeille
    """
    # Vérifier si le type de matériel est valide
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type de matériel '{material_type}' invalide.", 'danger')
        return redirect(url_for('dashboard'))

    try:
        item = model.query.get_or_404(item_id)

        # Restaurer l'élément
        item.is_delete = False
        item.date_delete = None
        item.app_management_user = current_user.user

        db.session.commit()

        flash(f"Le matériel '{item.name}' a été restauré.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors de la restauration du matériel : {str(e)}", 'danger')

    return redirect(url_for('material_trash', material_type=material_type))


@app.route('/material/<material_type>/trash')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def material_trash(material_type):
    """
    Affiche la liste du matériel dans la corbeille
    """
    # Vérifier si le type de matériel est valide
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type de matériel '{material_type}' invalide.", 'danger')
        return redirect(url_for('dashboard'))

    # Récupérer tous les éléments supprimés
    items = model.query.filter_by(is_delete=True).all()

    # Titres pour l'affichage
    titles = {
        'computers': 'Corbeille - Ordinateurs',
        'monitors': 'Corbeille - Moniteurs',
        'peripherals': 'Corbeille - Périphériques',
        'phones': 'Corbeille - Téléphones'
    }

    return render_template('material/trash.html',
                           items=items,
                           material_type=material_type,
                           title=titles.get(material_type, 'Corbeille - Matériel'))


@app.route('/material/<material_type>/purge/<int:item_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def material_purge(material_type, item_id):
    """
    Suppression définitive d'un matériel (hard delete)
    """
    # Vérifier si le type de matériel est valide
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type de matériel '{material_type}' invalide.", 'danger')
        return redirect(url_for('dashboard'))

    try:
        item = model.query.get_or_404(item_id)

        # Vérifier si l'élément est dans la corbeille
        if not item.is_delete:
            flash("Ce matériel n'est pas dans la corbeille et ne peut pas être supprimé définitivement.", 'warning')
            return redirect(url_for('material_list', material_type=material_type))

        # Supprimer les entrées de l'historique associées à ce matériel
        if material_type == 'computers':
            History.query.filter_by(computers_id=item_id).delete()
        elif material_type == 'monitors':
            History.query.filter_by(monitors_id=item_id).delete()
        elif material_type == 'peripherals':
            History.query.filter_by(peripherals_id=item_id).delete()
        elif material_type == 'phones':
            History.query.filter_by(phones_id=item_id).delete()

        # Suppression définitive
        db.session.delete(item)
        db.session.commit()

        flash(f"Le matériel a été supprimé définitivement.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors de la suppression définitive du matériel : {str(e)}", 'danger')

    return redirect(url_for('material_trash', material_type=material_type))


# Route API optimisée pour la recherche d'utilisateurs dans le workflow
@app.route('/api/workflow/search_users')
@login_required
@roles_required('gestionnaire')
def api_workflow_search_users():
    """
    API optimisée pour la recherche d'utilisateurs dans le workflow
    Limite les résultats à 10 maximum et recherche uniquement dans les champs pertinents
    """
    try:
        # Récupérer le terme de recherche depuis les paramètres GET
        search_term = request.args.get('q', '').strip()

        # Vérifier la longueur minimale
        if len(search_term) < 4:
            return jsonify({
                'status': 'success',
                'users': [],
                'message': 'Minimum 4 caractères requis'
            })

        # Recherche optimisée pour le workflow (uniquement dans GivenName, Surname, Username)
        search_pattern = f"%{search_term}%"

        users = Users.query.filter(
            Users.is_delete == False
        ).filter(
            # Rechercher uniquement dans les champs demandés
            db.or_(
                Users.GivenName.ilike(search_pattern),
                Users.Surname.ilike(search_pattern),
                Users.Username.ilike(search_pattern)
            )
        ).order_by(
            # Priorité : correspondance exacte dans Username, puis ordre alphabétique
            Users.Username.ilike(f"{search_term}%").desc(),
            Users.Surname.asc(),
            Users.GivenName.asc()
        ).limit(10).all()  # Limiter strictement à 10 résultats

        # Convertir les utilisateurs en format JSON
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'GivenName': user.GivenName or '',
                'Surname': user.Surname or '',
                'Username': user.Username or '',
                'Title': user.Title or '',
                'Department': user.Department or '',
                'Site': user.Site or ''
            })

        return jsonify({
            'status': 'success',
            'users': users_data,
            'count': len(users_data),
            'search_term': search_term
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la recherche : {str(e)}',
            'users': []
        }), 500


# Route API optimisée pour la recherche de matériel dans le workflow
@app.route('/api/workflow/search_materials')
@login_required
@roles_required('gestionnaire')
def api_workflow_search_materials():
    """
    API optimisée pour la recherche de matériel dans le workflow
    Limite les résultats à 10 maximum et recherche uniquement dans name, serial, otherserial
    """
    try:
        # Récupérer les paramètres de recherche
        material_type = request.args.get('material_type', '').strip()
        search_term = request.args.get('q', '').strip()

        # Vérifier que le type de matériel est valide
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Type de matériel invalide: {material_type}',
                'materials': []
            }), 400

        # Vérifier la longueur minimale
        if len(search_term) < 4:
            return jsonify({
                'status': 'success',
                'materials': [],
                'message': 'Minimum 4 caractères requis'
            })

        # Recherche optimisée pour le workflow (uniquement dans name, serial, otherserial)
        search_pattern = f"%{search_term}%"

        materials = model.query.filter(
            model.is_delete == False
        ).filter(
            # Rechercher uniquement dans les champs demandés
            db.or_(
                model.name.ilike(search_pattern),
                model.serial.ilike(search_pattern),
                model.otherserial.ilike(search_pattern)
            )
        ).order_by(
            # Priorité : correspondance exacte dans name, puis ordre alphabétique
            model.name.ilike(f"{search_term}%").desc(),
            model.name.asc()
        ).limit(10).all()  # Limiter strictement à 10 résultats

        # Convertir le matériel en format JSON
        materials_data = []
        for material in materials:
            materials_data.append({
                'id': material.id,
                'name': material.name or '',
                'serial': material.serial or '',
                'otherserial': material.otherserial or '',
                'Username': material.Username or '',
                'is_linked': material.is_linked or False
            })

        return jsonify({
            'status': 'success',
            'materials': materials_data,
            'count': len(materials_data),
            'search_term': search_term,
            'material_type': material_type
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la recherche : {str(e)}',
            'materials': []
        }), 500


# Route API pour récupérer le matériel lié à un utilisateur spécifique
@app.route('/api/workflow/user_linked_materials/<int:user_id>')
@login_required
@roles_required('gestionnaire')
def api_user_linked_materials(user_id):
    """
    API pour récupérer tout le matériel lié à un utilisateur spécifique
    Utilisée dans l'étape de déliance
    """
    try:
        # Vérifier que l'utilisateur existe
        user = Users.query.get_or_404(user_id)

        # Récupérer le type de matériel demandé
        material_type = request.args.get('material_type', '').strip()

        # Vérifier que le type de matériel est valide
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Type de matériel invalide: {material_type}',
                'materials': []
            }), 400

        # Rechercher le matériel lié à cet utilisateur
        materials = model.query.filter(
            model.is_delete == False,
            model.is_linked == True,
            model.Username == user.Username
        ).order_by(
            model.name.asc()
        ).all()

        # Convertir le matériel en format JSON
        materials_data = []
        for material in materials:
            materials_data.append({
                'id': material.id,
                'name': material.name or '',
                'serial': material.serial or '',
                'otherserial': material.otherserial or '',
                'Username': material.Username or '',
                'is_linked': material.is_linked or False,
                'date_mod': material.date_mod.isoformat() if material.date_mod else None
            })

        return jsonify({
            'status': 'success',
            'materials': materials_data,
            'count': len(materials_data),
            'user_id': user_id,
            'username': user.Username,
            'material_type': material_type
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Erreur lors de la récupération : {str(e)}',
            'materials': []
        }), 500




@app.route('/api/sync_tables', methods=['POST'])
@login_required
@roles_required('administrateur')
def sync_tables():
    """
    Route API pour synchroniser les données depuis les bases externes
    et exécuter les commandes SQL post-import si le fichier post.sql existe
    """
    try:
        # Importer le gestionnaire de synchronisation
        from sync_manager import SyncManager

        # Chemin vers le fichier bdd.json
        json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'bdd.json')

        # Créer et exécuter le gestionnaire de synchronisation
        sync_manager = SyncManager(json_path, current_user.user)
        results = sync_manager.run_sync()

        # Exécuter les commandes SQL post-import si le fichier post.sql existe
        post_sql_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'post.sql')

        if os.path.exists(post_sql_path):
            # Lire le fichier post.sql
            with open(post_sql_path, 'r', encoding='utf-8') as f:
                post_sql = f.read()

            # Exécuter les commandes SQL
            try:
                # Établir une connexion directe à la base de données
                connection = mysql.connector.connect(
                    host=Config.MYSQL_HOST,
                    user=Config.MYSQL_USER,
                    password=Config.MYSQL_PASSWORD,
                    database=Config.MYSQL_DB
                )

                cursor = connection.cursor()

                # Diviser le fichier en commandes SQL individuelles
                sql_commands = post_sql.split(';')
                executed_commands = 0

                for command in sql_commands:
                    # Ignorer les commandes vides
                    command = command.strip()
                    if command:
                        cursor.execute(command)
                        executed_commands += 1

                connection.commit()
                cursor.close()
                connection.close()

                results['post_sql'] = {
                    'status': 'success',
                    'message': f"Exécuté {executed_commands} commandes SQL post-import",
                    'commands': executed_commands
                }

            except Exception as e:
                results['post_sql'] = {
                    'status': 'error',
                    'message': f"Erreur lors de l'exécution des commandes SQL post-import: {str(e)}",
                    'commands': 0
                }
        else:
            results['post_sql'] = {
                'status': 'warning',
                'message': "Fichier post.sql non trouvé, aucune commande post-import exécutée",
                'commands': 0
            }

        return jsonify(results)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Erreur lors de la synchronisation: {str(e)}",
            'details': {}
        })


# Ajoutez ces fonctions de support

def sync_users(config, admin_user):
    """Synchronise les utilisateurs depuis la base externe"""
    try:
        # Configuration de la base externe
        ext_config = config['users']['connect']
        field_mappings = config['users']['fields']

        # Connexion à la base externe
        ext_conn = mysql.connector.connect(
            host=ext_config['host'],
            user=ext_config['user'],
            password=ext_config['password'],
            database=ext_config['db']
        )

        ext_cursor = ext_conn.cursor(dictionary=True)

        # Construction de la requête
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
                # Mise à jour
                user = existing_users[username]
                user.GivenName = ext_user.get('GivenName', user.GivenName)
                user.Surname = ext_user.get('Surname', user.Surname)
                user.Title = ext_user.get('Title', user.Title)
                user.Department = ext_user.get('Department', user.Department)
                user.Site = ext_user.get('Site', user.Site)
                user.date_mod = now
                user.app_management_user = admin_user
                updated += 1
            else:
                # Création
                new_user = Users(
                    GivenName=ext_user.get('GivenName', ''),
                    Surname=ext_user.get('Surname', ''),
                    Username=username,
                    Title=ext_user.get('Title', ''),
                    Department=ext_user.get('Department', ''),
                    Site=ext_user.get('Site', ''),
                    date_create=now,
                    date_mod=now,
                    app_management_user=admin_user
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
        raise Exception(f"Erreur lors de la synchronisation des utilisateurs: {str(e)}")


def sync_material(config, material_type, admin_user):
    """Synchronise le matériel spécifié depuis la base externe"""
    try:
        # Sélection du modèle approprié
        model_map = {
            'computers': Computers,
            'monitors': Monitors,
            'peripherals': Peripherals,
            'phones': Phones
        }

        if material_type not in model_map:
            return {'error': f"Type de matériel non reconnu: {material_type}"}

        model = model_map[material_type]

        # Configuration de la base externe
        ext_config = config[material_type]['connect']
        field_mappings = config[material_type]['fields']

        # Connexion à la base externe
        ext_conn = mysql.connector.connect(
            host=ext_config['host'],
            user=ext_config['user'],
            password=ext_config['password'],
            database=ext_config['db']
        )

        ext_cursor = ext_conn.cursor(dictionary=True)

        # Construction de la requête
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
                serial = f"AUTO_{material_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{created + updated}"

            if serial in existing_items:
                # Mise à jour
                item = existing_items[serial]
                item.name = ext_item.get('name')
                item.otherserial = ext_item.get('otherserial', item.otherserial)
                item.date_mod = now
                item.app_management_user = admin_user
                updated += 1
            else:
                # Création
                new_item = model(
                    name=ext_item.get('name'),
                    serial=serial,
                    otherserial=ext_item.get('otherserial', ''),
                    date_create=now,
                    date_mod=now,
                    app_management_user=admin_user
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
        raise Exception(f"Erreur lors de la synchronisation de {material_type}: {str(e)}")


@app.route('/api/import_tables', methods=['POST'])
@login_required
@roles_required('administrateur')
def import_tables():
    """
    Route API pour importer les données depuis les bases externes
    et exécuter les commandes SQL post-import si le fichier post.sql existe
    """
    try:
        # Importer le gestionnaire de synchronisation
        from sync_manager import SyncManager

        # Chemin vers le fichier bdd.json
        json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'bdd.json')

        # Créer et exécuter le gestionnaire de synchronisation
        sync_manager = SyncManager(json_path, current_user.user)
        results = sync_manager.run_sync()

        # Exécuter les commandes SQL post-import si le fichier post.sql existe
        post_sql_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'post.sql')

        if os.path.exists(post_sql_path):
            # Lire le fichier post.sql
            with open(post_sql_path, 'r', encoding='utf-8') as f:
                post_sql = f.read()

            # Exécuter les commandes SQL
            try:
                # Établir une connexion directe à la base de données
                connection = mysql.connector.connect(
                    host=app.config['MYSQL_HOST'],
                    user=app.config['MYSQL_USER'],
                    password=app.config['MYSQL_PASSWORD'],
                    database=app.config['MYSQL_DB']
                )

                cursor = connection.cursor()

                # Diviser le fichier en commandes SQL individuelles
                sql_commands = post_sql.split(';')
                executed_commands = 0

                for command in sql_commands:
                    # Ignorer les commandes vides
                    command = command.strip()
                    if command:
                        cursor.execute(command)
                        executed_commands += 1

                connection.commit()
                cursor.close()
                connection.close()

                results['post_sql'] = {
                    'status': 'success',
                    'message': f"Exécuté {executed_commands} commandes SQL post-import",
                    'commands': executed_commands
                }

            except Exception as e:
                results['post_sql'] = {
                    'status': 'error',
                    'message': f"Erreur lors de l'exécution des commandes SQL post-import: {str(e)}",
                    'commands': 0
                }
        else:
            results['post_sql'] = {
                'status': 'warning',
                'message': "Fichier post.sql non trouvé, aucune commande post-import exécutée",
                'commands': 0
            }

        return jsonify(results)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Erreur lors de l'importation: {str(e)}",
            'details': {}
        })


# Gestion des erreurs
@app.errorhandler(403)
def forbidden(e):
    """
    Gestion de l'erreur 403 - Accès non autorisé
    """
    return render_template('errors/403.html'), 403


# Point d'entrée de l'application
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)