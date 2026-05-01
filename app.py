# app.py
"""
Main Flask application — authentication, routes, and business logic.

Location: app.py  (root of the project)
"""

# ---------------------------------------------------------------------------
# load_dotenv() MUST be called first — before ANY import that reads
# os.environ (Config, SQLAlchemy URI, security keys…).
# If Config is imported before load_dotenv() runs, SECRET_KEY and
# SECURITY_PASSWORD_SALT fall back to their hardcoded defaults on every
# restart, which invalidates all sessions and makes stored passwords
# impossible to verify.
# ---------------------------------------------------------------------------
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify
from flask_security import Security, SQLAlchemySessionUserDatastore, login_required, current_user, \
    roles_accepted, roles_required, hash_password, verify_password
from flask_bootstrap import Bootstrap5
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_babel import Babel
from datetime import datetime, timezone
from sqlalchemy import text
from config import Config
from db_setup import db, Role, AppManagement, Users, History, Computers, Monitors, Peripherals, Phones
from users_import_export import export_users_csv, import_users_csv
import os
import re
import csv
import io

# Flask Initialization
app = Flask(__name__)

# Using centralized configuration
app.config.from_object(Config)

# Initializing extensions
db.init_app(app)
Bootstrap5(app)

# CSRF must be initialized before Flask-Security
csrf = CSRFProtect(app)

# Initializing babel for translations
babel = Babel(app)

# Configuration Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db.session, AppManagement, Role)
security = Security(app, user_datastore)

# ---------------------------------------------------------------------------
# Template definitions
# ---------------------------------------------------------------------------

# Columns filled automatically at import time — excluded from the template.
_AUTO_COLUMNS = {
    'date_create', 'date_mod', 'date_delete',
    'is_delete', 'is_linked', 'app_management_user'
}

_TEMPLATE_COLUMNS = {
    'computers': ['name', 'serial', 'otherserial'],
    'monitors': ['name', 'serial', 'otherserial'],
    'peripherals': ['name', 'serial', 'otherserial'],
    'phones': ['name', 'serial', 'otherserial'],
    'users': ['GivenName', 'Surname', 'Username', 'Title', 'Department', 'Site'],
}

# example row per table shown in the downloaded template
_TEMPLATE_EXAMPLES = {
    'computers': {
        'name': 'HP EliteBook 850',
        'serial': 'CND1234567',
        'otherserial': '12.2024.11.0001',
    },
    'monitors': {
        'name': 'Dell P2422H',
        'serial': 'CN-0T1234',
        'otherserial': 'MON.2024.0001',
    },
    'peripherals': {
        'name': 'Logitech MX Keys',
        'serial': 'KBD123456',
        'otherserial': 'PER.2024.0001',
    },
    'phones': {
        'name': 'Samsung Galaxy A54',
        'serial': 'R58N12345678',
        'otherserial': 'PHN.2024.0001',
    },
    'users': {
        'GivenName': 'Jean',
        'Surname': 'Dupont',
        'Username': 'DUPONT-001',
        'Title': 'Developpeur',
        'Department': 'DSI',
        'Site': 'Paris',
    },
}
# Adds csrf_token to Jinja2's global context
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)


_LOCK_FILE = os.path.join(os.path.dirname(__file__), 'installed.lock')

if not os.path.exists(_LOCK_FILE):
    # First run: register the installation wizard
    from install import install_bp

    app.register_blueprint(install_bp)


    @app.route('/')
    def index():
        """Redirect to the installation wizard on first run."""
        return redirect(url_for('install.step1'))


else:
    # Normal run: register the standard index route
    @app.route('/')
    def index():
        """Home page — redirect to dashboard or login."""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('security.login'))


# Homepage after login
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Main page after login - displays "Welcome"
    """
    # Retrieves the user's roles for display
    user_roles = [role.name for role in current_user.roles]
    return render_template('dashboard.html', user_roles=user_roles)


# User management page (administrator only)
@app.route('/admin/users')
@login_required
@roles_required('administrateur')
def admin_users():
    """
    User management page - Administrator only
    """
    users = AppManagement.query.all()
    return render_template('admin/users.html', users=users)


# Creating a new user
@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@roles_required('administrateur')
def create_user():
    """
    Creating a new user
    """
    if request.method == 'POST':
        try:
            # Retrieving form data
            email = request.form.get('email')
            password = request.form.get('password')
            given_name = request.form.get('given_name')
            surname = request.form.get('surname')
            username = request.form.get('username')
            role_id = request.form.get('role_id')

            # Checking if the user already exists
            existing_user = AppManagement.query.filter_by(email=email).first()
            if existing_user:
                flash('Cet email est déjà utilisé.', 'danger')
                return redirect(url_for('create_user'))

            # Creating the user with Flask-Security user_datastore
            # This method automatically handles the fs_uniquifier
            new_user = user_datastore.create_user(
                email=email,
                password=hash_password(password),
                GivenName=given_name,
                Surname=surname,
                user=username
            )

            # Role assignment
            if role_id:
                role = Role.query.get(role_id)
                if role:
                    user_datastore.add_role_to_user(new_user, role)

            db.session.commit()
            flash('User created successfully.', 'success')
            return redirect(url_for('admin_users'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during creation: {e}")
            flash('Error during creation please contact the administrator', 'danger')
            return redirect(url_for('create_user'))

    # GET : display form
    roles = Role.query.all()
    return render_template('admin/create_user.html', roles=roles)


# User modification
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('administrateur')
def edit_user(user_id):
    """
    Modifying an existing user
    """
    user = AppManagement.query.get_or_404(user_id)

    if request.method == 'POST':
        try:
            # Basic data update
            user.email = request.form.get('email')
            user.GivenName = request.form.get('given_name')
            user.Surname = request.form.get('surname')
            user.user = request.form.get('username')

            # Update password if provided
            new_password = request.form.get('password')
            if new_password:
                user.password = hash_password(new_password)

            # If the checkbox is not checked, it does not appear in request.form
            # We explicitly check for its presence
            user.active = 'active' in request.form

            # Update roles
            for role in user.roles:
                user_datastore.remove_role_from_user(user, role)

            # Add the newly selected roles
            role_ids = request.form.getlist('role_ids')
            for role_id in role_ids:
                role = Role.query.get(role_id)
                if role:
                    user_datastore.add_role_to_user(user, role)

            db.session.commit()

            # More informative feedback message
            status_text = "actif" if user.active else "inactif"
            flash(f'User modified successfully. Status : {status_text}', 'success')
            return redirect(url_for('admin_users'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during editing: {e}")
            flash('Error during editing : please contact the administrator', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

    # GET : display form
    roles = Role.query.all()
    return render_template('admin/edit_user.html', user=user, roles=roles)

# Delete an user
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@roles_required('administrateur')
def delete_user(user_id):
    """
    Delete an user
    """
    try:
        user = AppManagement.query.get_or_404(user_id)

        # Prevent the removal of the last administrator
        if 'administrateur' in [role.name for role in user.roles]:
            admin_count = AppManagement.query.join(AppManagement.roles).filter(Role.name == 'administrateur').count()
            if admin_count <= 1:
                flash('Unable to delete the last administrator.', 'danger')
                return redirect(url_for('admin_users'))

        # Preventing self-destruction
        if user.id == current_user.id:
            flash('You cannot delete your own account.', 'danger')
            return redirect(url_for('admin_users'))

        db.session.delete(user)
        db.session.commit()
        flash('User successfully deleted.', 'success')

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during deletion: {e}")
        flash('Error during deletion : please contact the administrator', 'danger')

    return redirect(url_for('admin_users'))


# Route to view user profile
@app.route('/profile')
@login_required
def user_profile():
    """
    User profile page
    Allows users to view their information and change their password
    """
    return render_template('profile.html')


# Instructions for changing your password
@app.route('/profile/change_password', methods=['POST'])
@login_required
def change_password():
    """
    Allows a user to change their own password.
    Requires knowledge of the old password for security reasons.
    """
    try:
        # Retrieving form data
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Data validation
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('user_profile'))

        # Check that the new password is long enough
        if len(new_password) < 6:
            flash('The new password must contain at least 6 characters.', 'danger')
            return redirect(url_for('user_profile'))

        # Verify that the new passwords match
        if new_password != confirm_password:
            flash('The new passwords do not match.', 'danger')
            return redirect(url_for('user_profile'))

        # Check the old password
        if not verify_password(current_password, current_user.password):
            flash('The current password is incorrect.', 'danger')
            return redirect(url_for('user_profile'))

        # Verify that the new password is different from the old one.
        if verify_password(new_password, current_user.password):
            flash('The new password must be different from the old one.', 'warning')
            return redirect(url_for('user_profile'))

        # Update password
        current_user.password = hash_password(new_password)
        db.session.commit()

        # Success message
        flash('Your password has been successfully changed. '
              'You will need to use this new password the next time you log in.',
              'success')

        # Security log (optional - to track password changes)
        app.logger.info(f'Password changed for user: {current_user.email} ({current_user.user})')

        return redirect(url_for('user_profile'))

    except Exception as e:
        # If there is an error, cancel the changes
        db.session.rollback()
        app.logger.error(f'Error changing password for user {current_user.email}: {str(e)}')
        flash('Error changing password', 'danger')
        return redirect(url_for('user_profile'))


# API route to check password strength
@app.route('/api/check_password_strength', methods=['POST'])
@login_required
def check_password_strength():
    """
    API for server-side password strength verification
    Can be used for additional validations
    """
    try:
        password = request.json.get('password', '')

        # Critères de validation
        criteria = {
            'length': len(password) >= 12,
            'lowercase': bool(re.search(r'[a-z]', password)),
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }

        # Calcul du score
        score = sum(criteria.values())

        # Détermination de la force
        if score < 2:
            strength = {'level': 'weak', 'message': 'Very low'}
        elif score < 3:
            strength = {'level': 'fair', 'message': 'Weak'}
        elif score < 4:
            strength = {'level': 'good', 'message': 'Correct'}
        else:
            strength = {'level': 'strong', 'message': 'Strong'}

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
    First step in the event creation workflow
    """
    return render_template('events/create.html')


@app.route('/events/select_user', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def select_user():
    """
    Step 1: Select a user to create an event
    Modified version to support dynamic search
    """
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')

        if not user_id:
            flash("Please select a user", 'warning')
            return redirect(url_for('select_user'))

        # Check if the user exists
        user = Users.query.get(user_id)
        if not user:
            flash("The selected user does not exist", 'danger')
            return redirect(url_for('select_user'))

        # Redirection based on the chosen action
        if action == 'link':
            return redirect(url_for('select_material_to_link', user_id=user_id))
        elif action == 'unlink':
            return redirect(url_for('select_material_to_unlink', user_id=user_id))
        else:
            flash("Invalid action", 'danger')
            return redirect(url_for('select_user'))

    # GET: Display the page with the new search interface
    # No need to load all users in advance
    return render_template('events/select_user.html')


# Modified the select_material_to_link route to support the new interface
@app.route('/events/select_material_to_link/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def select_material_to_link(user_id):
    """
    Step 2A: Select the hardware to link to the user
    Modified version to support dynamic search
    """
    # Retrieve the user
    user = Users.query.get_or_404(user_id)

    if request.method == 'POST':
        material_type = request.form.get('material_type')
        material_ids = request.form.getlist('material_ids')

        if not material_type or not material_ids:
            flash("Please select at least one item", 'warning')
            return redirect(url_for('select_material_to_link', user_id=user_id))

        # Validating IDs (ensuring they are valid integers)
        try:
            material_ids = [int(mid) for mid in material_ids]
        except ValueError:
            flash("IDs invalid equipment", 'danger')
            return redirect(url_for('select_material_to_link', user_id=user_id))

        # Link creation and history
        try:
            model = get_model_by_type(material_type)
            if not model:
                flash(f"Type of equipment '{material_type}' invalide.", 'danger')
                return redirect(url_for('select_material_to_link', user_id=user_id))

            linked_count = 0
            warnings = []

            for material_id in material_ids:
                material = model.query.get(material_id)
                if material:
                    # Check if the device is already linked to another user
                    if material.is_linked and material.Username and material.Username != user.Username:
                        warnings.append(f"The equipment '{material.name}' is already linked to {material.Username}")
                        continue

                    # Update the hardware
                    material.Username = user.Username
                    material.is_linked = True
                    material.date_mod = datetime.now(timezone.utc)
                    material.app_management_user = current_user.user

                    # Create an entry in the history
                    history_entry = History()
                    history_entry.app_management_id = current_user.id
                    history_entry.users_id = user.id
                    history_entry.is_linked = True
                    history_entry.app_management_user = current_user.user

                    # Add the hardware ID to the corresponding field
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

            # Feedback messages
            if linked_count > 0:
                flash(f"{linked_count} item(s) of material successfully linked to {user.GivenName} {user.Surname}",
                      'success')

            for warning in warnings:
                flash(warning, 'warning')

            return redirect(url_for('event_summary', user_id=user_id))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating the link: {e}")
            flash("Error creating the link : please contact the administrator", 'danger')
            return redirect(url_for('select_material_to_link', user_id=user_id))

    # GET : display the page with the new search interface
    return render_template('events/select_material_to_link.html', user=user)


@app.route('/events/select_material_to_unlink/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def select_material_to_unlink(user_id):
    """
    Step 2B: Select the material to unbind from the user
    Modified version to support dynamic search
    """
    # Retrieve the user
    user = Users.query.get_or_404(user_id)

    if request.method == 'POST':
        material_type = request.form.get('material_type')
        material_ids = request.form.getlist('material_ids')

        if not material_type or not material_ids:
            flash("Please select at least one item", 'warning')
            return redirect(url_for('select_material_to_unlink', user_id=user_id))

        # ID Validation
        try:
            material_ids = [int(mid) for mid in material_ids]
        except ValueError:
            flash("Invalid hardware IDs", 'danger')
            return redirect(url_for('select_material_to_unlink', user_id=user_id))

        # Removal of links and history
        try:
            model = get_model_by_type(material_type)
            if not model:
                flash(f"Type of equipment '{material_type}' invalid.", 'danger')
                return redirect(url_for('select_material_to_unlink', user_id=user_id))

            unlinked_count = 0
            warnings = []

            for material_id in material_ids:
                material = model.query.get(material_id)
                if material:
                    # Check if the hardware is correctly linked to this user
                    if not material.is_linked or material.Username != user.Username:
                        warnings.append(f"The hardware '{material.name}' is not linked to this user")
                        continue

                    # Update the hardware
                    material.Username = None
                    material.is_linked = False
                    material.date_mod = datetime.now(timezone.utc)
                    material.app_management_user = current_user.user

                    # Create a history entry
                    history_entry = History()
                    history_entry.app_management_id = current_user.id
                    history_entry.users_id = user.id
                    history_entry.is_linked = False
                    history_entry.app_management_user = current_user.user

                    # Add the hardware ID in the corresponding field
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

            # Feedback messages
            if unlinked_count > 0:
                flash(
                    f"{unlinked_count} successfully detached material element(s) {user.GivenName} {user.Surname}",
                    'success')

            for warning in warnings:
                flash(warning, 'warning')

            return redirect(url_for('event_summary', user_id=user_id))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting link: {e}")
            flash("Error deleting link : please contact the administrator", 'danger')
            return redirect(url_for('select_material_to_unlink', user_id=user_id))

    # GET : display the page with the new interface
    return render_template('events/select_material_to_unlink.html', user=user)


@app.route('/events/summary/<int:user_id>')
@login_required
@roles_required('gestionnaire')
def event_summary(user_id):
    """
    Step 3: Event Summary
    """
    # Retrieve the user
    user = Users.query.get_or_404(user_id)

    # Retrieve the material associated with this user
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

    # Retrieve recent history for this user
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
                           # Add the models so they can be used in the template
                           Computers=Computers,
                           Monitors=Monitors,
                           Peripherals=Peripherals,
                           Phones=Phones)


# Lists page (manager and reader)
@app.route('/lists')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def lists():
    """
    Lists page - Accessible to managers and readers
    """
    return render_template('lists.html')


# Reports page (manager and reader) - update
@app.route('/reports')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports():
    """
    Reports page - Accessible to managers and readers
    """
    return render_template('reports.html')


# New report by department
@app.route('/reports/by_service', methods=['GET', 'POST'])
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports_by_service():
    """
    Report on users and their equipment by department
    """
    # Retrieve all unique services (non-empty and non-deleted)
    services_query = db.session.query(Users.Department).filter(
        Users.is_delete == False,
        Users.Department.isnot(None),
        Users.Department != ''
    ).distinct().order_by(Users.Department.asc()).all()

    # Convert to a simple list
    services = [service[0] for service in services_query if service[0]]

    # Variables for the results
    selected_service = None
    date_from = None
    date_to = None
    users_data = []
    generation_date = datetime.now(timezone.utc)  # Always defined

    if request.method == 'POST':
        try:
            # Retrieve form parameters
            selected_service = request.form.get('service')
            date_from_str = request.form.get('date_from')
            date_to_str = request.form.get('date_to')

            # Service validation (required)
            if not selected_service:
                flash("Please select a service", 'warning')
                return render_template('reports/by_service.html',
                                       services=services)

            # Date conversion (optional)
            if date_from_str:
                try:
                    date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
                except ValueError:
                    flash("Incorrect date format for the start date", 'warning')
                    date_from = None

            if date_to_str:
                try:
                    date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
                    # Add 23:59:59 to include the whole day
                    date_to = date_to.replace(hour=23, minute=59, second=59)
                except ValueError:
                    flash("Incorrect date format for the end date", 'warning')
                    date_to = None

            # Validation of date consistency
            if date_from and date_to and date_from > date_to:
                flash("The start date cannot be later than the end date.", 'warning')
                return render_template('reports/by_service.html',
                                       services=services,
                                       selected_service=selected_service,
                                       date_from=date_from_str,
                                       date_to=date_to_str)

            # Retrieve users from the selected service
            users_in_service = Users.query.filter(
                Users.Department == selected_service,
                Users.is_delete == False
            ).order_by(Users.Surname.asc(), Users.GivenName.asc()).all()

            if not users_in_service:
                flash(f"No users found in the service '{selected_service}'", 'info')
                return render_template('reports/by_service.html',
                                       services=services,
                                       selected_service=selected_service,
                                       date_from=date_from_str,
                                       date_to=date_to_str)

            # For each user, retrieve their hardware and history
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

                # Retrieve user-related material
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

                # Retrieve history for this user
                history_query = History.query.filter(
                    History.users_id == user.id
                )

                # Apply date filters if specified
                if date_from:
                    history_query = history_query.filter(History.date_mod >= date_from)
                if date_to:
                    history_query = history_query.filter(History.date_mod <= date_to)

                # Sort by descending date (newest first)
                history_entries = history_query.order_by(History.date_mod.desc()).all()

                # Enrich the history with hardware information
                for entry in history_entries:
                    material_info = None
                    material_type = None

                    # Identify the type of equipment and retrieve its information
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

                    # Add the enriched entry to the history
                    user_data['history'].append({
                        'entry': entry,
                        'material_info': material_info,
                        'material_type': material_type
                    })

                users_data.append(user_data)

            # Success Message
            flash(f"Report generated for {len(users_data)} of the service '{selected_service}'", 'success')

        except Exception as e:
            # If an error occurs, display a message and return to the form
            app.logger.error(f"Error generating report: {e}")
            flash("Error generating report : please contact the administrator", 'danger')
            return render_template('reports/by_service.html',
                                   services=services)

    return render_template('reports/by_service.html',
                           services=services,
                           selected_service=selected_service,
                           date_from=date_from.strftime('%Y-%m-%d') if date_from else None,
                           date_to=date_to.strftime('%Y-%m-%d') if date_to else None,
                           users_data=users_data,
                           generation_date=generation_date)


# New report per user
@app.route('/reports/by_user', methods=['GET', 'POST'])
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports_by_user():
    """
    Detailed report for a specific user
    With dynamic search and complete history
    """
    # Variables for the results
    selected_user = None
    user_data = None
    generation_date = datetime.now(timezone.utc)

    if request.method == 'POST':
        try:
            # Retrieve the selected user ID
            user_id = request.form.get('user_id')

            # User validation (required)
            if not user_id:
                flash("Please select an user", 'warning')
                return render_template('reports/by_user.html',
                                       generation_date=generation_date)

            # Retrieve the selected user
            selected_user = Users.query.filter(
                Users.id == user_id,
                Users.is_delete == False
            ).first()

            if not selected_user:
                flash("The selected user does not exist or has been deleted", 'danger')
                return render_template('reports/by_user.html',
                                       generation_date=generation_date)

            # Build the complete user data
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

            # Retrieve ALL material linked to the (current) user
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

            # Count the total amount of related equipment
            total_materials = sum(len(materials) for materials in user_data['materials'].values())
            user_data['statistics']['total_materials'] = total_materials

            # Retrieve the ENTIRE history for this user (all dates)
            history_entries = History.query.filter(
                History.users_id == selected_user.id
            ).order_by(History.date_mod.desc()).all()

            user_data['statistics']['total_movements'] = len(history_entries)

            # Enrich the history with hardware information
            for entry in history_entries:
                material_info = None
                material_type = None
                material_icon = None

                # Identify the type of equipment and retrieve its information
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
                        'is_deleted': material.is_delete  # To know if the material has been removed since
                    }

                # Add the enriched entry to the history
                user_data['history'].append({
                    'entry': entry,
                    'material_info': material_info,
                    'material_type': material_type,
                    'material_icon': material_icon
                })

            # Calculate activity statistics
            if history_entries:
                user_data['statistics']['last_activity'] = history_entries[0].date_mod
                user_data['statistics']['first_activity'] = history_entries[-1].date_mod

            # Success Message
            flash(f"Report generated for {selected_user.GivenName} {selected_user.Surname}", 'success')

        except Exception as e:
            # If an error occurs, display a message and return to the form
            app.logger.error(f"Error generating report: {e}")
            flash("Error generating report : please contact the administrator", 'danger')
            return render_template('reports/by_user.html',
                                   generation_date=generation_date)

    return render_template('reports/by_user.html',
                           selected_user=selected_user,
                           user_data=user_data,
                           generation_date=generation_date)


# New report by equipment type
@app.route('/reports/by_material_type', methods=['GET', 'POST'])
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports_by_material_type():
    """
    Equipment type analysis report with graphs
    Analysis of distribution and usage by equipment type
    """
    # Variables for the results
    selected_material_type = None
    material_data = None
    generation_date = datetime.now(timezone.utc)

    # List of available equipment types
    material_types = {
        'computers': {'name': 'Ordinateurs', 'icon': 'fas fa-laptop', 'model': Computers},
        'monitors': {'name': 'Moniteurs', 'icon': 'fas fa-desktop', 'model': Monitors},
        'peripherals': {'name': 'Périphériques', 'icon': 'fas fa-keyboard', 'model': Peripherals},
        'phones': {'name': 'Téléphones', 'icon': 'fas fa-mobile-alt', 'model': Phones}
    }

    if request.method == 'POST':
        try:
            # Retrieve the selected material type
            selected_material_type = request.form.get('material_type')

            # Validation of equipment type (mandatory)
            if not selected_material_type or selected_material_type not in material_types:
                flash("Please select a valid material type", 'warning')
                return render_template('reports/by_material_type.html',
                                       material_types=material_types,
                                       generation_date=generation_date)

            # Retrieve the corresponding model
            model = material_types[selected_material_type]['model']
            material_name = material_types[selected_material_type]['name']

            # Build the complete hardware data
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

            # Overall Statistics
            total_items = model.query.filter_by(is_delete=False).count()
            linked_items = model.query.filter_by(is_delete=False, is_linked=True).count()
            unlinked_items = total_items - linked_items
            deleted_items = model.query.filter_by(is_delete=True).count()

            # Count unique users
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

            # Data for graph by status
            material_data['by_status'] = [
                {'label': 'Liés', 'value': linked_items, 'color': '#28a745'},
                {'label': 'Libres', 'value': unlinked_items, 'color': '#6c757d'},
                {'label': 'Supprimés', 'value': deleted_items, 'color': '#dc3545'}
            ]

            # Breakdown by department (for related equipment)
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

            # Colors for graphics by service
            service_colors = ['#007bff', '#28a745', '#ffc107', '#dc3545', '#17a2b8',
                              '#6f42c1', '#e83e8c', '#fd7e14', '#20c997', '#6c757d']

            material_data['by_service'] = []
            for i, (service, count) in enumerate(services_query):
                material_data['by_service'].append({
                    'label': service,
                    'value': count,
                    'color': service_colors[i % len(service_colors)]
                })

            # Top 10 users with the most hardware of this type
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

            # Recent movements (last 30)
            recent_movements_query = History.query.filter(
                getattr(History, f"{selected_material_type}_id").isnot(None)
            ).order_by(History.date_mod.desc()).limit(30).all()

            material_data['recent_movements'] = []
            for movement in recent_movements_query:
                # Retrieve the user
                user = Users.query.get(movement.users_id) if movement.users_id else None

                # Retrieve the equipment
                material_id = getattr(movement, f"{selected_material_type}_id")
                material_item = model.query.get(material_id) if material_id else None

                material_data['recent_movements'].append({
                    'date': movement.date_mod,
                    'action': 'Lié' if movement.is_linked else 'Délié',
                    'user': user,
                    'material': material_item,
                    'manager': movement.app_management_user
                })

            # Success Message
            flash(f"Report generated for {material_name.lower()}", 'success')

        except Exception as e:
            # En cas d'erreur, afficher un message et revenir au formulaire
            app.logger.error(f"Error generating report: {e}")
            flash("Error generating report : please contact the administrator", 'danger')
            return render_template('reports/by_material_type.html',
                                   material_types=material_types,
                                   generation_date=generation_date)

    return render_template('reports/by_material_type.html',
                           material_types=material_types,
                           selected_material_type=selected_material_type,
                           material_data=material_data,
                           generation_date=generation_date)


@app.route('/reports/activity', methods=['GET', 'POST'])
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def reports_activity():
    """
    Activity report with analysis of movements and activities over a given period
    Includes statistics by manager and trend charts
    """
    # Retrieve all unique handlers for the filter
    gestionnaires_query = db.session.query(History.app_management_user).filter(
        History.app_management_user.isnot(None),
        History.app_management_user != ''
    ).distinct().order_by(History.app_management_user.asc()).all()

    # Convert to a simple list
    gestionnaires = [gest[0] for gest in gestionnaires_query if gest[0]]

    # Variables for the results
    date_from = None
    date_to = None
    selected_gestionnaire = None
    action_filter = None
    activity_data = None
    generation_date = datetime.now(timezone.utc) # Always defined

    if request.method == 'POST':
        try:
            # Retrieve form parameters
            date_from_str = request.form.get('date_from')
            date_to_str = request.form.get('date_to')
            selected_gestionnaire = request.form.get('gestionnaire_filter')
            action_filter = request.form.get('action_filter')

            # Date validation (required)
            if not date_from_str or not date_to_str:
                flash("Start and end dates are mandatory.", 'warning')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       generation_date=generation_date)

            # Date Conversion
            try:
                date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
                date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
                # Ajouter 23:59:59 pour inclure toute la journée de fin
                date_to = date_to.replace(hour=23, minute=59, second=59)
            except ValueError:
                flash("Incorrect date format", 'warning')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       generation_date=generation_date)

            # Validation of date consistency
            if date_from > date_to:
                flash("The start date cannot be later than the end date.", 'warning')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       date_from=date_from_str,
                                       date_to=date_to_str,
                                       selected_gestionnaire=selected_gestionnaire,
                                       action_filter=action_filter,
                                       generation_date=generation_date)

            # Check that the period is not too long (max 1 year to avoid performance problems)
            date_diff = date_to - date_from
            if date_diff.days > 365:
                flash("The selected period cannot exceed 1 year", 'warning')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       date_from=date_from_str,
                                       date_to=date_to_str,
                                       selected_gestionnaire=selected_gestionnaire,
                                       action_filter=action_filter,
                                       generation_date=generation_date)

            # Building the main query for the history
            history_query = History.query.filter(
                History.date_mod >= date_from,
                History.date_mod <= date_to
            )

            # Apply the filter handler if specified
            if selected_gestionnaire:
                history_query = history_query.filter(
                    History.app_management_user == selected_gestionnaire
                )

            # Apply the action filter if specified
            if action_filter == 'link':
                history_query = history_query.filter(History.is_linked == True)
            elif action_filter == 'unlink':
                history_query = history_query.filter(History.is_linked == False)

            # Retrieve all activities for the period
            all_activities = history_query.order_by(History.date_mod.desc()).all()

            if not all_activities:
                flash("No activity found matching the selected criteria", 'info')
                return render_template('reports/activity.html',
                                       gestionnaires=gestionnaires,
                                       date_from=date_from_str,
                                       date_to=date_to_str,
                                       selected_gestionnaire=selected_gestionnaire,
                                       action_filter=action_filter,
                                       generation_date=generation_date)

            # Build activity data
            activity_data = build_activity_data(all_activities, date_from, date_to)

            # Success Message
            flash(f"Rapport d'activité généré : {len(all_activities)} activité(s) trouvée(s)", 'success')

        except Exception as e:
            # If an error occurs, display a message and return to the form
            app.logger.error(f"Error generating report : {e}")
            flash("Error generating report : please contact the administrator", 'danger')
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
    Builds structured data for the activity report

    Args:
        activities: List of History activities
        date_from: Start date
        date_to: End date

    Returns:
        dict: Structured data for the template
    """
    from collections import defaultdict, Counter
    import json

    # General Statistics
    total_activities = len(activities)
    total_links = sum(1 for activity in activities if activity.is_linked)
    total_unlinks = total_activities - total_links

    # Counter of unique users impacted
    unique_users = set()
    for activity in activities:
        if activity.users_id:
            unique_users.add(activity.users_id)

    # Data for graphs per day
    daily_data = defaultdict(lambda: {'total': 0, 'links': 0, 'unlinks': 0})

    # Browse all activities for daily statistics
    for activity in activities:
        date_key = activity.date_mod.strftime('%Y-%m-%d')
        daily_data[date_key]['total'] += 1
        if activity.is_linked:
            daily_data[date_key]['links'] += 1
        else:
            daily_data[date_key]['unlinks'] += 1

    # Create the complete list of dates (fill in the gaps)
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

    # Statistics by type of equipment
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

    # Statistics by manager
    manager_stats_raw = defaultdict(lambda: {'total': 0, 'links': 0, 'unlinks': 0})

    for activity in activities:
        manager = activity.app_management_user or 'Inconnu'
        manager_stats_raw[manager]['total'] += 1
        if activity.is_linked:
            manager_stats_raw[manager]['links'] += 1
        else:
            manager_stats_raw[manager]['unlinks'] += 1

    # Calculate the daily average for each manager
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

        # Data for the graph
        manager_chart_labels.append(manager)
        manager_chart_links.append(stats['links'])
        manager_chart_unlinks.append(stats['unlinks'])

    # Top users most impacted
    user_activity_count = defaultdict(lambda: {'total': 0, 'links': 0, 'unlinks': 0})

    for activity in activities:
        if activity.users_id:
            user_activity_count[activity.users_id]['total'] += 1
            if activity.is_linked:
                user_activity_count[activity.users_id]['links'] += 1
            else:
                user_activity_count[activity.users_id]['unlinks'] += 1

    # Retrieve information from the most active users
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

    # Enrich the 50 most recent activities with hardware and user information
    recent_activities = []
    for activity in activities[:50]:  # Limiter à 50 pour éviter la surcharge
        # Identify the type of equipment and retrieve its information
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

        # Retrieve user information
        user_info = None
        if activity.users_id:
            user = Users.query.get(activity.users_id)
            if user:
                user_info = {
                    'GivenName': user.GivenName,
                    'Surname': user.Surname,
                    'Username': user.Username
                }

        # Add the enriched activity
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

    # Structure all the data
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


# API for searching for users (specific to reports)
@app.route('/api/reports/search_users')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_reports_search_users():
    """
    API for searching users in reports
    Similar to the workflow but optimized for reports
    """
    try:
        # Retrieve the search term from the GET parameters
        search_term = request.args.get('q', '').strip()

        # Check the minimum length
        if len(search_term) < 4:
            return jsonify({
                'status': 'success',
                'users': [],
                'message': 'Minimum 4 characters required'
            })

        # Optimized search (only in GivenName, Surname, Username)
        search_pattern = f"%{search_term}%"

        users = Users.query.filter(
            Users.is_delete == False
        ).filter(
            # Search only in relevant fields
            db.or_(
                Users.GivenName.ilike(search_pattern),
                Users.Surname.ilike(search_pattern),
                Users.Username.ilike(search_pattern)
            )
        ).order_by(
            # Priority: exact match in Username, then alphabetical order
            Users.Username.ilike(f"{search_term}%").desc(),
            Users.Surname.asc(),
            Users.GivenName.asc()
        ).limit(10).all()  # Strictly limit to 10 results

        # Convert users to JSON format with enriched information
        users_data = []
        for user in users:
            # Quickly count the associated hardware for each user
            total_computers = Computers.query.filter_by(Username=user.Username, is_linked=True, is_delete=False).count()
            total_monitors = Monitors.query.filter_by(Username=user.Username, is_linked=True, is_delete=False).count()
            total_peripherals = Peripherals.query.filter_by(Username=user.Username, is_linked=True,
                                                            is_delete=False).count()
            total_phones = Phones.query.filter_by(Username=user.Username, is_linked=True, is_delete=False).count()
            total_materials = total_computers + total_monitors + total_peripherals + total_phones

            # Count the history
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


# API to get the list of services (for AJAX if necessary)
@app.route('/api/services')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_services():
    """
    API to retrieve the list of unique services
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
            'message': f'Error retrieving services : {str(e)}',
            'services': []
        }), 500


# User Statistics
@app.route('/admin/users/stats')
@login_required
@roles_required('administrateur')
def users_stats():
    """
    User statistics page
    """
    # Count the total number of users
    total_users = AppManagement.query.count()

    # Count by role
    admin_count = AppManagement.query.join(AppManagement.roles).filter(Role.name == 'administrateur').count()
    gestionnaire_count = AppManagement.query.join(AppManagement.roles).filter(Role.name == 'gestionnaire').count()
    lecteur_count = AppManagement.query.join(AppManagement.roles).filter(Role.name == 'lecteur').count()

    # Count active/inactive
    active_count = AppManagement.query.filter_by(active=True).count()
    inactive_count = AppManagement.query.filter_by(active=False).count()

    return render_template('admin/users_stats.html',
                           total_users=total_users,
                           admin_count=admin_count,
                           gestionnaire_count=gestionnaire_count,
                           lecteur_count=lecteur_count,
                           active_count=active_count,
                           inactive_count=inactive_count)


# User Export
@app.route('/admin/users/export')
@login_required
@roles_required('administrateur')
def export_users():
    """
    Exports the user list in CSV format
    """
    return export_users_csv()


# Importing users
@app.route('/admin/users/import', methods=['GET', 'POST'])
@login_required
@roles_required('administrateur')
def import_users():
    """
    Import users from a CSV file
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('import_users'))

        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('import_users'))

        if file and file.filename.endswith('.csv'):
            try:
                imported_count, errors = import_users_csv(file)

                if imported_count > 0:
                    flash(f'{imported_count} user(s) successfully imported', 'success')

                if errors:
                    for error in errors:
                        flash(error, 'warning')

                return redirect(url_for('admin_users'))

            except Exception as e:
                app.logger.error(f"Error during import: {e}")
                flash('Error during import : please contact the administrator', 'danger')
                return redirect(url_for('import_users'))
        else:
            flash('The file must be in CSV format', 'danger')
            return redirect(url_for('import_users'))

    # GET :display the form
    return render_template('admin/import_users.html')


# User management (users table)
@app.route('/users')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def users_list():
    """
    Displays a list of users in the organization, filtered by department.
    """
    # Retrieve the selected service from the GET settings
    selected_service = request.args.get('service', '').strip()

    # Build the basic query (users not deleted)
    query = Users.query.filter_by(is_delete=False)

    # Apply filter by service if selected
    if selected_service:
        query = query.filter(Users.Department == selected_service)

    # Retrieve filtered users
    users = query.order_by(Users.Surname.asc(), Users.GivenName.asc()).all()

    # Retrieve all unique services (non-empty and non-deleted) for the filter
    services_query = db.session.query(Users.Department).filter(
        Users.is_delete == False,
        Users.Department.isnot(None),
        Users.Department != ''
    ).distinct().order_by(Users.Department.asc()).all()

    # Convert to a simple list
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
    Creating a new user for the organization
    """
    if request.method == 'POST':
        try:
            # Retrieving form data
            given_name = request.form.get('given_name')
            surname = request.form.get('surname')
            username = request.form.get('username')
            title = request.form.get('title')
            department = request.form.get('department')
            site = request.form.get('site')

            # Checking if the user already exists
            existing_user = Users.query.filter_by(Username=username).first()
            if existing_user and not existing_user.is_delete:
                flash(f"The user {username} already exists.", 'warning')
                return redirect(url_for('user_create'))

            # Creating the new user
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

            flash(f"The user {given_name} {surname} was successfully created.", 'success')
            return redirect(url_for('users_list'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating user: {e}")
            flash("Error creating user : please contact the administrator", 'danger')
            return redirect(url_for('user_create'))

    # GET : display of the form
    return render_template('users/create.html')


@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def user_edit(user_id):
    """
    Modification of an organization user
    """
    user = Users.query.get_or_404(user_id)

    # Check if the user is in the trash.
    if user.is_delete:
        flash("This user is in the trash and cannot be modified..", 'warning')
        return redirect(url_for('users_list'))

    if request.method == 'POST':
        try:
            # Data update
            user.GivenName = request.form.get('given_name')
            user.Surname = request.form.get('surname')
            user.Username = request.form.get('username')
            user.Title = request.form.get('title')
            user.Department = request.form.get('department')
            user.Site = request.form.get('site')

            # Update the modification date and the user who made the change
            user.date_mod = datetime.now(timezone.utc)
            user.app_management_user = current_user.user

            db.session.commit()

            flash(f"The user {user.GivenName} {user.Surname} has been successfully modified.", 'success')
            return redirect(url_for('users_list'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error modifying user: {e}")
            flash("Error modifying user : please contact the administrator", 'danger')
            return redirect(url_for('user_edit', user_id=user_id))

    # GET : display of the pre-filled form
    return render_template('users/edit.html', user=user)


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def user_delete(user_id):
    """
    Place a user in the trash (soft delete)
    """
    try:
        user = Users.query.get_or_404(user_id)

        #Soft delete: update the is_delete and date_delete fields
        user.is_delete = True
        user.date_delete = datetime.now(timezone.utc)
        user.app_management_user = current_user.user

        db.session.commit()

        flash(f"The user {user.GivenName} {user.Surname} was placed in the bin.", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting user: {e}")
        flash("Error deleting user : please contact the administrator", 'danger')

    return redirect(url_for('users_list'))


@app.route('/users/restore/<int:user_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def user_restore(user_id):
    """
    Restore a user from the recycle bin
    """
    try:
        user = Users.query.get_or_404(user_id)

        # Restore user
        user.is_delete = False
        user.date_delete = None
        user.app_management_user = current_user.user

        db.session.commit()

        flash(f"The user {user.GivenName} {user.Surname} has been restored.", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error restoring user: {e}")
        flash("Error restoring user : please contact the administrator", 'danger')

    return redirect(url_for('users_trash'))


@app.route('/users/trash')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def users_trash():
    """
    Displays the list of users in the trash.
    """
    users = Users.query.filter_by(is_delete=True).all()
    return render_template('users/trash.html', users=users)


@app.route('/users/purge/<int:user_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def user_purge(user_id):
    """
    Permanent deletion of a user (hard delete)
    """
    try:
        user = Users.query.get_or_404(user_id)

        # Check if the user is in the trash.
        if not user.is_delete:
            flash("This user is not in the trash and cannot be permanently deleted..", 'warning')
            return redirect(url_for('users_list'))

        # Delete the history entries associated with this user
        History.query.filter_by(users_id=user_id).delete()

        # Permanent deletion
        db.session.delete(user)
        db.session.commit()

        flash(f"The user has been permanently removed.", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error  during permanent deletion of the user: {e}")
        flash("Error during permanent deletion of the user : please contact the administrator", 'danger')

    return redirect(url_for('users_trash'))


@app.route('/api/search_users')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_search_users():
    """
    API for searching users
    Returns a JSON list of users who match the criteria
    """
    try:
        # Retrieve the search term from the GET parameters
        search_term = request.args.get('q', '').strip()

        # If no search terms are found, return all users (limited).
        if not search_term:
            users = Users.query.filter_by(is_delete=False).limit(100).all()
        else:
            # Search across multiple fields using LIKE (case-insensitive)
            search_pattern = f"%{search_term}%"

            users = Users.query.filter(
                Users.is_delete == False
            ).filter(
                # Search in all relevant fields
                db.or_(
                    Users.GivenName.ilike(search_pattern),
                    Users.Surname.ilike(search_pattern),
                    Users.Username.ilike(search_pattern),
                    Users.Title.ilike(search_pattern),
                    Users.Department.ilike(search_pattern),
                    Users.Site.ilike(search_pattern)
                )
            ).order_by(
                # Sorted by relevance: first by last name/first name, then by department
                Users.Surname.asc(),
                Users.GivenName.asc()
            ).limit(500).all()  # Limit to 500 results to avoid overload

        # Convert users to JSON format
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
        # In case of an error, return a JSON error message
        return jsonify({
            'status': 'error',
            'message': f'Error during search : {str(e)}',
            'users': []
        }), 500


@app.route('/api/search_departments')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_search_departments():
    """
    API to retrieve the list of unique departments/services
    Used to populate the department filter
    """
    try:
        # Retrieve all unique, non-empty, and non-deleted departments
        departments_query = db.session.query(Users.Department).filter(
            Users.is_delete == False,
            Users.Department.isnot(None),
            Users.Department != ''
        ).distinct().order_by(Users.Department.asc()).all()

        # Extract the names of the departments
        departments = [dept[0] for dept in departments_query if dept[0]]

        return jsonify({
            'status': 'success',
            'departments': departments
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error retrieving departments : {str(e)}',
            'departments': []
        }), 500


# Alternative search route with advanced autocomplete
@app.route('/api/autocomplete_users')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_autocomplete_users():
    """
    Autocomplete API for users
    Returns suggestions based on the first few characters typed
    Optimized for quick responses
    """
    try:
        search_term = request.args.get('q', '').strip()
        limit = int(request.args.get('limit', 10))  # Limit suggestions

        if len(search_term) < 2:
            return jsonify({
                'status': 'success',
                'suggestions': []
            })

        search_pattern = f"{search_term}%"  # Search at the beginning of words

        # Search optimized for autocomplete
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

        # Format the suggestions
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


@app.route('/api/search_materials')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_search_materials():
    """
    API for searching for hardware by type
    Returns a JSON list of hardware that matches the criteria
    """
    try:
        # Retrieve search parameters
        material_type = request.args.get('material_type', '').strip()
        search_term = request.args.get('q', '').strip()

        # Verify that the equipment type is valid
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Invalid equipment type: {material_type}',
                'materials': []
            }), 400

        # If no search terms are found, return all material (limited).
        if not search_term:
            materials = model.query.filter_by(is_delete=False).limit(200).all()
        else:
            # Search across multiple fields using LIKE (case-insensitive)
            search_pattern = f"%{search_term}%"

            materials = model.query.filter(
                model.is_delete == False
            ).filter(
                # Search in all relevant fields
                db.or_(
                    model.name.ilike(search_pattern),
                    model.serial.ilike(search_pattern),
                    model.otherserial.ilike(search_pattern),
                    model.Username.ilike(search_pattern)
                )
            ).order_by(
                # Sorted by relevance: first by name, then by linked/unlinked status
                model.name.asc(),
                model.is_linked.desc()  # Materials linked first
            ).limit(500).all()  # Limit to 500 results

        # Convert the material to JSON format
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
        # In case of an error, return a JSON error message
        return jsonify({
            'status': 'error',
            'message': f'Error during search : {str(e)}',
            'materials': []
        }), 500


@app.route('/api/search_material_users/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_search_material_users(material_type):
    """
    API to retrieve the list of unique users associated with a hardware type
    Used to populate the user filter
    """
    try:
        # Verify that the equipment type is valid
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Invalid equipment type: {material_type}',
                'users': []
            }), 400

        # Retrieve all unique, non-empty, and non-deleted users
        users_query = db.session.query(model.Username).filter(
            model.is_delete == False,
            model.Username.isnot(None),
            model.Username != ''
        ).distinct().order_by(model.Username.asc()).all()

        # Extract user names
        users = [user[0] for user in users_query if user[0]]

        return jsonify({
            'status': 'success',
            'users': users,
            'material_type': material_type
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error retrieving users : {str(e)}',
            'users': []
        }), 500


@app.route('/api/material_statistics/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_material_statistics(material_type):
    """
    API to retrieve statistics for a type of hardware
    """
    try:
        # Verify that the equipment type is valid
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Invalid equipment type: {material_type}',
                'statistics': {}
            }), 400

        # Calculate the statistics
        total_count = model.query.filter_by(is_delete=False).count()
        linked_count = model.query.filter_by(is_delete=False, is_linked=True).count()
        unlinked_count = total_count - linked_count

        # Count unique users
        unique_users_query = db.session.query(model.Username).filter(
            model.is_delete == False,
            model.Username.isnot(None),
            model.Username != ''
        ).distinct().count()

        # Statistics per user (top 10)
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
            'message': f'Error in calculating statistics : {str(e)}',
            'statistics': {}
        }), 500


@app.route('/api/autocomplete_materials/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_autocomplete_materials(material_type):
    """
    Hardware autocomplete API
    Returns suggestions based on the first few characters typed
    Optimized for fast responses
    """
    try:
        # Verify that the equipment type is valid
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Invalid equipment type: {material_type}',
                'suggestions': []
            }), 400

        search_term = request.args.get('q', '').strip()
        limit = int(request.args.get('limit', 15))  # Limit suggestions

        if len(search_term) < 3:  # Minimum 3 characters for autocomplete
            return jsonify({
                'status': 'success',
                'suggestions': []
            })

        search_pattern = f"{search_term}%"  # Search at the beginning of words

        # Search optimized for autocomplete
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

        # Format suggestions
        suggestions_data = []
        for suggestion in suggestions:
            # Create a descriptive label
            label_parts = [suggestion.name or 'Without name']
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


# Route for advanced hardware search with multiple filters
@app.route('/api/advanced_search_materials/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_advanced_search_materials(material_type):
    """
    API for advanced hardware search with multiple filters
    Supported parameters:
    - q: search term
    - status: linked/unlinked
    - user: username
    - date_from: creation date from (YYYY-MM-DD)
    - date_to: creation date up to (YYYY-MM-DD)
    - sort_by: name/serial/date_mod/username
    - sort_order: asc/desc
    """
    try:
        # Verify that the equipment type is valid
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Invalid equipment type: {material_type}',
                'materials': []
            }), 400

        # Retrieve search parameters
        search_term = request.args.get('q', '').strip()
        status_filter = request.args.get('status', '').strip()
        user_filter = request.args.get('user', '').strip()
        date_from = request.args.get('date_from', '').strip()
        date_to = request.args.get('date_to', '').strip()
        sort_by = request.args.get('sort_by', 'name').strip()
        sort_order = request.args.get('sort_order', 'asc').strip()
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        # Build the basic query
        query = model.query.filter(model.is_delete == False)

        # Apply the text search filter
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

        # Apply the status filter
        if status_filter == 'linked':
            query = query.filter(model.is_linked == True)
        elif status_filter == 'unlinked':
            query = query.filter(model.is_linked == False)

        # Apply user filter
        if user_filter:
            query = query.filter(model.Username.ilike(f"%{user_filter}%"))

        # Apply date filters
        if date_from:
            try:
                from datetime import datetime
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(model.date_create >= date_from_obj)
            except ValueError:
                pass  # Ignore invalid dates

        if date_to:
            try:
                from datetime import datetime
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
                query = query.filter(model.date_create <= date_to_obj)
            except ValueError:
                pass  # Ignore invalid dates

        # Apply the sorting
        sort_column = getattr(model, sort_by, model.name)
        if sort_order.lower() == 'desc':
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())

        # Apply pagination
        materials = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )

        # Convert the results to JSON
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
            'message': f'Error during search avancée : {str(e)}',
            'materials': []
        }), 500


# Route for exporting hardware search results
@app.route('/api/export_materials/<material_type>')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def api_export_materials(material_type):
    """
    API for exporting hardware search results to CSV
    Uses the same parameters as the advanced search
    """
    try:
        import csv
        import io
        from flask import make_response

        # Verify that the equipment type is valid
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Invalid equipment type: {material_type}'
            }), 400

        # Retrieve search parameters (same as for advanced search)
        search_term = request.args.get('q', '').strip()
        status_filter = request.args.get('status', '').strip()
        user_filter = request.args.get('user', '').strip()

        # Build the query (without pagination for export)
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

        # Sort by name
        materials = query.order_by(model.name.asc()).all()

        # Create the CSV file
        output = io.StringIO()
        writer = csv.writer(output)

        # CSV Headers
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

        # Prepare the answer
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename={material_type}_export.csv'

        return response

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error during export : {str(e)}'
        }), 500


def get_model_by_type(material_type):
    """
    Returns the model based on the type of equipment
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
    Displays the list of equipment based on type
    """
    # Check if the equipment type is valid
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type of equipment '{material_type}' invalid.", 'danger')
        return redirect(url_for('dashboard'))

    # Recover all undeleted items
    items = model.query.filter_by(is_delete=False).all()

    # Title and description for display
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
    Creation of new equipment based on the type
    """
    # Check if the equipment type is valid
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type of equipment '{material_type}' invalid.", 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            # Retrieving form data
            name = request.form.get('name')
            serial = request.form.get('serial')
            otherserial = request.form.get('otherserial')
            username = request.form.get('username')

            # Check if the equipment already exists (by serial number)
            if serial:
                existing_item = model.query.filter_by(serial=serial, is_delete=False).first()
                if existing_item:
                    flash(f"A device with the serial number '{serial}' already exists.", 'warning')
                    return redirect(url_for('material_create', material_type=material_type))

            # Creation of the new equipment
            new_item = model(
                name=name,
                serial=serial,
                otherserial=otherserial,
                Username=username,
                app_management_user=current_user.user
            )

            db.session.add(new_item)
            db.session.commit()

            flash(f"The material '{name}' was successfully created.", 'success')
            return redirect(url_for('material_list', material_type=material_type))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating material: {e}")
            flash("Error creating material : please contact the administrator", 'danger')
            return redirect(url_for('material_create', material_type=material_type))

    # Titles for display
    titles = {
        'computers': 'Créer un ordinateur',
        'monitors': 'Créer un moniteur',
        'peripherals': 'Créer un périphérique',
        'phones': 'Créer un téléphone'
    }

    # GET: display of the form
    return render_template('material/create.html',
                           material_type=material_type,
                           title=titles.get(material_type, 'Créer un matériel'))


@app.route('/material/<material_type>/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
@roles_required('gestionnaire')
def material_edit(material_type, item_id):
    """
    Modification of equipment based on type
    """
    # Check if the equipment type is valid
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type of equipment '{material_type}' invalid.", 'danger')
        return redirect(url_for('dashboard'))

    # Retrieve the element to modify
    item = model.query.get_or_404(item_id)

    # Check if the item is in the trash
    if item.is_delete:
        flash("This material is in the trash and cannot be modified..", 'warning')
        return redirect(url_for('material_list', material_type=material_type))

    if request.method == 'POST':
        try:
            # Data update
            item.name = request.form.get('name')
            item.serial = request.form.get('serial')
            item.otherserial = request.form.get('otherserial')
            item.Username = request.form.get('username')

            # Update the modification date and the user who made the change
            item.date_mod = datetime.now(timezone.utc)
            item.app_management_user = current_user.user

            db.session.commit()

            flash(f"The item '{item.name}' has been successfully modified.", 'success')
            return redirect(url_for('material_list', material_type=material_type))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error  during item modification: {e}")
            flash("Error during item modification : please contact the administrator", 'danger')
            return redirect(url_for('material_edit', material_type=material_type, item_id=item_id))

    # Titles for display
    titles = {
        'computers': 'Modifier un ordinateur',
        'monitors': 'Modifier un moniteur',
        'peripherals': 'Modifier un périphérique',
        'phones': 'Modifier un téléphone'
    }

    # GET : display of the form pré-rempli
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
    # Check if the equipment type is valid
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type of equipment '{material_type}' invalid.", 'danger')
        return redirect(url_for('dashboard'))

    try:
        item = model.query.get_or_404(item_id)

        # Soft delete: update the is_delete and date_delete fields
        item.is_delete = True
        item.date_delete = datetime.now(timezone.utc)
        item.app_management_user = current_user.user

        db.session.commit()

        flash(f"The item '{item.name}' has been placed in the trashe.", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting material: {e}")
        flash("Error deleting material : please contact the administrator", 'danger')

    return redirect(url_for('material_list', material_type=material_type))


@app.route('/material/<material_type>/restore/<int:item_id>', methods=['POST'])
@login_required
@roles_required('gestionnaire')
def material_restore(material_type, item_id):
    """
    Restore equipment from the recycle bin
    """
    # Check if the equipment type is valid
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type of equipment '{material_type}' invalid.", 'danger')
        return redirect(url_for('dashboard'))

    try:
        item = model.query.get_or_404(item_id)

        # Restore the item
        item.is_delete = False
        item.date_delete = None
        item.app_management_user = current_user.user

        db.session.commit()

        flash(f"The item '{item.name}' has been restored.", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during item restoration: {e}")
        flash("Error during item restoration : please contact the administrator", 'danger')

    return redirect(url_for('material_trash', material_type=material_type))


@app.route('/material/<material_type>/trash')
@login_required
@roles_accepted('gestionnaire', 'lecteur')
def material_trash(material_type):
    """
    Displays the list of items in the bin
    """
    # Check if the equipment type is valid
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type of equipment '{material_type}' invalid.", 'danger')
        return redirect(url_for('dashboard'))

    # Recover all deleted items
    items = model.query.filter_by(is_delete=True).all()

    # Titles for display
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
    Permanent removal of a device (hard delete)
    """
    # Check if the equipment type is valid
    model = get_model_by_type(material_type)
    if not model:
        flash(f"Type of equipment '{material_type}' invalid.", 'danger')
        return redirect(url_for('dashboard'))

    try:
        item = model.query.get_or_404(item_id)

        # Check if the item is in the trash
        if not item.is_delete:
            flash("This material is not in the recycle bin and cannot be permanently deleted..", 'warning')
            return redirect(url_for('material_list', material_type=material_type))

        # Delete history entries associated with this hardware
        if material_type == 'computers':
            History.query.filter_by(computers_id=item_id).delete()
        elif material_type == 'monitors':
            History.query.filter_by(monitors_id=item_id).delete()
        elif material_type == 'peripherals':
            History.query.filter_by(peripherals_id=item_id).delete()
        elif material_type == 'phones':
            History.query.filter_by(phones_id=item_id).delete()

        # Permanent deletion
        db.session.delete(item)
        db.session.commit()

        flash(f"The item has been permanently removed.", 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error  during permanent deletion of the item: {e}")
        flash("Error during permanent deletion of the item : please contact the administrator", 'danger')

    return redirect(url_for('material_trash', material_type=material_type))


# Optimized API route for user search within the workflow
@app.route('/api/workflow/search_users')
@login_required
@roles_required('gestionnaire')
def api_workflow_search_users():
    """
    API optimized for searching users in the workflow.
    Limits results to a maximum of 10 and searches only within relevant fields.
    """
    try:
        # Retrieve the search term from the GET parameters
        search_term = request.args.get('q', '').strip()

        # Check the minimum length
        if len(search_term) < 4:
            return jsonify({
                'status': 'success',
                'users': [],
                'message': 'Minimum 4 characters required'
            })

        # Optimized search for workflow (only in GivenName, Surname, Username)
        search_pattern = f"%{search_term}%"

        users = Users.query.filter(
            Users.is_delete == False
        ).filter(
            # Search only in the requested fields
            db.or_(
                Users.GivenName.ilike(search_pattern),
                Users.Surname.ilike(search_pattern),
                Users.Username.ilike(search_pattern)
            )
        ).order_by(
            # Priority: exact match in Username, then alphabetical order
            Users.Username.ilike(f"{search_term}%").desc(),
            Users.Surname.asc(),
            Users.GivenName.asc()
        ).limit(10).all()  # Strictly limit to 10 results

        # Convert users to JSON format
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
            'message': f'Error during search : {str(e)}',
            'users': []
        }), 500


# Optimized API route for hardware search in the workflow
@app.route('/api/workflow/search_materials')
@login_required
@roles_required('gestionnaire')
def api_workflow_search_materials():
    """
    API optimized for hardware search within the workflow.
    Limits results to a maximum of 10 and searches only in name, serial, and other serial numbers.
    """
    try:
        # Retrieve search parameters
        material_type = request.args.get('material_type', '').strip()
        search_term = request.args.get('q', '').strip()

        # Verify that the equipment type is valid
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Invalid equipment type: {material_type}',
                'materials': []
            }), 400

        # Check the minimum length
        if len(search_term) < 4:
            return jsonify({
                'status': 'success',
                'materials': [],
                'message': 'Minimum 4 characters required'
            })

        # Optimized search for workflow (only in name, serial, otherserial)
        search_pattern = f"%{search_term}%"

        materials = model.query.filter(
            model.is_delete == False
        ).filter(
            # Search only in the requested fields
            db.or_(
                model.name.ilike(search_pattern),
                model.serial.ilike(search_pattern),
                model.otherserial.ilike(search_pattern)
            )
        ).order_by(
            # Priority: exact match in name, then alphabetical order
            model.name.ilike(f"{search_term}%").desc(),
            model.name.asc()
        ).limit(10).all()  # Strictly limit to 10 results

        # Convert the material to JSON format
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
            'message': f'Error during search : {str(e)}',
            'materials': []
        }), 500


# API route to retrieve hardware associated with a specific user
@app.route('/api/workflow/user_linked_materials/<int:user_id>')
@login_required
@roles_required('gestionnaire')
def api_user_linked_materials(user_id):
    """
    API to retrieve all material related to a specific user
    Used in the unlink step
    """
    try:
        # Verify that the user exists
        user = Users.query.get_or_404(user_id)

        # Retrieve the requested type of equipment
        material_type = request.args.get('material_type', '').strip()

        # Verify that the equipment type is valid
        model = get_model_by_type(material_type)
        if not model:
            return jsonify({
                'status': 'error',
                'message': f'Invalid equipment type: {material_type}',
                'materials': []
            }), 400

        # Search for material related to this user
        materials = model.query.filter(
            model.is_delete == False,
            model.is_linked == True,
            model.Username == user.Username
        ).order_by(
            model.name.asc()
        ).all()

        # Convert the material to JSON format
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
            'message': f'Error during retrieval : {str(e)}',
            'materials': []
        }), 500


def _quote(identifier, driver='mysql'):
    """
    Return a safely-quoted SQL identifier for the given driver.

    Args:
        identify (str): Column or table name to quote.
        driver (str): Database driver type. 'mysql' uses backticks,
        'postgresql' uses double-quotes. Defaults to 'mysql'.

    Returns:
        str: Quoted identifier string.

    Example:
        ('my_table', 'mysql')
        '`my_table`'
        ('my_table', 'postgresql')
        '"my_table"'
    """
    if driver == 'postgresql':
        return f'"{identifier}"'
    # Default: MySQL / MariaDB style
    return f'`{identifier}`'


@app.route('/api/import_tables', methods=['POST'])
@login_required
@roles_required('administrateur')
def import_tables():
    """
    API route to import data from external databases
    and execute post-import SQL commands if the post.sql file exists
    """
    try:
        # Import the synchronization manager
        from sync_manager import SyncManager

        # Path to the bdd.json file
        json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'bdd.json')

        # Path to the bdd.json file. Create and run the synchronization manager.
        sync_manager = SyncManager(json_path, current_user.user)
        results = sync_manager.run_sync()

        # Execute the post-import SQL commands if the post.sql file exists.
        post_sql_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'post.sql')

        if os.path.exists(post_sql_path):
            # Read the post.sql file
            with open(post_sql_path, 'r', encoding='utf-8') as f:
                post_sql = f.read()

            # Execute SQL commands
            try:
                # Split the SQL file into individual statements.
                # Each statement is separated by a semicolon.
                sql_commands = post_sql.split(';')
                executed_commands = 0

                # Use SQLAlchemy's engine so no separate MySQL connection
                # is needed — works with any database backend (PostgreSQL,
                # MySQL, SQLite…).
                with db.engine.connect() as conn:
                    for command in sql_commands:
                        # Skip empty statements (trailing semicolons, blank lines)
                        command = command.strip()
                        if command:
                            # text() tells SQLAlchemy this is a raw SQL string
                            conn.execute(text(command))
                            executed_commands += 1

                    # Commit all statements as a single transaction
                    conn.commit()

                results['post_sql'] = {
                    'status': 'success',
                    'message': f"Executed {executed_commands} post-import SQL commands",
                    'commands': executed_commands
                }

            except Exception as e:
                results['post_sql'] = {
                    'status': 'error',
                    'message': f"Error executing post-import SQL: {str(e)}",
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


@app.route('/api/csv/template/<string:table_type>')
@login_required
@roles_required('administrateur')
def csv_template_download(table_type):
    """
    Return a CSV template file for the requested table.

    The file contains one header row and one example data row.
    Auto-managed columns (date_create, date_mod, date_delete, is_delete,
    is_linked, app_management_user) and the Username link column for material
    tables are intentionally excluded — they are filled automatically on import.

    Args:
        table_type (str): One of computers | monitors | peripherals | phones | users.

    Returns:
        flask.Response: A CSV file as a download attachment, or 404 JSON if
        the table_type is not recognised.
    """
    if table_type not in _TEMPLATE_COLUMNS:
        return jsonify({'error': f'Unknown table type: {table_type}'}), 404

    columns = _TEMPLATE_COLUMNS[table_type]
    example = _TEMPLATE_EXAMPLES[table_type]

    # Build CSV content in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    writer.writerow({col: example.get(col, '') for col in columns})

    # utf-8-sig adds a BOM so Excel recognises the encoding automatically
    csv_bytes = io.BytesIO(output.getvalue().encode('utf-8-sig'))

    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'{table_type}_template.csv'
    )


@app.route('/api/csv/import', methods=['POST'])
@login_required
@roles_required('administrateur')
def csv_import():
    """
    Import rows from a user-supplied CSV file into the target table.

    Behaviour:
      - Existing rows are never modified (non-destructive import).
      - The whole file is scanned for duplicates BEFORE any insertion.
        If at least one duplicate is found the entire import is aborted
        and the offending rows are returned to the caller.
        Duplicate key:
          - material tables (computers / monitors / peripherals / phones): ``serial``
          - users table: ``Username``
      - Columns filled automatically (must NOT appear in the CSV):
          date_create         → current UTC datetime
          date_mod            → current UTC datetime
          date_delete         → NULL
          is_delete           → False
          is_linked           → False  (material tables only)
          app_management_user → current logged-in operator's ``user`` field
          Username            → NULL / empty  (material tables — set via events)

    Expected multipart/form-data fields:
        table_type (str):  One of computers | monitors | peripherals | phones | users.
        csv_file   (file): The CSV file to import.

    Returns:
        flask.Response: JSON object with keys:
            success    (bool)
            message    (str)
            imported   (int)   — rows inserted (0 on failure)
            duplicates (list)  — list of duplicate row dicts (empty on success)
    """
    # Validate inputs
    table_type = request.form.get('table_type', '').strip().lower()
    if table_type not in _TEMPLATE_COLUMNS:
        return jsonify({
            'success': False,
            'message': f"Type de table inconnu : '{table_type}'.",
            'imported': 0,
            'duplicates': []
        }), 400

    if 'csv_file' not in request.files:
        return jsonify({
            'success': False,
            'message': 'Aucun fichier fourni.',
            'imported': 0,
            'duplicates': []
        }), 400

    file = request.files['csv_file']
    if not file.filename or not file.filename.lower().endswith('.csv'):
        return jsonify({
            'success': False,
            'message': "Le fichier doit avoir l'extension .csv.",
            'imported': 0,
            'duplicates': []
        }), 400

    # Parse the CSV
    try:
        # utf-8-sig handles the optional BOM that Excel adds when saving as CSV
        content = file.read().decode('utf-8-sig')
        reader  = csv.DictReader(io.StringIO(content))
        rows    = list(reader)
    except Exception as exc:
        return jsonify({
            'success': False,
            'message': f'Impossible de lire le fichier CSV : {exc}',
            'imported': 0,
            'duplicates': []
        }), 400

    if not rows:
        return jsonify({
            'success': False,
            'message': 'Le fichier CSV est vide ou ne contient que les en-têtes.',
            'imported': 0,
            'duplicates': []
        }), 400

    #  Map table type to its SQLAlchemy model
    model_map = {
        'computers':   Computers,
        'monitors':    Monitors,
        'peripherals': Peripherals,
        'phones':      Phones,
        'users':       Users,
    }
    Model = model_map[table_type]

    # Duplicate check
    # Choose the uniqueness field depending on the target table
    unique_field = 'Username' if table_type == 'users' else 'serial'

    # Collect non-empty key values from the CSV rows
    csv_keys = [
        row.get(unique_field, '').strip()
        for row in rows
        if row.get(unique_field, '').strip()
    ]

    duplicates = []

    if csv_keys:
        try:
            existing_records = db.session.query(
                getattr(Model, unique_field)
            ).filter(
                getattr(Model, unique_field).in_(csv_keys)
            ).all()
            existing_values = {rec[0] for rec in existing_records}
        except Exception as exc:
            return jsonify({
                'success': False,
                'message': f'Error checking for duplicates : {exc}',
                'imported': 0,
                'duplicates': []
            }), 500

        # Collect every row whose key already exists in the database
        for row in rows:
            key_value = row.get(unique_field, '').strip()
            if key_value and key_value in existing_values:
                duplicates.append(dict(row))

    if duplicates:
        return jsonify({
            'success': False,
            'message': (
                f"{len(duplicates)} duplicate(s) detected in the field "
                f"« {unique_field} ». No lines imported."
            ),
            'imported': 0,
            'duplicates': duplicates
        })

    #  Insert rows
    now        = datetime.now(timezone.utc)
    admin_user = current_user.user   # short login name of the logged-in admin

    inserted = 0
    try:
        for row in rows:
            # Strip leading/trailing whitespace from every string value
            clean = {
                k: (v.strip() if isinstance(v, str) else v)
                for k, v in row.items()
            }

            if table_type == 'users':
                obj = Users(
                    GivenName=clean.get('GivenName', ''),
                    Surname=clean.get('Surname', ''),
                    Username=clean.get('Username', ''),
                    Title=clean.get('Title', ''),
                    Department=clean.get('Department', ''),
                    Site=clean.get('Site', ''),
                    # Auto-managed columns
                    date_create=now,
                    date_mod=now,
                    date_delete=None,
                    is_delete=False,
                    app_management_user=admin_user,
                )
            else:
                # Material tables: name / serial / otherserial from CSV.
                # Username (staff link) is left NULL — assigned via events.
                obj = Model(
                    name=clean.get('name', ''),
                    serial=clean.get('serial', ''),
                    otherserial=clean.get('otherserial', ''),
                    Username=None,          # set later through link events
                    # Auto-managed columns
                    date_create=now,
                    date_mod=now,
                    date_delete=None,
                    is_delete=False,
                    is_linked=False,
                    app_management_user=admin_user,
                )

            db.session.add(obj)
            inserted += 1

        db.session.commit()

    except Exception as exc:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f"Error during database insertion : {exc}",
            'imported': 0,
            'duplicates': []
        }), 500

    return jsonify({
        'success': True,
        'message': f'{inserted} line(s) successfully imported.',
        'imported': inserted,
        'duplicates': []
    })


# Error handling
@app.errorhandler(403)
def forbidden(e):
    """
    Handling error 403 - Unauthorized access
    """
    return render_template('errors/403.html'), 403


# Application entry point for local testing
if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)

# Application entry point for production
"""
if __name__ == '__main__':
    from waitress import serve
    serve(app, host='0.0.0.0', port=8000, threads=4)
"""
