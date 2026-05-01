# users_import_export.py
"""
User import/export functions
"""

import csv
import io
from flask import send_file, flash
from db_setup import AppManagement, Role, db
from flask_security import hash_password


def export_users_csv():
    """
    Exports the user list in CSV format
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Headers
    writer.writerow(['Prénom', 'Nom', 'Email', 'Nom d\'utilisateur', 'Rôles', 'Statut'])

    # Datas
    users = AppManagement.query.all()
    for user in users:
        roles = ', '.join([role.name for role in user.roles])
        status = 'Actif' if user.active else 'Inactif'
        writer.writerow([
            user.GivenName,
            user.Surname,
            user.email,
            user.user,
            roles,
            status
        ])

    # Create the file to be downloaded
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='users_export.csv'
    )


def import_users_csv(file_stream):
    """
    Import users from a CSV file
    """
    try:
        csv_input = io.StringIO(file_stream.read().decode('utf-8'))
        reader = csv.DictReader(csv_input)

        imported_count = 0
        errors = []

        for row_num, row in enumerate(reader, start=2):  # Start at 2 because of header
            try:
                # Check if the user already exists
                existing_user = AppManagement.query.filter_by(email=row['Email']).first()
                if existing_user:
                    errors.append(f"Line {row_num}: he user with the email address {row['Email']} already exists")
                    continue

                # Generate a unique identifier required by Flask-Security
                import uuid
                fs_uniquifier = str(uuid.uuid4())

                # Create the new user
                new_user = AppManagement(
                    GivenName=row['Prénom'],
                    Surname=row['Nom'],
                    email=row['Email'],
                    user=row['Nom d\'utilisateur'],
                    password=hash_password('password123'),  # Default password
                    active=row.get('Statut', 'Actif') == 'Actif',
                    fs_uniquifier=fs_uniquifier  # Unique identifier required by Flask-Security
                )

                # Add the roles
                if row.get('Rôles'):
                    roles = [r.strip() for r in row['Rôles'].split(',')]
                    for role_name in roles:
                        role = Role.query.filter_by(name=role_name).first()
                        if role:
                            new_user.roles.append(role)

                db.session.add(new_user)
                imported_count += 1

            except KeyError as e:
                errors.append(f"Line {row_num}: Missing column {str(e)}")
            except Exception as e:
                errors.append(f"Line {row_num}: Error {str(e)}")

        db.session.commit()

        return imported_count, errors

    except Exception as e:
        db.session.rollback()
        return 0, [f"Global error: {str(e)}"]