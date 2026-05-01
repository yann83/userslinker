# forms.py
"""
Flask-WTF forms for the applicationn
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SelectMultipleField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Optional, ValidationError
from db_setup import AppManagement


class UserForm(FlaskForm):
    """
    Form for creating and modifying users
    """
    given_name = StringField('Prénom', validators=[DataRequired(), Length(max=45)])
    surname = StringField('Nom', validators=[DataRequired(), Length(max=45)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    username = StringField("Nom d'utilisateur", validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Mot de passe', validators=[Optional(), Length(min=6)])
    active = BooleanField('Compte actif', default=True)
    role_ids = SelectMultipleField('Rôles', coerce=int)
    submit = SubmitField('Enregistrer')

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def validate_email(self, field):
        """
        Check that the email address is not already in use.
        """
        if self.user:
            # In edit mode, only check if the email has changed
            if field.data != self.user.email:
                existing = AppManagement.query.filter_by(email=field.data).first()
                if existing:
                    raise ValidationError('Cet email est déjà utilisé.')
        else:
            # In creation mode, check if the email exists.
            existing = AppManagement.query.filter_by(email=field.data).first()
            if existing:
                raise ValidationError('Cet email est déjà utilisé.')


class CreateUserForm(UserForm):
    """
    Specific form for creating users
    """
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=6)])