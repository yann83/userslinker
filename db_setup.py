# db_setup.py
"""
SQLAlchemy model definitions and shared database instance for UsersLinker.

This module is a LIBRARY — it only declares models and exports the shared
``db`` object.  It does NOT create tables, seed data, or run any startup
logic on its own.

Table creation and first-run seeding are handled exclusively by the
installation wizard (install.py → /install/step2 and /install/step3).

Every model declares  __table_args__ = {'schema': 'app'}  so SQLAlchemy
always qualifies table names as  app.<table>  in every SQL statement,
regardless of the PostgreSQL search_path.  This is more reliable than
relying on a search_path option in the connection URI, especially on Windows
with psycopg2.

Foreign keys also use the fully-qualified form  'app.table_name'  for the
same reason.

Usage:
    from db_setup import db, Role, AppManagement, Users, Computers, ...

Location: db_setup.py  (root of the project, same folder as app.py)
"""

from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Shared SQLAlchemy instance.
# Created without being bound to a Flask app (application factory pattern).
# app.py calls db.init_app(app) to bind it at runtime.
# ---------------------------------------------------------------------------
db = SQLAlchemy()


# ===========================================================================
# Flask-Security join table
# ===========================================================================

# Many-to-many association between AppManagement users and Role.
# schema='app' and fully-qualified ForeignKey strings ensure the table lands
# in — and references — the correct schema.
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('app.app_management.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('app.role.id')),
    schema='app',
)


# ===========================================================================
# Model definitions
# ===========================================================================

class Role(db.Model, RoleMixin):
    """Application roles used by Flask-Security for access control.

    Attributes:
        id (int): Primary key.
        name (str): Unique role identifier — one of:
            ``administrateur``, ``gestionnaire``, ``lecteur``.
        description (str): Human-readable description shown in the UI.
    """

    __tablename__  = 'role'
    __table_args__ = {'schema': 'app'}

    id          = db.Column(db.Integer(), primary_key=True)
    name        = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))


class AppManagement(db.Model, UserMixin):
    """Accounts for people who operate the UsersLinker application.

    Used exclusively for application authentication via Flask-Security.
    Separate from the ``users`` table which holds the organisation's staff.

    Attributes:
        id (int): Primary key.
        GivenName (str): First name.
        Surname (str): Last name.
        user (str): Short username / login handle.
        email (str): Login identifier for Flask-Security.
        password (str): Bcrypt-hashed password managed by Flask-Security.
        active (bool): False disables the account without deleting it.
        confirmed_at (datetime): Unused — confirmations are disabled.
        fs_uniquifier (str): Unique token required by Flask-Security >= 4.
        roles (list[Role]): Roles assigned via the roles_users join table.
    """

    __tablename__  = 'app_management'
    __table_args__ = {'schema': 'app'}

    id            = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    GivenName     = db.Column(db.String(45))
    Surname       = db.Column(db.String(45))
    user          = db.Column(db.String(100))
    email         = db.Column(db.String(255), unique=True, nullable=False)
    password      = db.Column(db.String(255),              nullable=False)
    active        = db.Column(db.Boolean(),   default=True)
    confirmed_at  = db.Column(db.DateTime())
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    roles         = db.relationship(
        'Role',
        secondary=roles_users,
        backref=db.backref('users', lazy='dynamic'),
    )


class Users(db.Model):
    """Organisation staff directory — the people whose assets are tracked.

    Attributes:
        id (int): Primary key.
        GivenName (str): First name.
        Surname (str): Last name.
        Username (str): Login name / sAMAccountName — unique matching key
            when synchronising from an external LDAP/AD source.
        Title (str): Job title.
        Department (str): Department or business unit.
        Site (str): Office location (free text).
        date_create (datetime): Row creation timestamp (UTC).
        date_mod (datetime): Last modification timestamp (UTC).
        date_delete (datetime): Timestamp of soft-deletion.
        is_delete (bool): True when the row is in the trash bin.
        app_management_user (str): Operator username — denormalised for display.
    """

    __tablename__  = 'users'
    __table_args__ = {'schema': 'app'}

    id                  = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    GivenName           = db.Column(db.String(45))
    Surname             = db.Column(db.String(45))
    Username            = db.Column(db.String(100))
    Title               = db.Column(db.String(200))
    Department          = db.Column(db.String(45))
    Site                = db.Column(db.Text)
    date_create         = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod            = db.Column(
        db.DateTime,
        default=lambda:  datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    date_delete         = db.Column(db.DateTime)
    is_delete           = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class Computers(db.Model):
    """IT inventory — desktop and laptop computers.

    Attributes:
        id (int): Primary key.
        name (str): Asset name or hostname.
        serial (str): Manufacturer serial number — unique matching key on sync.
        otherserial (str): Secondary reference (asset tag, barcode…).
        Username (str): Staff member this asset is currently linked to.
        date_create / date_mod / date_delete (datetime): Lifecycle timestamps (UTC).
        is_delete (bool): True when the row is in the trash bin.
        is_linked (bool): True when the asset is assigned to a user.
        app_management_user (str): Operator who last modified this record.
    """

    __tablename__  = 'computers'
    __table_args__ = {'schema': 'app'}

    id                  = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    name                = db.Column(db.String(255))
    serial              = db.Column(db.String(255))
    otherserial         = db.Column(db.String(255))
    Username            = db.Column(db.String(255))
    date_create         = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod            = db.Column(
        db.DateTime,
        default=lambda:  datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    date_delete         = db.Column(db.DateTime)
    is_delete           = db.Column(db.Boolean, default=False)
    is_linked           = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class Monitors(db.Model):
    """IT inventory — monitors and screens.

    See Computers for full attribute descriptions (identical structure).
    """

    __tablename__  = 'monitors'
    __table_args__ = {'schema': 'app'}

    id                  = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    name                = db.Column(db.String(255))
    serial              = db.Column(db.String(255))
    otherserial         = db.Column(db.String(255))
    Username            = db.Column(db.String(255))
    date_create         = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod            = db.Column(
        db.DateTime,
        default=lambda:  datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    date_delete         = db.Column(db.DateTime)
    is_delete           = db.Column(db.Boolean, default=False)
    is_linked           = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class Peripherals(db.Model):
    """IT inventory — peripheral devices (keyboards, mice, docking stations…).

    See Computers for full attribute descriptions (identical structure).
    """

    __tablename__  = 'peripherals'
    __table_args__ = {'schema': 'app'}

    id                  = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    name                = db.Column(db.String(255))
    serial              = db.Column(db.String(255))
    otherserial         = db.Column(db.String(255))
    Username            = db.Column(db.String(255))
    date_create         = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod            = db.Column(
        db.DateTime,
        default=lambda:  datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    date_delete         = db.Column(db.DateTime)
    is_delete           = db.Column(db.Boolean, default=False)
    is_linked           = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class Phones(db.Model):
    """IT inventory — mobile phones and desk phones.

    See Computers for full attribute descriptions (identical structure).
    """

    __tablename__  = 'phones'
    __table_args__ = {'schema': 'app'}

    id                  = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    name                = db.Column(db.String(255))
    serial              = db.Column(db.String(255))
    otherserial         = db.Column(db.String(255))
    Username            = db.Column(db.String(255))
    date_create         = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    date_mod            = db.Column(
        db.DateTime,
        default=lambda:  datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    date_delete         = db.Column(db.DateTime)
    is_delete           = db.Column(db.Boolean, default=False)
    is_linked           = db.Column(db.Boolean, default=False)
    app_management_user = db.Column(db.String(100))


class History(db.Model):
    """Audit log — records every link and unlink event between users and assets.

    When a row is hard-deleted from users, computers, monitors, peripherals
    or phones, related History rows are removed automatically (CASCADE).
    When an AppManagement account is deleted the FK is set to NULL.

    Attributes:
        id (int): Primary key.
        app_management_id (int): FK → app.app_management — who performed the action.
        users_id (int): FK → app.users — which staff member was involved.
        computers_id / monitors_id / peripherals_id / phones_id (int):
            FK to the affected asset row (only one is set per event).
        date_mod (datetime): Event timestamp (UTC).
        is_linked (bool): True = link event; False = unlink event.
        is_delete (bool): True when the related asset has been soft-deleted.
        app_management_user (str): Username string for display (denormalised).
    """

    __tablename__  = 'history'
    __table_args__ = {'schema': 'app'}

    id                  = db.Column(db.Integer, primary_key=True, autoincrement=True)
    app_management_id   = db.Column(db.Integer, db.ForeignKey('app.app_management.id', ondelete='SET NULL'), nullable=True)
    users_id            = db.Column(db.Integer, db.ForeignKey('app.users.id',          ondelete='CASCADE'),  nullable=True)
    computers_id        = db.Column(db.Integer, db.ForeignKey('app.computers.id',      ondelete='CASCADE'),  nullable=True)
    monitors_id         = db.Column(db.Integer, db.ForeignKey('app.monitors.id',       ondelete='CASCADE'),  nullable=True)
    peripherals_id      = db.Column(db.Integer, db.ForeignKey('app.peripherals.id',    ondelete='CASCADE'),  nullable=True)
    phones_id           = db.Column(db.Integer, db.ForeignKey('app.phones.id',         ondelete='CASCADE'),  nullable=True)
    date_mod            = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_linked           = db.Column(db.Boolean,  default=False)
    is_delete           = db.Column(db.Boolean,  default=False)
    app_management_user = db.Column(db.String(100))