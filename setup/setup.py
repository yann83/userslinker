# setup/setup.py
"""
Complete configuration script for the Flask application
This script prepares the environment and creates the database with optimization.
"""
import subprocess
import sys
from pathlib import Path
import mysql.connector
from app import app, db, user_datastore
from flask_security import hash_password
from config import Config
from db_setup import create_database, AppManagement, Role


def install_requirements():
    """
    Installs all necessary dependencies from requirements.txt

    This function uses pip to automatically install all packages
    Python required to run the Flask application
    """
    print("Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    print("Dependencies successfully installed...")


def create_env_file():
    """
    Creates an .env file with the default configuration.

    The .env file contains sensitive environment variables such as:
    - Database connection parameters
    - Security keys
    - Debug parameters
    """
    env_file = Path('../.env')
    env_content = """# Database Configuration
        MYSQL_HOST=localhost
        MYSQL_USER=root
        MYSQL_PASSWORD=your_password_here
        MYSQL_DB=bd_userslinker
        
        # Security Keys (change these values in production)
        SECRET_KEY=dev-key-change-in-production
        SECURITY_PASSWORD_SALT=super-secret-random-salt
        
        # Debug Mode
        FLASK_DEBUG=1
        FLASK_ENV=development
        """

    # Check if the .env file already exists to avoid overwriting the configuration
    if not env_file.exists():
        with open('../.env', 'w') as f:
            f.write(env_content)
        print(".env file created. Don't forget to change the settings according to your configuration!")
    else:
        print("The .env file already exists.")


def create_mysql_database():
    """
    Creates the MySQL database if it doesn't exist.

    This function establishes a connection to the MySQL server and creates
    the 'bd_userslinker' database if it doesn't already exist.

    Returns:
    bool: True if the creation was successful, False otherwise.
    """
    try:
        # Connecting to MySQL server without specifying a database
        connection = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD
        )

        cursor = connection.cursor()

        # create the database if it does not exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {Config.MYSQL_DB}")
        print(f"✓ Database '{Config.MYSQL_DB}' created or already exists.")

        cursor.close()
        connection.close()

        return True

    except mysql.connector.Error as err:
        print(f"❌ Erreur MySQL: {err}")
        return False


def create_indexes():
    """
    Creates performance indexes to optimize searches

    This feature creates indexes on the most frequently used columns
    to improve the performance of search and filter queries
    """
    try:
        print("Creating indexes to optimize performance...")

        # Connection to the specific database
        connection = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB
        )

        cursor = connection.cursor()

        # List of SQL commands to create indexes
        index_commands = [
            # Index to optimize user searches
            "CREATE INDEX IF NOT EXISTS idx_users_search ON users (GivenName, Surname, Username)",

            # Index to optimize hardware searches
            "CREATE INDEX IF NOT EXISTS idx_computers_search ON computers (name, serial, otherserial)",
            "CREATE INDEX IF NOT EXISTS idx_monitors_search ON monitors (name, serial, otherserial)",
            "CREATE INDEX IF NOT EXISTS idx_peripherals_search ON peripherals (name, serial, otherserial)",
            "CREATE INDEX IF NOT EXISTS idx_phones_search ON phones (name, serial, otherserial)",

            # Index for user-related material queries
            "CREATE INDEX IF NOT EXISTS idx_computers_user ON computers (Username, is_linked, is_delete)",
            "CREATE INDEX IF NOT EXISTS idx_monitors_user ON monitors (Username, is_linked, is_delete)",
            "CREATE INDEX IF NOT EXISTS idx_peripherals_user ON peripherals (Username, is_linked, is_delete)",
            "CREATE INDEX IF NOT EXISTS idx_phones_user ON phones (Username, is_linked, is_delete)",

            # Index to optimize historical queries
            "CREATE INDEX IF NOT EXISTS idx_history_user ON history (users_id, date_mod)",
            "CREATE INDEX IF NOT EXISTS idx_history_date ON history (date_mod DESC)",

            # Index to optimize queries on non-deleted users
            "CREATE INDEX IF NOT EXISTS idx_users_active ON users (is_delete, Department)",

            # Index to optimize administration queries
            "CREATE INDEX IF NOT EXISTS idx_app_management_email ON app_management (email)"
        ]

        # Run each index creation command
        created_indexes = 0
        for command in index_commands:
            try:
                cursor.execute(command)
                created_indexes += 1
                print(f"✓ Index created: {command.split()[4]}") # Displays the name of the index
            except mysql.connector.Error as err:
                # If the index already exists, this is not a critical error
                if "Duplicate key name" in str(err):
                    print(f"- Index already exists: {command.split()[4]}")
                else:
                    print(f"⚠ Error creating index: {err}")

        # Validate all changes
        connection.commit()
        cursor.close()
        connection.close()

        print(f"✓ {created_indexes} indexes created successfully")
        return True

    except mysql.connector.Error as err:
        print(f"❌ Error creating indexes: {err}")
        return False


def create_test_users():
    """
    Creates test users with different roles to test the application.

    This function creates four test users:
    - An administrator to manage app users
    - A manager to create events
    - A reader to view data
    - A multi-role user to test permissions
    """
    # Use Flask context to access database
    with app.app_context():
        try:
            # Retrieve existing roles created by Flask-Security
            admin_role = Role.query.filter_by(name='administrateur').first()
            gestionnaire_role = Role.query.filter_by(name='gestionnaire').first()
            lecteur_role = Role.query.filter_by(name='lecteur').first()

            # Check that all roles exist
            if not all([admin_role, gestionnaire_role, lecteur_role]):
                print("❌ Error: Not all roles are available. Run db_setup.py first.")
                return

            # 1. Create a test administrator
            admin_exists = AppManagement.query.filter_by(email='admin.test@example.com').first()
            if not admin_exists:
                admin = user_datastore.create_user(
                    email='admin.test@example.com',
                    password=hash_password('admin123'),  # Mot de passe hashé pour la sécurité
                    GivenName='Admin',
                    Surname='Test',
                    user='admin_test'
                )
                user_datastore.add_role_to_user(admin, admin_role)
                print("✓ Test administrator created")
            else:
                print("- Test administrator created")

            # 2. Create a test manager
            gestionnaire_exists = AppManagement.query.filter_by(email='gestionnaire.test@example.com').first()
            if not gestionnaire_exists:
                gestionnaire = user_datastore.create_user(
                    email='gestionnaire.test@example.com',
                    password=hash_password('gestionnaire123'),
                    GivenName='Gestionnaire',
                    Surname='Test',
                    user='gestionnaire_test'
                )
                user_datastore.add_role_to_user(gestionnaire, gestionnaire_role)
                print("✓ Test manager created")
            else:
                print("- Test manager already exists")

            # 3. Create a test player
            lecteur_exists = AppManagement.query.filter_by(email='lecteur.test@example.com').first()
            if not lecteur_exists:
                lecteur = user_datastore.create_user(
                    email='lecteur.test@example.com',
                    password=hash_password('lecteur123'),
                    GivenName='Lecteur',
                    Surname='Test',
                    user='lecteur_test'
                )
                user_datastore.add_role_to_user(lecteur, lecteur_role)
                print("✓ test reader created")
            else:
                print("- Test reader already exists")

            # 4. Create a user with multiple roles to test permissions
            multi_exists = AppManagement.query.filter_by(email='multi.test@example.com').first()
            if not multi_exists:
                multi = user_datastore.create_user(
                    email='multi.test@example.com',
                    password=hash_password('multi123'),
                    GivenName='Multi',
                    Surname='Rôles',
                    user='multi_roles'
                )
                # Assign multiple roles to this user
                user_datastore.add_role_to_user(multi, gestionnaire_role)
                user_datastore.add_role_to_user(multi, lecteur_role)
                print("✓ Multi-role user created")
            else:
                print("- Multi-role user already exists")

            # Save all changes to the database
            db.session.commit()

            print("\n" + "=" * 50)
            print("Test users successfully created/verified !")
            print("=" * 50)
            print("\n🔐 Accounts available to log in :")
            print("1. Administrator : admin.test@example.com / admin123")
            print("2. Manager : gestionnaire.test@example.com / gestionnaire123")
            print("3. Reader : lecteur.test@example.com / lecteur123")
            print("4. Multi-roles : multi.test@example.com / multi123")
            print("\n💡 Use these accounts to test the different features")

        except Exception as e:
            print(f"❌ Error creating test users: {e}")
            # Undo changes if you make a mistake
            db.session.rollback()
            import traceback
            traceback.print_exc()


def create_sample_data():
    """
    Creates sample data to test the application

    This feature adds some sample users and hardware
    to allow immediate testing of features
    """
    with app.app_context():
        try:
            # Import the necessary models
            from db_setup import Users, Computers, Monitors, Peripherals, Phones
            from datetime import datetime, timezone

            print("Creation of sample data...")

            # Create some example users
            sample_users = [
                {
                    'GivenName': 'Jean',
                    'Surname': 'Dupont',
                    'Username': 'jdupont',
                    'Title': 'Développeur',
                    'Department': 'Informatique',
                    'Site': 'Paris'
                },
                {
                    'GivenName': 'Marie',
                    'Surname': 'Martin',
                    'Username': 'mmartin',
                    'Title': 'Chef de projet',
                    'Department': 'Informatique',
                    'Site': 'Lyon'
                },
                {
                    'GivenName': 'Pierre',
                    'Surname': 'Bernard',
                    'Username': 'pbernard',
                    'Title': 'Comptable',
                    'Department': 'Finance',
                    'Site': 'Paris'
                }
            ]

            created_users = 0
            now = datetime.now(timezone.utc)

            for user_data in sample_users:
                # Check if user already exists
                existing_user = Users.query.filter_by(Username=user_data['Username']).first()
                if not existing_user:
                    new_user = Users(
                        GivenName=user_data['GivenName'],
                        Surname=user_data['Surname'],
                        Username=user_data['Username'],
                        Title=user_data['Title'],
                        Department=user_data['Department'],
                        Site=user_data['Site'],
                        date_create=now,
                        date_mod=now,
                        app_management_user='system'
                    )
                    db.session.add(new_user)
                    created_users += 1

            # Create some sample materials
            sample_computers = [
                {'name': 'PC-DEV-001', 'serial': 'SN001234', 'otherserial': 'INV001'},
                {'name': 'PC-FINANCE-001', 'serial': 'SN001235', 'otherserial': 'INV002'},
                {'name': 'LAPTOP-MOBILE-001', 'serial': 'SN001236', 'otherserial': 'INV003'}
            ]

            sample_monitors = [
                {'name': 'DELL-24-001', 'serial': 'MON001234', 'otherserial': 'INV101'},
                {'name': 'HP-27-001', 'serial': 'MON001235', 'otherserial': 'INV102'}
            ]

            created_materials = 0

            # Create the example computers
            for comp_data in sample_computers:
                existing_comp = Computers.query.filter_by(serial=comp_data['serial']).first()
                if not existing_comp:
                    new_comp = Computers(
                        name=comp_data['name'],
                        serial=comp_data['serial'],
                        otherserial=comp_data['otherserial'],
                        date_create=now,
                        date_mod=now,
                        app_management_user='system'
                    )
                    db.session.add(new_comp)
                    created_materials += 1

            # Create the example monitors
            for mon_data in sample_monitors:
                existing_mon = Monitors.query.filter_by(serial=mon_data['serial']).first()
                if not existing_mon:
                    new_mon = Monitors(
                        name=mon_data['name'],
                        serial=mon_data['serial'],
                        otherserial=mon_data['otherserial'],
                        date_create=now,
                        date_mod=now,
                        app_management_user='system'
                    )
                    db.session.add(new_mon)
                    created_materials += 1

            # Save all sample data
            db.session.commit()

            if created_users > 0 or created_materials > 0:
                print(f"✓ Example data created: {created_users} users, {created_materials} materials")
            else:
                print("- Existing sample data")

        except Exception as e:
            print(f"❌ Error creating sample data: {e}")
            db.session.rollback()


def main():
    """
    Main function for fully configuring the application

    This function orchestrates all configuration steps:
    1. Installing dependencies
    2. Configuring the environment
    3. Creating the database
    4. Creating tables and indexes
    5. Creating test users
    6. Creating sample data
    """
    print("=" * 60)
    print("🚀 CONFIGURATION DE L'APPLICATION USERSLINKER")
    print("=" * 60)



    # Step 1: Install Python Dependencies
    print("\n📦 Step 1: Install Python Dependencies")
    try:
        install_requirements()
    except Exception as e:
        print(f"⚠ Error installing dependencies: {e}")
        print("Continue manually with: pip install -r requirements.txt")

    # Step 2: Create the configuration file
    print("\n⚙️ Step 2: Create the configuration file")
    create_env_file()

    # Ask user to check configuration
    print("\n" + "⚠️ " * 20)
    print("IMPORTANT: Check and modify the .env file with your settings")
    print("- MySQL password")
    print("- Security keys (in production)")
    print("⚠️ " * 20)

    while True:
        answer = input("\n✅ Have you modified the .env file? (y/n): ").lower().strip()
        if answer in ['y', 'yes']:
            break
        elif answer in ['n', 'no']:
            print("❌ Please edit the .env file before continuing")
            return
        else:
            print("Please answer with 'y' or 'n'")

    # Step 3: Create the MySQL database
    print("\n🗄️ Step 3: Create the MySQL database")
    if not create_mysql_database():
        print("❌ Unable to continue without database")
        return

    # Step 4: Create the tables via SQLAlchemy
    print("\n🏗️ Step 4: Create the tables via SQLAlchemy")
    try:
        create_database()  # This function is defined in db_setup.py
        print("✓ Tables created successfully")
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return

    # Step 5: Create indexes to optimize performance
    print("\n🔍 Step 5: Create indexes to optimize performance")
    if not create_indexes():
        print("⚠ Indexes could not be created, but the app will still work")

    # Step 6: Create the test users
    print("\n👤 Step 6: Create the test users")
    create_test_users()

    # Step 7: Create sample data
    print("\n📊 Step 7: Create sample data")
    create_sample_data()

    # Final success message
    print("\n" + "🎉" * 20)
    print("CONFIGURATION COMPLETED SUCCESSFULLY!")
    print("🎉" * 20)
    print("📋 Next steps:")
    print("1. Launch the application with: python app.py")
    print("2. Open your browser to: http://127.0.0.1:5000")
    print("3. Log in with one of the test accounts")
    print("4. (Optional) Configure bdd.json for external databases")
    print("🔧 Configuration files created:")
    print("- .env (environment settings)")
    print("- config/bdd.json (to configure for external databases)")
    print("✨ Your UsersLinker application is ready to use!")

if __name__ == "__main__":
    main()