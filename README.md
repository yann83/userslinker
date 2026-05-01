# UsersLinker - Asset and User Management System

A comprehensive Flask-based web application for managing users and IT assets with role-based access control, external database integration, and comprehensive reporting capabilities.

A small gesture, a big support! Buy me a coffee ☕ if you appreciate my work. Thanks in advance!

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/yann83)

## 🚀 Features

### Role-Based Access Control
- **Administrator**: Manages user accounts, roles, and permissions
- **Manager**: Creates events, accesses reports, and edits materials/users
- **Reader**: Read-only access to reports and asset/user lists

### Asset Management
- Support for multiple asset types: computers, monitors, peripherals, and phones
- Link/unlink assets to users with full audit trail
- Soft delete with trash bin functionality
- Real-time conflict detection when assets are already assigned

### External Database Integration (Optional)
- Connect to external user directories (LDAP/AD)
- GLPI inventory system integration
- Auto-completion for user and asset creation
- Fallback to manual entry when external systems unavailable

### Event Management Workflow
- Step-by-step wizard for asset assignment/unassignment
- Visual conflict detection with current asset ownership
- Complete audit trail with timestamps and user tracking
- Bulk operations support

### Comprehensive Reporting
- Filter by department, name, date ranges
- Historical movement tracking
- PDF export with formatted data
- Visual analytics with pie charts for asset distribution
- Asset distribution by model, type, and department

### Modern UI/UX
- Bootstrap 5 responsive design
- FontAwesome icons
- Intuitive navigation
- Mobile-friendly interface

## 🛠️ Technology Stack

- **Backend**: Flask 2.x (Latest Stable)
- **Authentication**: Flask-Security
- **Database**: MySQL (bd_userslinker)
- **Frontend**: Bootstrap 5 + FontAwesome (Free)
- **Templates**: Jinja2
- **Charts**: JavaScript charting library for pie charts

## 📋 Prerequisites

- Python 3.8+
- MySQL 5.7+ or MariaDB 10.3+
- pip (Python package installer)
- Virtual environment (recommended)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/userslinker.git
cd userslinker
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Setup

In the  `setup` folder update this values

```
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_password_here
MYSQL_DB=bd_userslinker
``` 

Create a MySQL database named `bd_userslinker` and configure your connection settings.

```sql
CREATE DATABASE bd_userslinker;
```

### 5. Configure External Databases (Optional)

Create a `bdd.json` file in the root directory (outside web-accessible folder) with your external database configurations:

```json
{
  "users": {
    "connect": {
      "host": "your-ldap-server",
      "user": "username",
      "password": "password",
      "db": "database_name",
      "table": "users_table"
    },
    "fields": {
      "GivenName": "first_name",
      "Surname": "last_name",
      "Username": "username",
      "email": "email_address",
      "Title": "job_title",
      "Department": "department",
      "Site": "location"
    }
  },
  "computers": {
    "connect": {
      "host": "glpi-server",
      "user": "username",
      "password": "password",
      "db": "glpi_db",
      "table": "glpi_computers"
    },
    "fields": {
      "name": "name",
      "serial": "serial",
      "otherserial": "otherserial"
    }
  }
  // ... similar configuration for monitors, peripherals, phones
}
```

### 6. Initialize Database Tables

```bash
python manage.py db init
python manage.py db migrate
python manage.py db upgrade
```

### 7. Create Initial Administrator

```bash
python create_admin.py
```

### 8. Run the Application

```bash
# Development mode
export FLASK_ENV=development
python app.py

# Production mode
export FLASK_ENV=production
python app.py
```

The application will be available at `http://localhost:5000`

## 📊 Database Schema

### Core Tables

#### app_management
Stores application users and their roles
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `GivenName` (VARCHAR(45))
- `Surname` (VARCHAR(45))
- `user` (VARCHAR(100))
- `password` (VARCHAR(255))
- `email` (VARCHAR(255))
- `role` (VARCHAR(45))

#### users
Stores end-users who receive assets
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `GivenName` (VARCHAR(45))
- `Surname` (VARCHAR(45))
- `Username` (VARCHAR(100))
- `Title` (VARCHAR(200))
- `Department` (VARCHAR(45))
- `Site` (LONGTEXT)
- `date_create` (DATETIME)
- `date_mod` (DATETIME)
- `date_delete` (DATETIME)
- `is_delete` (TINYINT(1))
- `app_management_user` (VARCHAR(100))

#### Asset Tables (computers, monitors, peripherals, phones)
Each asset table contains:
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `name` (VARCHAR(255))
- `serial` (VARCHAR(255))
- `otherserial` (VARCHAR(255))
- `Username` (VARCHAR(255))
- `date_create` (DATETIME)
- `date_mod` (DATETIME)
- `date_delete` (DATETIME)
- `is_delete` (TINYINT(1))
- `is_linked` (TINYINT(1))
- `app_management_user` (VARCHAR(100))

#### history
Audit trail for all asset movements
- `id` (INT, PRIMARY KEY, AUTO_INCREMENT)
- `app_management_id` (INT)
- `users_id` (INT)
- `computers_id` (INT)
- `monitors_id` (INT)
- `peripherals_id` (INT)
- `phones_id` (INT)
- `date_mod` (DATETIME)
- `is_linked` (TINYINT(1))
- `is_delete` (TINYINT(1))
- `app_management_user` (VARCHAR(100))

## 💼 Usage

### First Login
1. Navigate to `http://localhost:5000`
2. Login with administrator credentials
3. The system will test external database connections (if configured)
4. Create additional users and assign roles

### Creating Events (Manager Role)
1. Go to "Create Event" from the main menu
2. Select or create a user
3. Choose to link or unlink assets
4. Follow the step-by-step wizard
5. Review and confirm changes

### Managing Assets and Users
1. Access "Lists" menu for asset/user management
2. Search, edit, add, or delete items
3. Use trash bin for soft deletes
4. Permanently delete items from trash when needed

### Generating Reports
1. Navigate to "Reports" section
2. Apply filters (department, date range, etc.)
3. View historical data and movements
4. Export to PDF or view charts
5. Analyze asset distribution patterns

## 🔧 Configuration

### Environment Variables

```bash
# Flask configuration
FLASK_ENV=development|production
SECRET_KEY=your-secret-key-here

# Database configuration
DATABASE_URL=mysql://username:password@host:port/bd_userslinker

# External database configuration path
EXTERNAL_DB_CONFIG=/path/to/bdd.json
```

### Security Considerations

- The `bdd.json` file contains sensitive database credentials and should never be accessible via web browser
- Use strong passwords for database connections
- Implement SSL/TLS in production
- Regular backup of the main database
- Monitor access logs for security issues

## 📈 Monitoring and Maintenance

### Health Checks
The application performs automatic health checks on:
- Main database connectivity
- External database connections (if configured)
- File system permissions

### Backup Strategy
- Regular MySQL database backups
- Configuration file backups
- Log file rotation and archival

### Performance Optimization
- Database indexing on frequently queried fields
- Connection pooling for external databases
- Caching for frequently accessed data

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add comprehensive comments for beginners
- Include unit tests for new features
- Update documentation for changes

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🗂️ Project Structure

```
userslinker/
├── app.py                 # Main application entry point
├── config.py             # Application configuration
├── requirements.txt      # Python dependencies
├── bdd.json             # External DB config (not in repo)
├── models/              # Database models
│   ├── __init__.py
│   ├── user.py          # User models
│   ├── asset.py         # Asset models
│   └── history.py       # History/audit models
├── views/               # Application routes
│   ├── __init__.py
│   ├── auth.py          # Authentication routes
│   ├── admin.py         # Admin functionality
│   ├── events.py        # Event management
│   ├── reports.py       # Reporting features
│   └── api.py           # API endpoints
├── templates/           # Jinja2 templates
│   ├── base.html
│   ├── auth/
│   ├── admin/
│   ├── events/
│   └── reports/
├── static/              # Static files
│   ├── css/
│   ├── js/
│   └── images/
├── utils/               # Utility functions
│   ├── __init__.py
│   ├── database.py      # DB helper functions
│   ├── external_db.py   # External DB integration
│   └── reporting.py     # Report generation
└── tests/               # Unit tests
    ├── __init__.py
    ├── test_models.py
    ├── test_views.py
    └── test_utils.py
```
### Manager Role

![public_map](./img/03.jpg)

The manager can access the following functions:

- Create an event: manage links between users and equipment
- Lists: view users and equipment
- Reports: generate reports and statistics

__Create an event__

![public_map](./img/04.jpg)

This is the most important function. You must follow the steps to assign (link) or retrieve (unlink) equipment for a given user.

__Lists__

![public_map](./img/05.jpg)

Allows you to view the equipment inventory and create, edit, or delete objects.

__Reports__

![public_map](./img/06.jpg)

1. Report by department: Generates a detailed report of users and their equipment by department.

- Filter by department (required)
- Filter by period (optional)
- Display of linked equipment
- History of movements

2. Report by user: Generates a detailed report for a specific user.

- Dynamic user search
- Complete history (all dates)
- Currently linked equipment
- Detailed statistics

3. Report by equipment type: Analysis of distribution and usage by equipment type.

![public_map](./img/07.jpg)

- Pie charts
- Detailed statistics
- Utilization rates
- Breakdown by department

4. Activity report: analysis of movements and activities over a given period.

- Activity timeline
- Statistics by manager
- Trend charts
- Detailed export

### Reader role

The reader can access the following functions:

- Lists: view users and equipment.
- Reports: generate reports and statistics.

The reader does not have editing rights to lists.

---

**Built with ❤️ using Flask, Bootstrap, and modern web technologies**