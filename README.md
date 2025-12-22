# Investor Platform - Beeline Capital Advisors

A Django-based investor management platform with role-based access control.

## Technology Stack

- **Backend:** Django 5.1.1
- **Database:** SQLite (local), PostgreSQL/MySQL ready for production
- **Frontend:** Django Templates with Bootstrap 5
- **Authentication:** Custom User Model with role-based permissions

## Features

### User Roles
- **Admin:** Full system access
- **Partner:** Read/Write access to all investors and deals
- **Team Member:** Restricted access to assigned investors only

### Core Models
- **Investor:** Complete investor profile with KYC information
- **Deal:** Investment opportunities with workflow status
- **Commitment:** Links investors to deals with payment tracking
- **Document:** Generic document storage for investors and deals

## Setup Instructions

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Migrations**
   ```bash
   python manage.py migrate
   ```

3. **Create Superuser**
   ```bash
   python manage.py createsuperuser
   ```
   - Set role as 'admin' in the admin panel after creation

4. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

5. **Access the Platform**
   - Web Interface: http://127.0.0.1:8000/
   - Admin Panel: http://127.0.0.1:8000/admin/

## Database Configuration

For production, update `settings.py` to use PostgreSQL or MySQL:
- Uncomment the PostgreSQL/MySQL database configuration
- Install the appropriate database adapter (psycopg2 for PostgreSQL, mysqlclient for MySQL)

## Key Features Implemented

✅ Custom User Model with roles  
✅ Investor Management (CRUD)  
✅ Deal Management (CRUD)  
✅ Commitment/Interest Tracking  
✅ Document Management  
✅ Role-based Access Control  
✅ Bootstrap 5 UI  
✅ Responsive Design  
✅ Aadhaar masking for privacy  
✅ Family head relationship tracking  

