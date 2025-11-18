# PostgreSQL Database Setup

This guide walks you through setting up PostgreSQL 16 for local development.

## Prerequisites

- macOS with Homebrew installed
- Python 3.11+ with virtual environment

## Installation Steps

### 1. Install PostgreSQL 16

```bash
# Install PostgreSQL 16 via Homebrew
brew install postgresql@16

# Start the PostgreSQL service
brew services start postgresql@16

# Verify installation
/opt/homebrew/opt/postgresql@16/bin/psql --version
# Expected output: psql (PostgreSQL) 16.x
```

### 2. Create Database and User

```bash
# Create the database
/opt/homebrew/opt/postgresql@16/bin/createdb django_auth_db

# Create a user with password
/opt/homebrew/opt/postgresql@16/bin/psql -d postgres -c "CREATE USER django_user WITH PASSWORD 'django_pass';"

# Grant database privileges
/opt/homebrew/opt/postgresql@16/bin/psql -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE django_auth_db TO django_user;"

# Grant schema privileges (required for PostgreSQL 15+)
/opt/homebrew/opt/postgresql@16/bin/psql -d django_auth_db -c "GRANT ALL ON SCHEMA public TO django_user;"
```

### 3. Configure Environment Variables

Add the following to your `.env` file:

```bash
# PostgreSQL Database Configuration
DATABASE_URL=postgres://django_user:django_pass@localhost:5432/django_auth_db
```

### 4. Install Python Dependencies

```bash
# Activate your virtual environment
source venv/bin/activate

# Install requirements (includes psycopg and dj-database-url)
pip install -r requirements.txt
```

### 5. Run Migrations

```bash
python manage.py migrate --settings=config.settings.development
```

### 6. Verify Connection

```bash
python -c "
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
import django
django.setup()
from django.db import connection
cursor = connection.cursor()
cursor.execute('SELECT version();')
print('PostgreSQL Version:', cursor.fetchone()[0])
"
```

## Database Configuration Strategy

The project uses different database configurations for each environment:

| Environment | Settings File | Database | Behavior |
|-------------|---------------|----------|----------|
| Development | `development.py` | PostgreSQL | Uses `DATABASE_URL` from `.env`, falls back to SQLite |
| Production | `production.py` | PostgreSQL | Requires `DATABASE_URL`, no fallback |
| Testing | `testing.py` | SQLite | In-memory database for fast tests |

## Key Dependencies

- **psycopg[binary]** - PostgreSQL adapter for Python (v3.x with binary support)
- **dj-database-url** - Parse database URLs from environment variables
- **python-dotenv** - Load environment variables from `.env` file

## Common Tasks

### Start/Stop PostgreSQL Service

```bash
# Start
brew services start postgresql@16

# Stop
brew services stop postgresql@16

# Restart
brew services restart postgresql@16

# Check status
brew services list
```

### Connect to Database Shell

```bash
# Using psql directly
/opt/homebrew/opt/postgresql@16/bin/psql django_auth_db

# Using Django's dbshell
python manage.py dbshell --settings=config.settings.development
```

### View Database Tables

```bash
/opt/homebrew/opt/postgresql@16/bin/psql django_auth_db -c "\dt"
```

### Add PostgreSQL to PATH (Optional)

To use `psql` directly without the full path:

```bash
echo 'export PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

## Troubleshooting

### "pg_config executable not found"

If you see this error when installing psycopg2-binary, ensure PostgreSQL is installed:

```bash
brew install postgresql@16
```

For Python 3.13+, use `psycopg[binary]` instead of `psycopg2-binary`:

```bash
pip install "psycopg[binary]"
```

### "FATAL: role does not exist"

Create the database user:

```bash
/opt/homebrew/opt/postgresql@16/bin/psql -d postgres -c "CREATE USER django_user WITH PASSWORD 'django_pass';"
```

### "FATAL: database does not exist"

Create the database:

```bash
/opt/homebrew/opt/postgresql@16/bin/createdb django_auth_db
```

### "permission denied for schema public"

Grant schema privileges (required for PostgreSQL 15+):

```bash
/opt/homebrew/opt/postgresql@16/bin/psql -d django_auth_db -c "GRANT ALL ON SCHEMA public TO django_user;"
```

### Connection refused

Ensure PostgreSQL is running:

```bash
brew services start postgresql@16
```

## Environment-Specific Notes

### Development

- Falls back to SQLite if `DATABASE_URL` is not set
- Good for quick testing without PostgreSQL
- Set `DATABASE_URL` in `.env` for PostgreSQL development

### Production

- Requires `DATABASE_URL` to be set (no fallback)
- Uses connection pooling with `conn_max_age=600`
- Format: `postgres://user:password@host:port/database`

### Testing

- Always uses SQLite in-memory database
- Fast test execution
- No configuration needed

## Cloud PostgreSQL Services

The `DATABASE_URL` format works with all major cloud providers:

- **Heroku Postgres**: Automatically sets `DATABASE_URL`
- **AWS RDS**: `postgres://user:password@host.rds.amazonaws.com:5432/database`
- **Google Cloud SQL**: `postgres://user:password@/database?host=/cloudsql/project:region:instance`
- **Digital Ocean**: `postgres://user:password@host:port/database?sslmode=require`

## Security Notes

1. Never commit `.env` files with real credentials
2. Use strong passwords in production
3. Restrict database user permissions as needed
4. Enable SSL for remote connections
5. Regularly backup your database
