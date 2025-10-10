# 🚀 BankU Production Environment Configuration

## 📧 Email Configuration (Namecheap)
```bash
MAIL_SERVER=mail.allnd.me
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=noreply@allnd.me
MAIL_PASSWORD=@@@Zenon@@@010@@@
MAIL_FROM_NAME=BankU
```

## 🗄️ Database Configuration (MariaDB)
```bash
DATABASE_URL=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU?charset=utf8mb4
SQLALCHEMY_DATABASE_URI=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU?charset=utf8mb4
```

## 🔐 Security Configuration
```bash
SECRET_KEY=your-super-secret-production-key-change-this
WTF_CSRF_ENABLED=true
WTF_CSRF_TIME_LIMIT=3600
MAX_CONTENT_LENGTH=16777216
```

## 🌐 Server Configuration
```bash
PORT=8000
HOST=0.0.0.0
```

## 📋 Complete Environment Variables for Production

### Required Variables
```bash
# Database
DATABASE_URL=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU?charset=utf8mb4
SQLALCHEMY_DATABASE_URI=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU?charset=utf8mb4

# Email
MAIL_SERVER=mail.allnd.me
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=noreply@allnd.me
MAIL_PASSWORD=@@@Zenon@@@010@@@
MAIL_FROM_NAME=BankU

# Security
SECRET_KEY=your-super-secret-production-key-change-this

# Server
PORT=8000
```

### Optional Variables
```bash
# Email Verification (keep default for production)
DISABLE_EMAIL_VERIFICATION=false
WEBMAIL_SIMULATION=false

# Performance
SQLALCHEMY_ENGINE_OPTIONS={"pool_size": 10, "pool_recycle": 3600, "pool_pre_ping": true, "max_overflow": 20}
```

## 🔧 Database Information
- **Server**: MariaDB 11.4.8
- **Host**: localhost:3306
- **Database**: aioaczgd_BankU
- **User**: aioaczgd_UBankU
- **Password**: @@@Zenon@@@010@@@
- **Connection**: Local via UNIX socket
- **SSL**: Not required (local connection)

## 🚀 Deployment Instructions

### For Railway/Heroku
Set these environment variables in your hosting platform dashboard:
```bash
DATABASE_URL=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU?charset=utf8mb4
MAIL_SERVER=mail.allnd.me
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=noreply@allnd.me
MAIL_PASSWORD=@@@Zenon@@@010@@@
MAIL_FROM_NAME=BankU
SECRET_KEY=your-super-secret-production-key
PORT=8000
```

### For VPS/Server
Create a `.env` file on your server:
```bash
# Database
DATABASE_URL=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU?charset=utf8mb4
SQLALCHEMY_DATABASE_URI=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU?charset=utf8mb4

# Email
MAIL_SERVER=mail.allnd.me
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=noreply@allnd.me
MAIL_PASSWORD=@@@Zenon@@@010@@@
MAIL_FROM_NAME=BankU

# Security
SECRET_KEY=your-super-secret-production-key

# Server
PORT=8000
```

## 🧪 Testing Database Connection

After deployment, test the database connection:
```python
from app import app, db
with app.app_context():
    try:
        db.engine.execute('SELECT 1')
        print('✅ Database connection successful')
    except Exception as e:
        print(f'❌ Database connection failed: {e}')
```

## 📊 Database Migration

Run this to create all tables:
```bash
python init_db.py
```

## 🔒 Security Notes
- Generate a strong SECRET_KEY for production
- Use environment variables for all sensitive data
- Enable SSL for production email if possible
- Regular database backups recommended

---

**Domain**: allnd.me  
**Email**: noreply@allnd.me  
**Database**: aioaczgd_BankU (MariaDB)  
**Application**: BankU Production Ready
