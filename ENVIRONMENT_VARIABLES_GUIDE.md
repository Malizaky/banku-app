# 🔧 Environment Variables Setup Guide

## 📋 What Are Environment Variables?

Environment variables are configuration settings that:
- **Store sensitive information** (passwords, API keys) securely
- **Configure your application** for different environments
- **Keep secrets out of your code** for security
- **Allow easy deployment** across different platforms

## 🚀 Your BankU Environment Variables

### Required Variables for Production

```bash
# Database Configuration (MariaDB)
DATABASE_URL=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU
SQLALCHEMY_DATABASE_URI=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU

# Email Configuration (Namecheap)
MAIL_SERVER=mail.allnd.me
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=noreply@allnd.me
MAIL_PASSWORD=@@@Zenon@@@010@@@
MAIL_FROM_NAME=BankU

# Security
SECRET_KEY=your-super-secret-production-key-change-this

# Server Configuration
PORT=8000
```

### Optional Variables

```bash
# Email Verification Settings
DISABLE_EMAIL_VERIFICATION=false
WEBMAIL_SIMULATION=false

# Performance Settings
SQLALCHEMY_ENGINE_OPTIONS={"pool_size": 10, "pool_recycle": 3600, "pool_pre_ping": true, "max_overflow": 20}
```

## 🎯 How to Set Environment Variables

### Platform 1: Railway

1. **Go to Railway Dashboard**
2. **Select your project**
3. **Click on "Variables" tab**
4. **Add each variable:**
   - Click "New Variable"
   - Enter variable name (e.g., `DATABASE_URL`)
   - Enter variable value (e.g., `mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU`)
   - Click "Add"
5. **Repeat for all variables**
6. **Redeploy your application**

### Platform 2: Heroku

1. **Go to Heroku Dashboard**
2. **Select your app**
3. **Go to "Settings" tab**
4. **Click "Reveal Config Vars"**
5. **Add each variable:**
   - Enter key (e.g., `DATABASE_URL`)
   - Enter value (e.g., `mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU`)
   - Click "Add"
6. **Repeat for all variables**
7. **Restart your application**

### Platform 3: VPS/Server

1. **Create .env file on server:**
   ```bash
   nano .env
   ```

2. **Add all variables:**
   ```bash
   DATABASE_URL=mysql://aioaczgd_UBankU:@@@Zenon@@@010@@@@@localhost:3306/aioaczgd_BankU
   MAIL_SERVER=mail.allnd.me
   MAIL_PORT=587
   MAIL_USE_TLS=true
   MAIL_USERNAME=noreply@allnd.me
   MAIL_PASSWORD=@@@Zenon@@@010@@@
   MAIL_FROM_NAME=BankU
   SECRET_KEY=your-super-secret-production-key
   PORT=8000
   ```

3. **Save and restart application**

### Platform 4: DigitalOcean App Platform

1. **Go to App Platform Dashboard**
2. **Select your app**
3. **Go to "Settings" tab**
4. **Click "Environment Variables"**
5. **Add each variable**
6. **Save changes**

## 🔒 Security Best Practices

### Generate Strong SECRET_KEY

```python
import secrets
print(secrets.token_urlsafe(32))
```

### Protect Sensitive Data
- ✅ Use environment variables for passwords
- ✅ Never commit secrets to Git
- ✅ Use different keys for development/production
- ✅ Regularly rotate sensitive credentials

## 🧪 Testing Environment Variables

### Test Database Connection
```python
from app import app, db
with app.app_context():
    try:
        db.engine.execute('SELECT 1')
        print('✅ Database connection successful')
    except Exception as e:
        print(f'❌ Database connection failed: {e}')
```

### Test Email Configuration
```python
from utils.email_service import EmailService
email_service = EmailService()
print(f'SMTP Server: {email_service.smtp_server}')
print(f'Username: {email_service.smtp_username}')
print(f'Use TLS: {email_service.use_tls}')
```

## 📊 Variable Reference

| Variable | Purpose | Example |
|----------|---------|---------|
| `DATABASE_URL` | Database connection | `mysql://user:pass@host:port/db` |
| `MAIL_SERVER` | Email server | `mail.allnd.me` |
| `MAIL_USERNAME` | Email username | `noreply@allnd.me` |
| `MAIL_PASSWORD` | Email password | `your-password` |
| `SECRET_KEY` | App security key | `random-secret-key` |
| `PORT` | Server port | `8000` |

## 🚨 Common Issues

### Database Connection Failed
- Check `DATABASE_URL` format
- Verify database credentials
- Ensure database server is running

### Email Not Working
- Check `MAIL_SERVER` and `MAIL_PORT`
- Verify email credentials
- Test SMTP connection

### App Won't Start
- Check all required variables are set
- Verify `SECRET_KEY` is set
- Check `PORT` configuration

---

**Your BankU app is ready for production with these environment variables!** 🚀
