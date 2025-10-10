# 🚀 BankU Server Deployment Guide

## 📧 Email Configuration (Configured & Ready)

**Your Namecheap Email Settings:**
```bash
MAIL_SERVER=mail.allnd.me
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=noreply@allnd.me
MAIL_PASSWORD=@@@Zenon@@@010@@@
MAIL_FROM_NAME=BankU
```

## 🌐 Deployment Options

### Option 1: Railway (Recommended - Easy Setup)

**Steps:**
1. **Connect GitHub to Railway:**
   - Go to [railway.app](https://railway.app)
   - Sign up with GitHub
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your `banku-app` repository

2. **Configure Environment Variables:**
   ```bash
   SECRET_KEY=your-super-secret-production-key-here
   DATABASE_URL=postgresql://username:password@host:port/database
   MAIL_SERVER=mail.allnd.me
   MAIL_PORT=587
   MAIL_USE_TLS=true
   MAIL_USERNAME=noreply@allnd.me
   MAIL_PASSWORD=@@@Zenon@@@010@@@
   MAIL_FROM_NAME=BankU
   PORT=8000
   ```

3. **Database Setup:**
   - Railway will automatically create a PostgreSQL database
   - Copy the DATABASE_URL from Railway dashboard
   - Set it as environment variable

4. **Deploy:**
   - Railway will automatically deploy from your GitHub repo
   - Your app will be live at `https://your-app.railway.app`

### Option 2: Heroku

**Steps:**
1. **Install Heroku CLI and login**
2. **Create Heroku app:**
   ```bash
   heroku create your-banku-app
   ```
3. **Set environment variables:**
   ```bash
   heroku config:set SECRET_KEY=your-secret-key
   heroku config:set DATABASE_URL=postgresql://...
   heroku config:set MAIL_SERVER=mail.allnd.me
   heroku config:set MAIL_PORT=587
   heroku config:set MAIL_USE_TLS=true
   heroku config:set MAIL_USERNAME=noreply@allnd.me
   heroku config:set MAIL_PASSWORD=@@@Zenon@@@010@@@
   heroku config:set MAIL_FROM_NAME=BankU
   ```
4. **Deploy:**
   ```bash
   git push heroku main
   ```

### Option 3: VPS/Cloud Server (DigitalOcean, AWS, etc.)

**Steps:**
1. **Set up server** (Ubuntu 20.04+ recommended)
2. **Install dependencies:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip nginx mysql-server
   ```
3. **Clone repository:**
   ```bash
   git clone https://github.com/Malizaky/banku-app.git
   cd banku-app
   ```
4. **Set up virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements_production.txt
   ```
5. **Configure database:**
   ```bash
   mysql -u root -p
   CREATE DATABASE banku_production;
   CREATE USER 'banku_user'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON banku_production.* TO 'banku_user'@'localhost';
   ```
6. **Set environment variables:**
   ```bash
   export SECRET_KEY=your-secret-key
   export DATABASE_URL=mysql://banku_user:password@localhost/banku_production
   export MAIL_SERVER=mail.allnd.me
   export MAIL_PORT=587
   export MAIL_USE_TLS=true
   export MAIL_USERNAME=noreply@allnd.me
   export MAIL_PASSWORD=@@@Zenon@@@010@@@
   export MAIL_FROM_NAME=BankU
   ```
7. **Run database migrations:**
   ```bash
   python init_db.py
   ```
8. **Set up systemd service** for auto-start
9. **Configure Nginx** as reverse proxy

## 🗄️ Database Configuration

### PostgreSQL (Recommended for Railway/Heroku)
```bash
DATABASE_URL=postgresql://username:password@host:port/database_name
```

### MySQL (For VPS deployment)
```bash
DATABASE_URL=mysql://username:password@host:port/database_name
```

## 🔐 Security Configuration

**Generate strong SECRET_KEY:**
```python
import secrets
print(secrets.token_urlsafe(32))
```

**Production Security Settings:**
```bash
SECRET_KEY=your-generated-secret-key
WTF_CSRF_ENABLED=true
WTF_CSRF_TIME_LIMIT=3600
MAX_CONTENT_LENGTH=16777216
```

## 🧪 Testing After Deployment

### 1. Email Verification Test
- Register a new user
- Check if verification email is received
- Test email verification link
- Test resend verification functionality

### 2. Core Functionality Test
- User registration and login
- Profile creation and editing
- Bank system functionality
- Wallet system operations
- Admin panel access
- File uploads

### 3. Admin Panel Test
- Access admin dashboard
- User management
- Role and permission management
- Wallet management
- Analytics and reports

## 📊 Production Monitoring

### Health Checks
- Application health: `https://your-domain.com/health`
- Database connectivity
- Email service status
- File upload functionality

### Logs Monitoring
- Application logs
- Error tracking
- Performance monitoring
- Email delivery logs

## 🔧 Troubleshooting

### Common Issues

**Email Problems:**
- **SMTP Authentication Failed**: Check username/password
- **Connection Timeout**: Verify SMTP server settings
- **Emails in Spam**: Configure SPF/DKIM records

**Database Issues:**
- **Connection Failed**: Verify database URL and credentials
- **Migration Errors**: Run `python init_db.py` on server
- **Performance Issues**: Add database indexes

**Application Issues:**
- **500 Errors**: Check application logs
- **Static Files Not Loading**: Verify static file configuration
- **Upload Issues**: Check file permissions and disk space

## 📋 Post-Deployment Checklist

- [ ] Email verification working
- [ ] User registration functional
- [ ] Admin panel accessible
- [ ] Database operations working
- [ ] File uploads working
- [ ] SSL certificate configured
- [ ] Domain DNS configured
- [ ] Monitoring set up
- [ ] Backup strategy implemented

## 🎉 Success!

Your BankU application is now ready for production deployment with:
- ✅ Email verification system (noreply@allnd.me)
- ✅ Profile slug-based URLs
- ✅ Comprehensive wallet system
- ✅ Advanced permission system
- ✅ Bank system with filtering
- ✅ Admin analytics and management
- ✅ File upload and management
- ✅ Production-ready configuration

**Next Steps:**
1. Choose your deployment platform
2. Set up environment variables
3. Deploy and test
4. Configure domain and SSL
5. Monitor and maintain

---

**GitHub Repository:** https://github.com/Malizaky/banku-app
**Email:** noreply@allnd.me
**Domain:** allnd.me
