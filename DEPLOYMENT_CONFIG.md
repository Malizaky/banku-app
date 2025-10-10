# 🚀 BankU Production Deployment Configuration

## 📧 Email Configuration (Namecheap - allnd.me)

**Production Email Settings:**
```bash
MAIL_SERVER=mail.allnd.me
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=noreply@allnd.me
MAIL_PASSWORD=@@@Zenon@@@010@@@
MAIL_FROM_NAME=BankU
```

## 🗄️ Database Configuration

**For Production (MySQL/PostgreSQL):**
```bash
# MySQL Configuration
DATABASE_URL=mysql://username:password@host:port/database_name
SQLALCHEMY_DATABASE_URI=mysql://username:password@host:port/database_name

# PostgreSQL Configuration (Alternative)
DATABASE_URL=postgresql://username:password@host:port/database_name
SQLALCHEMY_DATABASE_URI=postgresql://username:password@host:port/database_name
```

## 🔐 Security Configuration

**Production Security Settings:**
```bash
SECRET_KEY=your-super-secret-production-key-change-this
WTF_CSRF_ENABLED=true
WTF_CSRF_TIME_LIMIT=3600
MAX_CONTENT_LENGTH=16777216
```

## 🌐 Server Configuration

**Port and Host Settings:**
```bash
PORT=8000
HOST=0.0.0.0
```

## 📋 Deployment Checklist

### Pre-Deployment
- [ ] Set up production database (MySQL/PostgreSQL)
- [ ] Configure email server (mail.allnd.me)
- [ ] Generate strong SECRET_KEY
- [ ] Set up domain DNS
- [ ] Configure SSL certificate

### Environment Variables (Production)
```bash
# Required
SECRET_KEY=your-secret-key
DATABASE_URL=your-database-url
MAIL_SERVER=mail.allnd.me
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=noreply@allnd.me
MAIL_PASSWORD=@@@Zenon@@@010@@@
MAIL_FROM_NAME=BankU
PORT=8000

# Optional
DISABLE_EMAIL_VERIFICATION=false
WEBMAIL_SIMULATION=false
```

### GitHub Deployment Steps
1. **Push to GitHub**: `git push origin main`
2. **Set Environment Variables** on hosting platform
3. **Configure Database** connection
4. **Test Email** functionality
5. **Verify SSL** certificate
6. **Monitor** application logs

## 🧪 Testing Checklist

### Email Testing
- [ ] User registration sends verification email
- [ ] Email verification links work
- [ ] Resend verification works
- [ ] Welcome emails are sent
- [ ] Admin verification works

### Application Testing
- [ ] User authentication works
- [ ] Profile creation works
- [ ] Bank system functions
- [ ] Wallet system works
- [ ] Admin panel accessible
- [ ] File uploads work
- [ ] Database operations work

## 🔧 Troubleshooting

### Email Issues
- **SMTP Authentication Failed**: Check username/password
- **Connection Timeout**: Verify SMTP server and port
- **Emails in Spam**: Configure SPF/DKIM records
- **Rate Limits**: Check hosting email limits

### Database Issues
- **Connection Failed**: Verify database URL and credentials
- **Migration Errors**: Run database migrations
- **Performance Issues**: Optimize queries and add indexes

### Server Issues
- **Port Conflicts**: Ensure PORT environment variable is set
- **Memory Issues**: Monitor resource usage
- **SSL Issues**: Configure proper certificates

---

## 📞 Support Information

**Domain**: allnd.me
**Email**: noreply@allnd.me
**Application**: BankU
**Version**: Production Ready
