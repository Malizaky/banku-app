# 📧 Production Email Configuration Guide

## Namecheap Email Setup for BankU

### 1. Namecheap Email Configuration

**Required Environment Variables:**
```bash
# Namecheap Email Settings
MAIL_SERVER=mail.yourdomain.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=noreply@yourdomain.com
MAIL_PASSWORD=your-namecheap-email-password
MAIL_FROM_NAME=BankU
```

### 2. Namecheap SMTP Settings

**Standard Namecheap SMTP Configuration:**
- **SMTP Server**: `mail.yourdomain.com` (replace with your actual domain)
- **Port**: `587` (recommended) or `465` (SSL)
- **Encryption**: `TLS` (port 587) or `SSL` (port 465)
- **Authentication**: Required

### 3. Common Namecheap Email Ports

| Port | Encryption | Use Case |
|------|------------|----------|
| 587  | TLS        | Recommended for most applications |
| 465  | SSL        | Alternative SSL option |
| 25   | None       | Usually blocked by hosting providers |

### 4. Setting Up Your Email

1. **Log into Namecheap cPanel**
2. **Go to Email Accounts**
3. **Create a new email**: `noreply@yourdomain.com`
4. **Set a strong password**
5. **Note down the email credentials**

### 5. Testing Email Configuration

**Test your email settings:**
```python
# Test script (run on server)
from utils.email_service import EmailService

email_service = EmailService()
print(f"SMTP Server: {email_service.smtp_server}")
print(f"SMTP Port: {email_service.smtp_port}")
print(f"Username: {email_service.smtp_username}")
print(f"Use TLS: {email_service.use_tls}")
```

### 6. Email Verification Features

**Available Features:**
- ✅ User registration email verification
- ✅ Password reset emails
- ✅ Welcome emails after verification
- ✅ Admin notification emails
- ✅ Resend verification with attempt limits
- ✅ 24-hour verification token expiry

### 7. Production Deployment Checklist

**Before Going Live:**
- [ ] Test email sending with your Namecheap account
- [ ] Verify email delivery to common email providers
- [ ] Check spam folder delivery rates
- [ ] Set up email monitoring/logging
- [ ] Configure proper FROM address (noreply@yourdomain.com)

### 8. Troubleshooting

**Common Issues:**
- **Authentication Failed**: Check username/password
- **Connection Timeout**: Verify SMTP server and port
- **TLS/SSL Errors**: Ensure correct encryption settings
- **Emails in Spam**: Set up SPF/DKIM records in Namecheap DNS

### 9. Security Best Practices

**Email Security:**
- Use strong passwords for email accounts
- Enable 2FA on your Namecheap account
- Monitor email sending limits
- Set up proper FROM headers to avoid spam
- Consider using dedicated email service for high volume

### 10. Alternative Email Services

**If Namecheap email has issues:**
- **SendGrid**: Professional email service
- **Mailgun**: Developer-friendly email API
- **Amazon SES**: Scalable email service
- **Gmail SMTP**: With app passwords

---

## Quick Setup Commands

**For Railway/Heroku deployment:**
```bash
# Set environment variables
railway variables set MAIL_SERVER=mail.yourdomain.com
railway variables set MAIL_PORT=587
railway variables set MAIL_USE_TLS=true
railway variables set MAIL_USERNAME=noreply@yourdomain.com
railway variables set MAIL_PASSWORD=your-password
```

**For VPS/Server deployment:**
```bash
# Add to .env file
echo "MAIL_SERVER=mail.yourdomain.com" >> .env
echo "MAIL_PORT=587" >> .env
echo "MAIL_USE_TLS=true" >> .env
echo "MAIL_USERNAME=noreply@yourdomain.com" >> .env
echo "MAIL_PASSWORD=your-password" >> .env
```
