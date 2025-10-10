# 🔧 .htaccess Fix Guide

## 🔍 Check Your Current .htaccess

**Run this command on your server:**
```bash
cat /home/aioaczgd/allnd.me/.htaccess
```

## ⚠️ Common .htaccess Issues

### Issue 1: Wrong Redirects
**Problem**: Redirects all requests away from your Flask app
**Symptoms**: 
- All URLs redirect to wrong place
- Flask routes don't work
- Static files not loading

### Issue 2: Blocks Python Execution
**Problem**: Prevents Python/Flask from running
**Symptoms**:
- 500 Internal Server Error
- "File not found" errors
- App won't start

### Issue 3: Static File Interference
**Problem**: Blocks CSS, JS, images
**Symptoms**:
- No styling on pages
- JavaScript not working
- Images not loading

## ✅ Correct .htaccess for Flask

### Option 1: Minimal .htaccess (RECOMMENDED)
```apache
# Allow Python execution
AddHandler python-script .py
DirectoryIndex main.py

# Handle static files
<Files "*.css">
    Header set Content-Type "text/css"
</Files>
<Files "*.js">
    Header set Content-Type "application/javascript"
</Files>

# Enable rewrite engine
RewriteEngine On

# Redirect all requests to main.py (except static files)
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_URI} !^/static/
RewriteRule ^(.*)$ main.py [QSA,L]
```

### Option 2: Passenger .htaccess (If using Passenger)
```apache
PassengerEnabled On
PassengerAppRoot /home/aioaczgd/allnd.me
PassengerAppType wsgi
PassengerStartupFile main.py
PassengerPython /usr/bin/python3
```

### Option 3: Simple .htaccess
```apache
DirectoryIndex main.py
AddHandler python-script .py
```

## 🔧 Fix Commands

### Replace with Correct .htaccess

**Option 1: Minimal (Recommended)**
```bash
cat > /home/aioaczgd/allnd.me/.htaccess << 'EOF'
# Allow Python execution
AddHandler python-script .py
DirectoryIndex main.py

# Handle static files
<Files "*.css">
    Header set Content-Type "text/css"
</Files>
<Files "*.js">
    Header set Content-Type "application/javascript"
</Files>

# Enable rewrite engine
RewriteEngine On

# Redirect all requests to main.py (except static files)
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_URI} !^/static/
RewriteRule ^(.*)$ main.py [QSA,L]
EOF
```

**Option 2: Simple**
```bash
cat > /home/aioaczgd/allnd.me/.htaccess << 'EOF'
DirectoryIndex main.py
AddHandler python-script .py
EOF
```

### Delete .htaccess (If causing issues)
```bash
rm /home/aioaczgd/allnd.me/.htaccess
```

## 🧪 Test After Fix

### Check if .htaccess is correct:
```bash
cat /home/aioaczgd/allnd.me/.htaccess
```

### Test your application:
1. Visit your domain
2. Check if Flask routes work
3. Verify static files load (CSS, JS, images)
4. Test user registration/login

## 🚨 Troubleshooting

### If still having issues:

**1. Check server error logs:**
```bash
tail -f /var/log/apache2/error.log
# OR
tail -f /var/log/httpd/error_log
```

**2. Check if Python is enabled:**
```bash
# Test Python execution
echo "print('Hello World')" > /home/aioaczgd/allnd.me/test.py
```

**3. Check file permissions:**
```bash
chmod 644 /home/aioaczgd/allnd.me/.htaccess
chmod 755 /home/aioaczgd/allnd.me/
chmod 644 /home/aioaczgd/allnd.me/main.py
```

**4. Verify WSGI configuration:**
```bash
ls -la /home/aioaczgd/allnd.me/passenger_wsgi.py
```

## 📋 Common .htaccess Problems

| Problem | Symptom | Solution |
|---------|---------|----------|
| Wrong redirects | All URLs redirect | Fix rewrite rules |
| No Python handler | 500 errors | Add `AddHandler python-script .py` |
| Static file blocking | No CSS/JS | Add static file rules |
| Directory index wrong | 404 on root | Set `DirectoryIndex main.py` |

---

**Check your current .htaccess and let me know what it contains!** 🔍
