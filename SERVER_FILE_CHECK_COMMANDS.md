# 🔍 Server File Check Commands

## 📁 Your App Location: `/home/aioaczgd/allnd.me`

### Step 1: Check All Files

**Run this command on your server:**
```bash
ls -la /home/aioaczgd/allnd.me
```

**Expected output should include:**
```
✅ app.py (BankU main application)
✅ main.py (Railway entry point)
✅ models.py (Database models)
✅ forms.py (Form definitions)
✅ requirements.txt or requirements_production.txt
✅ routes/ (Application routes folder)
✅ templates/ (HTML templates folder)
✅ utils/ (Utilities folder)
✅ static/ (Static files folder)
```

### Step 2: Check Main Files

**Check if these files exist and their sizes:**
```bash
ls -la /home/aioaczgd/allnd.me/app.py
ls -la /home/aioaczgd/allnd.me/main.py
ls -la /home/aioaczgd/allnd.me/models.py
ls -la /home/aioaczgd/allnd.me/forms.py
```

**BankU files should be LARGE:**
- ✅ `app.py` - Should be ~50KB+ (thousands of lines)
- ✅ `main.py` - Should be small (~200 bytes)
- ✅ `models.py` - Should be ~30KB+ (hundreds of lines)
- ✅ `forms.py` - Should be ~10KB+ (hundreds of lines)

**Default files are SMALL:**
- ❌ `app.py` - If only ~2KB (dozens of lines) = DEFAULT
- ❌ `main.py` - If different content = DEFAULT

### Step 3: Check File Contents

**Check if files contain BankU code:**
```bash
head -10 /home/aioaczgd/allnd.me/app.py
head -10 /home/aioaczgd/allnd.me/main.py
```

**BankU app.py should start with:**
```python
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import logging
import atexit
import signal
import sys
from functools import wraps

app = Flask(__name__)
```

**BankU main.py should contain:**
```python
# Railway deployment entry point
import os
from app import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
```

### Step 4: Check Folders

**Check if essential folders exist:**
```bash
ls -la /home/aioaczgd/allnd.me/routes/
ls -la /home/aioaczgd/allnd.me/templates/
ls -la /home/aioaczgd/allnd.me/utils/
ls -la /home/aioaczgd/allnd.me/static/
```

**Expected folders:**
```
✅ routes/ (should contain admin.py, auth.py, banks.py, profiles.py, etc.)
✅ templates/ (should contain admin/, auth/, banks/, profiles/, etc.)
✅ utils/ (should contain email_service.py, slug_utils.py, permissions.py, etc.)
✅ static/ (should contain css/, js/, uploads/, etc.)
```

### Step 5: Check Requirements

**Check dependencies file:**
```bash
cat /home/aioaczgd/allnd.me/requirements.txt
# OR
cat /home/aioaczgd/allnd.me/requirements_production.txt
```

**Should contain BankU dependencies:**
```
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
Flask-WTF==1.2.1
Flask-Mail==0.9.1
WTForms==3.1.1
Werkzeug>=3.1.0
SQLAlchemy==2.0.25
PyMySQL==1.1.0
Pillow==10.4.0
bcrypt==4.0.1
python-dotenv==1.0.0
gunicorn==21.2.0
```

## 🚨 Troubleshooting

### Issue 1: Default app.py Found
**Problem**: Server created default Flask app
**Solution**: Replace with your BankU app.py

### Issue 2: Missing Routes Folder
**Problem**: No routes/ folder
**Solution**: Upload your complete routes/ folder

### Issue 3: Missing Templates
**Problem**: No templates/ folder or empty
**Solution**: Upload your complete templates/ folder

### Issue 4: Wrong Requirements
**Problem**: Basic requirements.txt
**Solution**: Replace with requirements_production.txt

## 🔧 File Replacement Commands

**If you need to replace files:**

```bash
# Replace app.py (if it's the default)
cp /path/to/your/banku/app.py /home/aioaczgd/allnd.me/app.py

# Replace main.py (if it's the default)
cp /path/to/your/banku/main.py /home/aioaczgd/allnd.me/main.py

# Replace requirements.txt
cp /path/to/your/banku/requirements_production.txt /home/aioaczgd/allnd.me/requirements.txt

# Copy folders (if missing)
cp -r /path/to/your/banku/routes/ /home/aioaczgd/allnd.me/
cp -r /path/to/your/banku/templates/ /home/aioaczgd/allnd.me/
cp -r /path/to/your/banku/utils/ /home/aioaczgd/allnd.me/
cp -r /path/to/your/banku/static/ /home/aioaczgd/allnd.me/
```

## 📊 Quick Check Summary

**Run this command to get a quick overview:**
```bash
echo "=== FILE SIZES ==="
ls -lh /home/aioaczgd/allnd.me/app.py /home/aioaczgd/allnd.me/main.py /home/aioaczgd/allnd.me/models.py

echo "=== FOLDERS ==="
ls -la /home/aioaczgd/allnd.me/ | grep "^d"

echo "=== MAIN FILES ==="
ls -la /home/aioaczgd/allnd.me/*.py
```

---

**Run these commands and let me know what you find!** 🔍
