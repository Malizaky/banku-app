#!/usr/bin/env python3
"""
BankU Application Startup Check
Validates system requirements and initializes the application safely
"""

import os
import sys
import logging
import traceback
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('logs/startup.log')
    ]
)
logger = logging.getLogger(__name__)

def check_python_version():
    """Check Python version compatibility"""
    try:
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            logger.error(f"Python 3.8+ required, found {version.major}.{version.minor}")
            return False
        logger.info(f"Python version: {version.major}.{version.minor}.{version.micro}")
        return True
    except Exception as e:
        logger.error(f"Error checking Python version: {e}")
        return False

def check_dependencies():
    """Check if all required dependencies are available"""
    required_packages = [
        'flask',
        'flask_sqlalchemy',
        'flask_login',
        'flask_wtf',
        'flask_mail',
        'werkzeug',
        'sqlalchemy',
        'psutil',
        'requests',
        'beautifulsoup4',
        'selenium',
        'schedule',
        'pillow'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            logger.info(f"✓ {package} available")
        except ImportError:
            missing_packages.append(package)
            logger.error(f"✗ {package} missing")
    
    if missing_packages:
        logger.error(f"Missing packages: {', '.join(missing_packages)}")
        logger.error("Please install missing packages: pip install " + " ".join(missing_packages))
        return False
    
    return True

def check_directories():
    """Check if required directories exist and create them if needed"""
    required_dirs = [
        'logs',
        'static/uploads',
        'static/uploads/logos',
        'instance'
    ]
    
    for directory in required_dirs:
        try:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                logger.info(f"Created directory: {directory}")
            else:
                logger.info(f"✓ Directory exists: {directory}")
        except Exception as e:
            logger.error(f"Error creating directory {directory}: {e}")
            return False
    
    return True

def check_database_connection():
    """Check database connectivity"""
    try:
        from app import app, db
        with app.app_context():
            # Test database connection
            db.session.execute('SELECT 1')
            db.session.commit()
            logger.info("✓ Database connection successful")
            return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False

def check_file_permissions():
    """Check file system permissions"""
    try:
        # Check if we can write to uploads directory
        test_file = 'static/uploads/test_write.tmp'
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        logger.info("✓ File system permissions OK")
        return True
    except Exception as e:
        logger.error(f"File system permissions error: {e}")
        return False

def check_environment_variables():
    """Check critical environment variables"""
    critical_vars = ['SECRET_KEY']
    optional_vars = ['DATABASE_URL', 'MAIL_SERVER', 'MAIL_USERNAME', 'MAIL_PASSWORD']
    
    missing_critical = []
    
    for var in critical_vars:
        if not os.environ.get(var):
            missing_critical.append(var)
            logger.error(f"✗ Missing critical environment variable: {var}")
        else:
            logger.info(f"✓ Environment variable set: {var}")
    
    for var in optional_vars:
        if os.environ.get(var):
            logger.info(f"✓ Optional environment variable set: {var}")
        else:
            logger.info(f"⚠ Optional environment variable not set: {var}")
    
    if missing_critical:
        logger.error("Critical environment variables missing. Application may not start properly.")
        return False
    
    return True

def initialize_database():
    """Initialize database tables and default data"""
    try:
        from app import app, db
        from models import User, Role
        
        with app.app_context():
            # Create all tables
            db.create_all()
            logger.info("✓ Database tables created/updated")
            
            # Check if admin user exists
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                logger.info("⚠ Admin user not found - will be created on first run")
            else:
                logger.info("✓ Admin user exists")
            
            return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        logger.error(traceback.format_exc())
        return False

def check_selenium_driver():
    """Check if Selenium WebDriver is available"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.quit()
        logger.info("✓ Selenium WebDriver available")
        return True
    except Exception as e:
        logger.warning(f"Selenium WebDriver not available: {e}")
        logger.warning("Advanced data collection features will be limited")
        return False

def run_startup_checks():
    """Run all startup checks"""
    logger.info("=" * 60)
    logger.info("BankU Application Startup Check")
    logger.info("=" * 60)
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("Directories", check_directories),
        ("Environment Variables", check_environment_variables),
        ("File Permissions", check_file_permissions),
        ("Database Connection", check_database_connection),
        ("Database Initialization", initialize_database),
        ("Selenium WebDriver", check_selenium_driver)
    ]
    
    results = []
    
    for check_name, check_func in checks:
        logger.info(f"\nRunning check: {check_name}")
        try:
            result = check_func()
            results.append((check_name, result))
            if result:
                logger.info(f"✓ {check_name} passed")
            else:
                logger.error(f"✗ {check_name} failed")
        except Exception as e:
            logger.error(f"✗ {check_name} failed with exception: {e}")
            results.append((check_name, False))
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("STARTUP CHECK SUMMARY")
    logger.info("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for check_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{status} - {check_name}")
    
    logger.info(f"\nOverall: {passed}/{total} checks passed")
    
    if passed == total:
        logger.info("🎉 All checks passed! Application ready to start.")
        return True
    elif passed >= total - 1:  # Allow one non-critical check to fail
        logger.warning("⚠ Some checks failed, but application should still start.")
        return True
    else:
        logger.error("❌ Critical checks failed. Please fix issues before starting.")
        return False

if __name__ == "__main__":
    success = run_startup_checks()
    sys.exit(0 if success else 1)






