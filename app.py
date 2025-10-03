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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI') or os.environ.get('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# File upload configuration
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Security and robustness configurations
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security headers middleware (minimal to avoid breaking frontend)
@app.after_request
def add_security_headers(response):
    """Add minimal security headers to avoid breaking frontend"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    logger.warning(f"404 error: {request.url}")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"500 error: {str(error)}")
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    logger.warning(f"403 error: {request.url}")
    return render_template('errors/403.html'), 403

# Request logging middleware
@app.before_request
def log_request_info():
    """Log request information for debugging"""
    logger.info(f"Request: {request.method} {request.url} from {request.remote_addr}")

# Import models first to initialize db
from models import db, User, Role, Tag, Profile, Item, Project, ProjectContributor, Deal, DealItem, DealMessage, Review, Earning, Notification, Bank, Information, ProductCategory, ButtonConfiguration, ItemType, DataStorageMapping, ChatbotCompletion, AnalyticsEvent, ABTest, ABTestAssignment, PerformanceMetric

# Initialize extensions
db.init_app(app)

# Initialize Flask-Mail
from flask_mail import Mail
mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.banks import banks_bp
from routes.deals import deals_bp
from routes.profiles import profiles_bp
from routes.admin import admin_bp
from routes.simulations import simulations_bp
from routes.chatbot import chatbot_bp
from routes.data_collectors import data_collectors_bp
from routes.analytics import analytics_bp
from routes.ai_matching import ai_matching_bp
from routes.organizations import organizations_bp
from routes.feedback import feedback_bp
from routes.scoring_admin import scoring_admin_bp

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
app.register_blueprint(banks_bp, url_prefix='/banks')
app.register_blueprint(deals_bp, url_prefix='/deals')
app.register_blueprint(profiles_bp, url_prefix='/profiles')
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(simulations_bp, url_prefix='/simulations')
app.register_blueprint(chatbot_bp, url_prefix='/chatbot')
app.register_blueprint(data_collectors_bp, url_prefix='/data-collectors')
app.register_blueprint(analytics_bp, url_prefix='/analytics')
app.register_blueprint(ai_matching_bp, url_prefix='/ai-matching')
app.register_blueprint(organizations_bp, url_prefix='')
app.register_blueprint(feedback_bp, url_prefix='')
app.register_blueprint(scoring_admin_bp, url_prefix='/admin')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/analytics/track', methods=['POST'])
def track_analytics():
    """Track analytics events from frontend"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Log the analytics event (you can extend this to store in database)
        print(f"Analytics Event: {data.get('event_type', 'unknown')} - {data.get('event_name', 'unknown')}")
        
        # For now, just return success
        # In the future, you can store this in the AnalyticsEvent model
        return jsonify({'status': 'success', 'message': 'Event tracked'}), 200
        
    except Exception as e:
        print(f"Analytics tracking error: {str(e)}")
        return jsonify({'error': 'Failed to track event'}), 500

@app.route('/favicon.ico')
def favicon():
    """Serve favicon.ico to prevent 404 errors"""
    return '', 204  # Return empty response with 204 No Content status

def cleanup_on_exit():
    """Cleanup function called when the app exits"""
    try:
        from utils.advanced_data_collector import advanced_collector
        advanced_collector.stop_scheduled_collectors()
        print("✓ Data collector scheduler stopped gracefully")
    except Exception as e:
        print(f"Warning: Error stopping scheduler: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}, shutting down gracefully...")
    cleanup_on_exit()
    sys.exit(0)

if __name__ == '__main__':
    # Register cleanup functions
    atexit.register(cleanup_on_exit)
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
    
    with app.app_context():
        db.create_all()
        
        # Create initial admin user if not exists
        from models import User, Role
        from werkzeug.security import generate_password_hash
        from sqlalchemy import text
        
        # Create admin role if not exists
        admin_role = Role.query.filter_by(name='Admin').first()
        if not admin_role:
            admin_role = Role(
                name='Admin',
                description='Administrator role with full access',
                permissions='admin_access,user_management,content_management',
                is_active=True
            )
            db.session.add(admin_role)
            db.session.commit()
            print("✅ Admin role created!")
        
        # Create admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@banku.com',
                password_hash=generate_password_hash('admin123'),
                first_name='Admin',
                last_name='User',
                is_active=True,
                email_verified=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Admin user created!")
            
            # Assign admin role to user using direct SQL
            if admin_role:
                db.session.execute(
                    text('INSERT INTO user_role_assignments (user_id, role_id) VALUES (:user_id, :role_id)'),
                    {'user_id': admin_user.id, 'role_id': admin_role.id}
                )
                db.session.commit()
                print("✅ Admin role assigned to user!")
        else:
            print("✅ Admin user already exists!")
        
        print("🎉 Admin setup complete! Login: admin / admin123")
        
        # Start the advanced data collector scheduler
        try:
            from utils.advanced_data_collector import advanced_collector
            advanced_collector.start_scheduled_collectors()
            print("SUCCESS: Advanced Data Collector scheduler started successfully!")
        except Exception as e:
            print(f"WARNING: Could not start data collector scheduler: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
