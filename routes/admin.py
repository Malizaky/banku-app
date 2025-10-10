from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from datetime import datetime
from models import User, Role, UserRole, Tag, Deal, Item, Profile, ProfileType, Earning, Notification, ChatbotFlow, ChatbotQuestion, ChatbotResponse, ChatbotStepBlock, Page, ContentBlock, NavigationMenu, SiteSetting, EmailTemplate, PageWidget, PageLayout, WidgetTemplate, Category, Subcategory, ButtonConfiguration, ItemType, DataStorageMapping, ChatbotCompletion, Bank, AnalyticsEvent, ABTest, ABTestAssignment, PerformanceMetric, DataCollector, BankCollector, BankContent, Organization, OrganizationType, ItemVisibilityScore, ItemCredibilityScore, ItemReviewScore, WalletTransaction, WithdrawalRequest, db
from utils.data_collection import collection_engine
from utils.permissions import require_permission
from functools import wraps

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        
        admin_role = Role.query.filter_by(name='Admin').first()
        if not admin_role:
            flash('Admin role not found', 'error')
            return redirect(request.referrer or url_for('index'))
        
        # Check if user has admin role using UserRole table
        user_admin_role = UserRole.query.filter_by(user_id=current_user.id, role_id=admin_role.id, is_active=True).first()
        if not user_admin_role:
            flash('Admin access required', 'error')
            return redirect(request.referrer or url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/')
@login_required
@admin_required
def index():
    # Get admin dashboard stats
    stats = {
        'total_users': User.query.count(),
        'total_organizations': Organization.query.count(),
        'total_deals': Deal.query.count(),
        'total_earnings': db.session.query(db.func.sum(Earning.amount)).filter_by(status='paid').scalar() or 0,
        'active_deals': Deal.query.filter(Deal.status.in_(['pending', 'in_progress'])).count(),
        'pending_verifications': Item.query.filter_by(is_verified=False).count(),
        'verified_users': User.query.filter_by(email_verified=True).count(),
        'unverified_users': User.query.filter_by(email_verified=False).count()
    }
    
    # Get bank statistics - All 14 banks
    bank_stats = {
        'products': Item.query.filter_by(category='products', is_available=True).count(),
        'services': Item.query.filter_by(category='services', is_available=True).count(),
        'ideas': Item.query.filter_by(category='ideas', is_available=True).count(),
        'projects': Item.query.filter_by(category='projects', is_available=True).count(),
        'funders': Item.query.filter_by(category='funders', is_available=True).count(),
        'events': Item.query.filter_by(category='events', is_available=True).count(),
        'auctions': Item.query.filter_by(category='auctions', is_available=True).count(),
        'experiences': Item.query.filter_by(category='experiences', is_available=True).count(),
        'opportunities': Item.query.filter_by(category='opportunities', is_available=True).count(),
        'information': Item.query.filter_by(category='information', is_available=True).count(),
        'observations': Item.query.filter_by(category='observations', is_available=True).count(),
        'hidden_gems': Item.query.filter_by(category='hidden_gems', is_available=True).count(),
        'needs': Item.query.filter_by(category='needs', is_available=True).count(),
        'people': Item.query.filter_by(category='people', is_available=True).count()
    }
    
    # Get recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_deals = Deal.query.order_by(Deal.created_at.desc()).limit(5).all()
    
    return render_template('admin/index.html', stats=stats, bank_stats=bank_stats, recent_users=recent_users, recent_deals=recent_deals)

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    role_filter = request.args.get('role', '')
    verification_filter = request.args.get('verification', '')
    
    query = User.query
    
    if search:
        query = query.filter(
            db.or_(
                User.username.contains(search),
                User.email.contains(search),
                User.first_name.contains(search),
                User.last_name.contains(search)
            )
        )
    
    if role_filter:
        query = query.join(User.roles).filter(Role.name == role_filter)
    
    if verification_filter == 'verified':
        query = query.filter(User.email_verified == True)
    elif verification_filter == 'pending':
        query = query.filter(User.email_verified == False)
    
    users = query.order_by(User.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    roles = Role.query.all()
    
    return render_template('admin/users.html', users=users, roles=roles, search=search, role_filter=role_filter, verification_filter=verification_filter)

@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    return jsonify({
        'success': True,
        'is_active': user.is_active,
        'message': f'User {"activated" if user.is_active else "deactivated"} successfully'
    })

@admin_bp.route('/users/<int:user_id>/verify-email', methods=['POST'])
@login_required
@admin_required
def verify_user_email(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.email_verified:
        return jsonify({'success': False, 'message': 'User email is already verified'})
    
    # Manually verify the user's email
    user.email_verified = True
    user.email_verification_token = None
    user.email_verification_sent_at = None
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Email for {user.email} has been manually verified'})

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user account permanently"""
    user = User.query.get_or_404(user_id)
    
    # Prevent deletion of the current user
    if user.id == current_user.id:
        return jsonify({
            'success': False,
            'message': 'You cannot delete your own account'
        }), 400
    
    # Prevent deletion of super admin accounts
    try:
        super_admin_roles = [role.name for role in user.roles]
        if 'Super Admin' in super_admin_roles:
            return jsonify({
                'success': False,
                'message': 'Cannot delete Super Admin accounts'
            }), 400
    except Exception as e:
        print(f"Error checking roles for user {user.id}: {e}")
        # Continue with deletion if role check fails
    
    try:
        # Get user data for logging
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        }
        
        print(f"Attempting to delete user: {user_data}")
        
        # First, delete all deals where this user is provider, consumer, or connector
        from models import Deal, DealMessage, DealItem
        
        # Get all deals involving this user
        deals_as_provider = Deal.query.filter_by(provider_id=user.id).all()
        deals_as_consumer = Deal.query.filter_by(consumer_id=user.id).all()
        deals_as_connector = Deal.query.filter_by(connector_id=user.id).all()
        
        all_deals = set(deals_as_provider + deals_as_consumer + deals_as_connector)
        
        print(f"Found {len(all_deals)} deals to delete for user {user.username}")
        
        # Delete all deals involving this user
        for deal in all_deals:
            # Delete deal messages first
            DealMessage.query.filter_by(deal_id=deal.id).delete()
            # Delete deal items
            DealItem.query.filter_by(deal_id=deal.id).delete()
            # Delete the deal
            db.session.delete(deal)
        
        # Delete other user-related records
        # Delete user roles
        UserRole.query.filter_by(user_id=user.id).delete()
        
        # Delete user permissions
        from models import UserPermission
        UserPermission.query.filter_by(user_id=user.id).delete()
        
        # Delete user needs
        from models import UserNeed
        UserNeed.query.filter_by(user_id=user.id).delete()
        
        # Delete user items
        from models import Item
        Item.query.filter_by(creator_id=user.id).delete()
        
        # Delete user reviews
        from models import Review
        Review.query.filter(db.or_(Review.reviewer_id == user.id, Review.reviewee_id == user.id)).delete()
        
        # Delete user earnings
        from models import Earning
        Earning.query.filter_by(user_id=user.id).delete()
        
        # Delete user notifications
        from models import Notification
        Notification.query.filter_by(user_id=user.id).delete()
        
        # Delete need-item matches involving user's needs or items
        from models import NeedItemMatch
        NeedItemMatch.query.filter(db.or_(
            NeedItemMatch.need_id.in_([need.id for need in UserNeed.query.filter_by(user_id=user.id).all()]),
            NeedItemMatch.item_id.in_([item.id for item in Item.query.filter_by(creator_id=user.id).all()])
        )).delete()
        
        # Delete other user-related records that might have NOT NULL constraints
        from models import MatchingSession, MatchingFeedback, Profile, OrganizationMember, ChatbotFlow
        
        # Matching and AI data
        MatchingSession.query.filter_by(user_id=user.id).delete()
        MatchingFeedback.query.filter_by(user_id=user.id).delete()
        
        # Profile and organization data
        Profile.query.filter_by(user_id=user.id).delete()
        OrganizationMember.query.filter_by(user_id=user.id).delete()
        
        # Chatbot data
        ChatbotFlow.query.filter_by(created_by=user.id).delete()
        
        # Finally, delete the user
        db.session.delete(user)
        db.session.commit()
        
        # Log the deletion
        print(f"User deleted by admin {current_user.username}: {user_data}")
        
        return jsonify({
            'success': True,
            'message': f'User {user_data["username"]} has been permanently deleted along with {len(all_deals)} associated deals'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user {user.id}: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error deleting user: {str(e)}'
        }), 500

@admin_bp.route('/users/<int:user_id>/assign-role', methods=['POST'])
@login_required
@admin_required
def assign_role(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    role_id = data.get('role_id')
    
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'success': False, 'message': 'Role not found'})
    
    # Check if user already has this role using UserRole table
    existing_user_role = UserRole.query.filter_by(user_id=user_id, role_id=role_id).first()
    
    if not existing_user_role:
        # Create new user role assignment
        user_role = UserRole(user_id=user_id, role_id=role_id, is_active=True)
        db.session.add(user_role)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Role assigned successfully'})
    
    return jsonify({'success': False, 'message': 'User already has this role'})

@admin_bp.route('/users/<int:user_id>/remove-role', methods=['POST'])
@login_required
@admin_required
def remove_role(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    role_id = data.get('role_id')
    
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'success': False, 'message': 'Role not found'})
    
    # Check if user has this role using UserRole table
    existing_user_role = UserRole.query.filter_by(user_id=user_id, role_id=role_id).first()
    
    if existing_user_role:
        # Remove user role assignment
        db.session.delete(existing_user_role)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Role removed successfully'})
    
    return jsonify({'success': False, 'message': 'User does not have this role'})

@admin_bp.route('/users/<int:user_id>/roles')
@login_required
@admin_required
def get_user_roles_data(user_id):
    """Get user's current roles and available roles to assign"""
    user = User.query.get_or_404(user_id)
    
    try:
        # Get user's current roles
        user_roles = []
        for role in user.roles:
            user_roles.append({
                'id': role.id,
                'name': role.name,
                'description': role.description,
                'is_internal': role.is_internal
            })
        
        # Get all available roles
        all_roles = Role.query.filter_by(is_active=True).all()
        available_roles = []
        for role in all_roles:
            available_roles.append({
                'id': role.id,
                'name': role.name,
                'description': role.description,
                'is_internal': role.is_internal
            })
        
        return jsonify({
            'success': True,
            'user_roles': user_roles,
            'available_roles': available_roles
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error loading roles: {str(e)}'
        }), 500

@admin_bp.route('/roles')
@login_required
@admin_required
def roles():
    roles = Role.query.all()
    return render_template('admin/roles.html', roles=roles)

@admin_bp.route('/role-management')
@login_required
@admin_required
def role_management():
    """Enhanced role and permission management interface"""
    roles = Role.query.all()
    users = User.query.all()
    
    # Get all unique permissions from roles
    all_permissions = set()
    permission_categories = set()
    
    for role in roles:
        if role.permissions:
            for resource, actions in role.permissions.items():
                permission_categories.add(resource)
                for action in actions:
                    all_permissions.add(f"{resource}:{action}")
    
    # Convert to list for template
    permissions = [{'name': perm, 'resource': perm.split(':')[0], 'action': perm.split(':')[1]} for perm in all_permissions]
    permission_categories = list(permission_categories)
    
    return render_template('admin/role_management.html', 
                         roles=roles, 
                         users=users, 
                         permissions=permissions,
                         permission_categories=permission_categories)

@admin_bp.route('/permissions/categories')
@login_required
@admin_required
def get_permission_categories():
    """Get all permission categories"""
    roles = Role.query.all()
    categories = set()
    
    for role in roles:
        if role.permissions:
            for resource in role.permissions.keys():
                categories.add(resource)
    
    return jsonify({'categories': list(categories)})

@admin_bp.route('/permissions/category/<category>')
@login_required
@admin_required
def get_permissions_for_category(category):
    """Get permissions for a specific category"""
    role_id = request.args.get('role_id')
    role = Role.query.get(role_id) if role_id else None
    
    # Define all possible actions for each resource
    resource_actions = {
        # Core User Management
        'users': ['create', 'delete', 'manage_roles', 'toggle_status', 'verify_email', 'view', 'edit', 'assign_roles'],
        'roles': ['create', 'delete', 'view', 'edit', 'manage_permissions'],
        
        # Business Logic
        'deals': ['create', 'delete', 'manage_status', 'send_messages', 'view', 'edit'],
        'items': ['create', 'delete', 'verify', 'manage_categories', 'view', 'edit'],
        'needs': ['create', 'delete', 'verify'],
        'profiles': ['create', 'delete', 'manage', 'view_private', 'view_about_own', 'view_about_others', 'view_activity_own', 'view_activity_others'],
        'organizations': ['create', 'delete', 'manage_members', 'verify', 'view', 'edit', 'join', 'view_private', 'view_about_own', 'view_about_others', 'view_members_own', 'view_members_others', 'view_activity_own', 'view_activity_others'],
        'organization_types': ['create', 'delete'],
        
        # AI & Matching
        'ai_matching': ['access_dashboard', 'access_engine', 'generate_recommendations', 'manage_matches'],
        'ai_recommendations': ['create', 'delete', 'rate', 'view_reports'],
        
        # Banks & Data
        'banks': ['create', 'delete', 'manage_content', 'view', 'edit', 'use'],
        'data_collectors': ['create', 'delete', 'run', 'monitor', 'test', 'toggle', 'logs', 'data'],
        'data_collection': ['create', 'delete', 'manage'],
        'collectors': ['create', 'delete', 'run', 'view', 'edit'],
        
        # Content Management System
        'cms': ['create', 'delete', 'manage_pages', 'manage_blocks', 'manage_navigation', 'dashboard'],
        'pages': ['create', 'delete', 'publish', 'preview', 'toggle', 'builder', 'widgets'],
        'content_blocks': ['create', 'delete', 'toggle'],
        'navigation': ['create', 'delete', 'toggle'],
        'email_templates': ['create', 'delete'],
        
        # Dynamic Configuration
        'dynamic_buttons': ['create', 'delete'],
        'item_types': ['create', 'delete'],
        'data_mappings': ['create', 'delete'],
        
        # Chatbot System
        'chatbots': ['create', 'delete', 'manage_flows', 'manage_questions', 'manage_responses', 'view', 'edit'],
        'chatbot_flows': ['create', 'delete', 'duplicate', 'toggle', 'responses', 'analytics'],
        'chatbot_questions': ['create', 'delete'],
        'chatbot_responses': ['create', 'delete'],
        'step_blocks': ['create', 'delete', 'questions'],
        'chatbot': ['use'],
        
        # Analytics & Reports
        'analytics': ['advanced_analytics', 'realtime_analytics', 'ab_testing', 'events', 'view', 'use'],
        'reports': ['generate', 'view_all', 'export', 'comprehensive', 'overview', 'user_activity', 'system_performance', 'business_metrics', 'security_events', 'ab_test_results'],
        'performance_metrics': ['monitor'],
        'ab_tests': ['create', 'delete', 'run'],
        
        # System Management
        'system_settings': ['view', 'edit'],
        'verifications': ['approve', 'reject', 'manage'],
        'notifications': ['create', 'delete', 'send'],
        'feedback': ['manage', 'respond'],
        'settings': ['manage'],
        'dashboard': ['view'],
        'admin': ['access'],
        'logs': ['view'],
        
        # API & Integration
        'api': ['access', 'manage_keys', 'monitor_usage'],
        'integrations': ['create', 'delete', 'test'],
        
        # Security & Monitoring
        'security': ['monitor', 'manage_incidents', 'audit_logs'],
        'monitoring': ['system_health', 'performance', 'errors'],
        'system_health': ['monitor', 'detailed'],
        
        # Scoring System
        'scoring': ['manage', 'visibility', 'credibility', 'review', 'recalculate'],
        'scoring_management': ['access', 'visibility', 'credibility', 'review'],
        
        # Admin Dashboard
        'admin_dashboard': ['access', 'view_stats', 'manage_stats'],
        'admin_management': ['access', 'users', 'roles', 'deals', 'verifications'],
        
        # Communication
        'messaging': ['send', 'view_own'],
        'reviews': ['create', 'edit_own'],
        
        # Error & Log Management
        'error_logs': ['manage'],
        'system_logs': ['monitor'],
        
        # Categories & Subcategories
        'categories': ['create', 'delete', 'subcategories'],
        'subcategories': ['create', 'delete'],
        
        # Profile Management (Legacy)
        'profile': ['view_own', 'edit_own', 'view_other', 'edit_other'],
        
        # Wallet & Financial Management
        'wallet': ['view', 'manage', 'withdraw', 'view_transactions'],
        'wallet_admin': ['view_all', 'manage_all', 'process_withdrawals', 'view_analytics'],
        'earnings': ['view', 'sync', 'manage'],
        'withdrawals': ['request', 'cancel', 'view_own'],
        'transactions': ['view_own', 'view_all']
    }
    
    if category not in resource_actions:
        return jsonify({'permissions': []})
    
    permissions = []
    role_permissions = role.permissions.get(category, []) if role and role.permissions else []
    
    for action in resource_actions[category]:
        permissions.append({
            'id': f"{category}:{action}",
            'name': f"{category}:{action}",
            'resource': category,
            'action': action,
            'description': f"Permission to {action} {category}",
            'granted': action in role_permissions
        })
    
    return jsonify({'permissions': permissions})

@admin_bp.route('/roles/<int:role_id>/permissions', methods=['POST'])
@login_required
@admin_required
def update_role_permissions(role_id):
    """Update permissions for a role"""
    role = Role.query.get_or_404(role_id)
    data = request.get_json()
    permissions = data.get('permissions', [])
    
    # Start with existing permissions (don't lose them!)
    current_permissions = role.permissions.copy() if role.permissions else {}
    
    # Convert permissions list to our JSON format
    new_permissions = {}
    for perm in permissions:
        if perm.get('granted', False):
            resource = perm.get('resource')
            action = perm.get('action')
            if resource and action:
                if resource not in new_permissions:
                    new_permissions[resource] = []
                if action not in new_permissions[resource]:
                    new_permissions[resource].append(action)
    
    # Merge new permissions with existing ones
    # Only update the resources that were actually modified
    for resource, actions in new_permissions.items():
        current_permissions[resource] = actions
    
    # Remove resources that were explicitly set to empty (all permissions unchecked)
    for perm in permissions:
        resource = perm.get('resource')
        if resource and not any(p.get('granted', False) and p.get('resource') == resource for p in permissions):
            # This resource had all permissions unchecked, remove it
            if resource in current_permissions:
                del current_permissions[resource]
    
    role.permissions = current_permissions
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Permissions updated successfully'})

@admin_bp.route('/roles/<int:role_id>/user-count')
@login_required
@admin_required
def get_role_user_count(role_id):
    """Get user count for a specific role"""
    count = UserRole.query.filter_by(role_id=role_id, is_active=True).count()
    return jsonify({'count': count})

@admin_bp.route('/roles/<int:role_id>/permission-count')
@login_required
@admin_required
def get_role_permission_count(role_id):
    """Get permission count for a specific role"""
    role = Role.query.get_or_404(role_id)
    
    # Calculate granted permissions
    granted_count = 0
    if role.permissions:
        granted_count = sum(len(actions) for actions in role.permissions.values())
    
    # Calculate total available permissions from resource_actions
    resource_actions = {
        # Core User Management
        'users': ['create', 'delete', 'manage_roles', 'toggle_status', 'verify_email', 'view', 'edit', 'assign_roles'],
        'roles': ['create', 'delete', 'view', 'edit', 'manage_permissions'],
        
        # Business Logic
        'deals': ['create', 'delete', 'manage_status', 'send_messages', 'view', 'edit'],
        'items': ['create', 'delete', 'verify', 'manage_categories', 'view', 'edit'],
        'needs': ['create', 'delete', 'verify'],
        'profiles': ['create', 'delete', 'manage', 'view_private', 'view_about_own', 'view_about_others', 'view_activity_own', 'view_activity_others'],
        'organizations': ['create', 'delete', 'manage_members', 'verify', 'view', 'edit', 'join', 'view_private', 'view_about_own', 'view_about_others', 'view_members_own', 'view_members_others', 'view_activity_own', 'view_activity_others'],
        'organization_types': ['create', 'delete'],
        
        # AI & Matching
        'ai_matching': ['access_dashboard', 'access_engine', 'generate_recommendations', 'manage_matches'],
        'ai_recommendations': ['create', 'delete', 'rate', 'view_reports'],
        
        # Banks & Data
        'banks': ['create', 'delete', 'manage_content', 'view', 'edit', 'use'],
        'data_collectors': ['create', 'delete', 'run', 'monitor', 'test', 'toggle', 'logs', 'data'],
        'data_collection': ['create', 'delete', 'manage'],
        'collectors': ['create', 'delete', 'run', 'view', 'edit'],
        
        # Content Management System
        'cms': ['create', 'delete', 'manage_pages', 'manage_blocks', 'manage_navigation', 'dashboard'],
        'pages': ['create', 'delete', 'publish', 'preview', 'toggle', 'builder', 'widgets'],
        'content_blocks': ['create', 'delete', 'toggle'],
        'navigation': ['create', 'delete', 'toggle'],
        'email_templates': ['create', 'delete'],
        
        # Dynamic Configuration
        'dynamic_buttons': ['create', 'delete'],
        'item_types': ['create', 'delete'],
        'data_mappings': ['create', 'delete'],
        
        # Chatbot System
        'chatbots': ['create', 'delete', 'manage_flows', 'manage_questions', 'manage_responses', 'view', 'edit'],
        'chatbot_flows': ['create', 'delete', 'duplicate', 'toggle', 'responses', 'analytics'],
        'chatbot_questions': ['create', 'delete'],
        'chatbot_responses': ['create', 'delete'],
        'step_blocks': ['create', 'delete', 'questions'],
        'chatbot': ['use'],
        
        # Analytics & Reports
        'analytics': ['advanced_analytics', 'realtime_analytics', 'ab_testing', 'events', 'view', 'use'],
        'reports': ['generate', 'view_all', 'export', 'comprehensive', 'overview', 'user_activity', 'system_performance', 'business_metrics', 'security_events', 'ab_test_results'],
        'performance_metrics': ['monitor'],
        'ab_tests': ['create', 'delete', 'run'],
        
        # System Management
        'system_settings': ['view', 'edit'],
        'verifications': ['approve', 'reject', 'manage'],
        'notifications': ['create', 'delete', 'send'],
        'feedback': ['manage', 'respond'],
        'settings': ['manage'],
        'dashboard': ['view'],
        'admin': ['access'],
        'logs': ['view'],
        
        # API & Integration
        'api': ['access', 'manage_keys', 'monitor_usage'],
        'integrations': ['create', 'delete', 'test'],
        
        # Security & Monitoring
        'security': ['monitor', 'manage_incidents', 'audit_logs'],
        'monitoring': ['system_health', 'performance', 'errors'],
        'system_health': ['monitor', 'detailed'],
        
        # Scoring System
        'scoring': ['manage', 'visibility', 'credibility', 'review', 'recalculate'],
        'scoring_management': ['access', 'visibility', 'credibility', 'review'],
        
        # Admin Dashboard
        'admin_dashboard': ['access', 'view_stats', 'manage_stats'],
        'admin_management': ['access', 'users', 'roles', 'deals', 'verifications'],
        
        # Communication
        'messaging': ['send', 'view_own'],
        'reviews': ['create', 'edit_own'],
        
        # Error & Log Management
        'error_logs': ['manage'],
        'system_logs': ['monitor'],
        
        # Categories & Subcategories
        'categories': ['create', 'delete', 'subcategories'],
        'subcategories': ['create', 'delete'],
        
        # Profile Management (Legacy)
        'profile': ['view_own', 'edit_own', 'view_other', 'edit_other'],
        
        # Wallet & Financial Management
        'wallet': ['view', 'manage', 'withdraw', 'view_transactions'],
        'wallet_admin': ['view_all', 'manage_all', 'process_withdrawals', 'view_analytics'],
        'earnings': ['view', 'sync', 'manage'],
        'withdrawals': ['request', 'cancel', 'view_own'],
        'transactions': ['view_own', 'view_all']
    }
    
    total_count = sum(len(actions) for actions in resource_actions.values())
    
    return jsonify({
        'granted': granted_count,
        'total': total_count,
        'count': granted_count  # Keep for backward compatibility
    })

@admin_bp.route('/roles/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_role():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        name = data.get('name')
        description = data.get('description')
        permissions = data.get('permissions', {})
        is_internal = data.get('is_internal', False)
        
        if not name:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Role name is required'})
            flash('Role name is required', 'error')
            return render_template('admin/create_role.html')
        
        role = Role(
            name=name,
            description=description,
            permissions=permissions,
            is_internal=is_internal
        )
        
        db.session.add(role)
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Role created successfully',
                'role_id': role.id
            })
        
        flash('Role created successfully', 'success')
        return redirect(url_for('admin.roles'))
    
    return render_template('admin/create_role.html')

@admin_bp.route('/deals')
@login_required
@admin_required
def deals():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    status_filter = request.args.get('status', 'all')
    
    query = Deal.query
    
    if status_filter != 'all':
        query = query.filter(Deal.status == status_filter)
    
    deals = query.order_by(Deal.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/deals.html', deals=deals, status_filter=status_filter)

@admin_bp.route('/verifications')
@login_required
@admin_required
def verifications():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    items = Item.query.filter_by(is_verified=False)\
        .order_by(Item.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/verifications.html', items=items)

@admin_bp.route('/verifications/<int:item_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_item(item_id):
    item = Item.query.get_or_404(item_id)
    item.is_verified = True
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Item approved successfully'})

@admin_bp.route('/verifications/<int:item_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_item(item_id):
    item = Item.query.get_or_404(item_id)
    data = request.get_json()
    reason = data.get('reason', 'No reason provided')
    
    # Create notification for the item owner
    notification = Notification(
        user_id=item.profile.user_id,
        title="Item Verification Rejected",
        message=f"Your item '{item.title}' was rejected: {reason}",
        notification_type="verification_rejected",
        data={'item_id': item.id}
    )
    db.session.add(notification)
    
    # Delete the item
    db.session.delete(item)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Item rejected and deleted'})

@admin_bp.route('/items/<int:item_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_item_admin(item_id):
    """Admin route to delete any item with cascading deletion"""
    item = Item.query.get_or_404(item_id)
    
    try:
        # Create notification for the item owner
        notification = Notification(
            user_id=item.profile.user_id,
            title="Item Deleted by Admin",
            message=f"Your item '{item.title}' was deleted by an administrator.",
            notification_type="item_deleted",
            data={'item_id': item.id}
        )
        db.session.add(notification)
        
        # Delete all related records first (cascading deletion)
        from models import ItemCredibilityScore, ItemReviewScore, ItemVisibilityScore
        from utils.file_cleanup import delete_item_files
        
        # Delete associated files first
        file_cleanup_result = delete_item_files(item)
        if file_cleanup_result['success']:
            print(f"✅ Admin deleted {file_cleanup_result['total_deleted']} files for item {item_id}")
        else:
            print(f"⚠️ Admin file cleanup had issues: {file_cleanup_result.get('error', 'Unknown error')}")
        
        # Delete credibility scores
        ItemCredibilityScore.query.filter_by(item_id=item_id).delete()
        
        # Delete review scores
        ItemReviewScore.query.filter_by(item_id=item_id).delete()
        
        # Delete visibility scores
        ItemVisibilityScore.query.filter_by(item_id=item_id).delete()
        
        # Finally delete the item itself
        db.session.delete(item)
        db.session.commit()
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Item deleted successfully'})
        
        flash('Item deleted successfully', 'success')
        return redirect(url_for('admin.index'))
        
    except Exception as e:
        db.session.rollback()
        if request.is_json:
            return jsonify({'success': False, 'error': str(e)})
        
        flash(f'Error deleting item: {str(e)}', 'error')
        return redirect(url_for('admin.index'))

@admin_bp.route('/cleanup-orphaned-files', methods=['POST'])
@login_required
@admin_required
def cleanup_orphaned_files():
    """Admin route to clean up orphaned files"""
    try:
        from utils.file_cleanup import cleanup_orphaned_files
        import os
        
        # Get orphaned files info
        result = cleanup_orphaned_files()
        
        if not result['success']:
            return jsonify({'success': False, 'error': result['error']})
        
        orphaned_files = result['orphaned_files']
        upload_folder = current_app.config['UPLOAD_FOLDER']
        
        # Delete orphaned files
        deleted_count = 0
        failed_count = 0
        
        for filename in orphaned_files:
            file_path = os.path.join(upload_folder, filename)
            try:
                os.remove(file_path)
                deleted_count += 1
                print(f"✅ Deleted orphaned file: {filename}")
            except Exception as e:
                failed_count += 1
                print(f"❌ Failed to delete orphaned file {filename}: {e}")
        
        return jsonify({
            'success': True,
            'message': f'Cleanup complete: {deleted_count} files deleted, {failed_count} failed',
            'deleted_count': deleted_count,
            'failed_count': failed_count,
            'total_orphaned': len(orphaned_files)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@admin_bp.route('/analytics')
@login_required
@admin_required
def analytics():
    # Get analytics data
    from datetime import datetime, timedelta
    
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    analytics_data = {
        'users_this_month': User.query.filter(User.created_at >= thirty_days_ago).count(),
        'deals_this_month': Deal.query.filter(Deal.created_at >= thirty_days_ago).count(),
        'revenue_this_month': db.session.query(db.func.sum(Earning.amount))\
            .filter(Earning.created_at >= thirty_days_ago)\
            .filter(Earning.status == 'paid').scalar() or 0,
        'top_earners': db.session.query(User, db.func.sum(Earning.amount))\
            .join(Earning)\
            .filter(Earning.status == 'paid')\
            .group_by(User.id)\
            .order_by(db.func.sum(Earning.amount).desc())\
            .limit(10).all()
    }
    
    return render_template('admin/analytics.html', analytics=analytics_data)

@admin_bp.route('/interaction-analytics')
@login_required
@admin_required
def interaction_analytics():
    """View item interaction analytics"""
    from datetime import datetime, timedelta
    from models import ItemInteraction
    
    # Get date range from query params
    days = int(request.args.get('days', 7))
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    # Get interaction data
    interactions = ItemInteraction.query.filter(
        ItemInteraction.created_at >= start_date,
        ItemInteraction.created_at <= end_date
    ).order_by(ItemInteraction.created_at.desc()).all()
    
    # Get interaction statistics
    total_interactions = len(interactions)
    
    # Interaction types breakdown
    interaction_types = {}
    for interaction in interactions:
        interaction_types[interaction.interaction_type] = interaction_types.get(interaction.interaction_type, 0) + 1
    
    # Source breakdown
    sources = {}
    for interaction in interactions:
        sources[interaction.source] = sources.get(interaction.source, 0) + 1
    
    # Most viewed items
    item_views = {}
    for interaction in interactions:
        if interaction.interaction_type == 'view':
            item_views[interaction.item_id] = item_views.get(interaction.item_id, 0) + 1
    
    # Get top viewed items with details
    top_items = []
    for item_id, view_count in sorted(item_views.items(), key=lambda x: x[1], reverse=True)[:10]:
        item = Item.query.get(item_id)
        if item:
            top_items.append({
                'item': item,
                'view_count': view_count
            })
    
    # Get all users for template use
    all_users = {user.id: user for user in User.query.all()}
    all_items = {item.id: item for item in Item.query.all()}
    all_profiles = {profile.id: profile for profile in Profile.query.all()}
    
    # User interaction data (logged in users only)
    user_interactions = {}
    for interaction in interactions:
        if interaction.user_id:
            user_interactions[interaction.user_id] = user_interactions.get(interaction.user_id, 0) + 1
    
    # Get top active users
    top_users = []
    for user_id, interaction_count in sorted(user_interactions.items(), key=lambda x: x[1], reverse=True)[:10]:
        user = User.query.get(user_id)
        if user:
            top_users.append({
                'user': user,
                'interaction_count': interaction_count
            })
    
    # Anonymous vs logged in breakdown
    logged_in_interactions = len([i for i in interactions if i.user_id])
    anonymous_interactions = total_interactions - logged_in_interactions
    
    analytics_data = {
        'total_interactions': total_interactions,
        'interaction_types': interaction_types,
        'sources': sources,
        'top_items': top_items,
        'top_users': top_users,
        'logged_in_interactions': logged_in_interactions,
        'anonymous_interactions': anonymous_interactions,
        'date_range': f"{start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
        'interactions': interactions[:50],  # Latest 50 interactions
        'all_users': all_users,
        'all_items': all_items,
        'all_profiles': all_profiles
    }
    
    return render_template('admin/interaction_analytics.html', analytics=analytics_data)

@admin_bp.route('/interaction-analytics/item/<int:item_id>')
@login_required
@admin_required
def item_interaction_history(item_id):
    """View detailed interaction history for a specific item"""
    from models import ItemInteraction
    
    # Get the item
    item = Item.query.get_or_404(item_id)
    
    # Get all interactions for this item
    interactions = ItemInteraction.query.filter_by(item_id=item_id)\
        .order_by(ItemInteraction.created_at.desc()).all()
    
    # Get interaction statistics
    total_interactions = len(interactions)
    
    # Interaction types breakdown for this item
    interaction_types = {}
    for interaction in interactions:
        interaction_types[interaction.interaction_type] = interaction_types.get(interaction.interaction_type, 0) + 1
    
    # User interaction data
    user_interactions = {}
    for interaction in interactions:
        if interaction.user_id:
            user_interactions[interaction.user_id] = user_interactions.get(interaction.user_id, 0) + 1
    
    # Get top users for this item
    top_users = []
    for user_id, interaction_count in sorted(user_interactions.items(), key=lambda x: x[1], reverse=True)[:10]:
        user = User.query.get(user_id)
        if user:
            top_users.append({
                'user': user,
                'interaction_count': interaction_count
            })
    
    # Anonymous vs logged in breakdown
    logged_in_interactions = len([i for i in interactions if i.user_id])
    anonymous_interactions = total_interactions - logged_in_interactions
    
    # Get all users and profiles for template use
    all_users = {user.id: user for user in User.query.all()}
    all_profiles = {profile.id: profile for profile in Profile.query.all()}
    
    analytics_data = {
        'item': item,
        'total_interactions': total_interactions,
        'interaction_types': interaction_types,
        'top_users': top_users,
        'logged_in_interactions': logged_in_interactions,
        'anonymous_interactions': anonymous_interactions,
        'interactions': interactions,
        'all_users': all_users,
        'all_profiles': all_profiles
    }
    
    return render_template('admin/item_interaction_history.html', analytics=analytics_data)

@admin_bp.route('/interaction-analytics/profile/<int:profile_id>')
@login_required
@admin_required
def profile_interaction_history(profile_id):
    """View detailed interaction history for a specific profile"""
    from models import ItemInteraction
    
    # Get the profile
    profile = Profile.query.get_or_404(profile_id)
    
    # Get all items for this profile
    profile_items = Item.query.filter_by(profile_id=profile_id).all()
    item_ids = [item.id for item in profile_items]
    
    if not item_ids:
        interactions = []
    else:
        # Get all interactions for items belonging to this profile
        interactions = ItemInteraction.query.filter(ItemInteraction.item_id.in_(item_ids))\
            .order_by(ItemInteraction.created_at.desc()).all()
    
    # Get interaction statistics
    total_interactions = len(interactions)
    
    # Interaction types breakdown for this profile's items
    interaction_types = {}
    for interaction in interactions:
        interaction_types[interaction.interaction_type] = interaction_types.get(interaction.interaction_type, 0) + 1
    
    # Item interaction breakdown
    item_interactions = {}
    for interaction in interactions:
        item_interactions[interaction.item_id] = item_interactions.get(interaction.item_id, 0) + 1
    
    # Get top items for this profile
    top_items = []
    for item_id, interaction_count in sorted(item_interactions.items(), key=lambda x: x[1], reverse=True)[:10]:
        item = Item.query.get(item_id)
        if item:
            top_items.append({
                'item': item,
                'interaction_count': interaction_count
            })
    
    # User interaction data (who interacted with this profile's items)
    user_interactions = {}
    for interaction in interactions:
        if interaction.user_id:
            user_interactions[interaction.user_id] = user_interactions.get(interaction.user_id, 0) + 1
    
    # Get top users who interacted with this profile's items
    top_users = []
    for user_id, interaction_count in sorted(user_interactions.items(), key=lambda x: x[1], reverse=True)[:10]:
        user = User.query.get(user_id)
        if user:
            top_users.append({
                'user': user,
                'interaction_count': interaction_count
            })
    
    # Anonymous vs logged in breakdown
    logged_in_interactions = len([i for i in interactions if i.user_id])
    anonymous_interactions = total_interactions - logged_in_interactions
    
    # Get all users and items for template use
    all_users = {user.id: user for user in User.query.all()}
    all_items = {item.id: item for item in Item.query.all()}
    
    analytics_data = {
        'profile': profile,
        'total_interactions': total_interactions,
        'interaction_types': interaction_types,
        'top_items': top_items,
        'top_users': top_users,
        'logged_in_interactions': logged_in_interactions,
        'anonymous_interactions': anonymous_interactions,
        'interactions': interactions,
        'profile_items': profile_items,
        'all_users': all_users,
        'all_items': all_items
    }
    
    return render_template('admin/profile_interaction_history.html', analytics=analytics_data)


# Chatbot Management Routes
@admin_bp.route('/chatbots')
@login_required
@admin_required
def chatbots():
    """List all chatbot flows"""
    flows = ChatbotFlow.query.order_by(ChatbotFlow.created_at.desc()).all()
    return render_template('admin/chatbots.html', flows=flows)


@admin_bp.route('/chatbots/create_simple', methods=['GET'])
def create_chatbot_simple():
    """Simple chatbot creator with fixed branching"""
    return render_template('admin/create_chatbot_simple.html')

@admin_bp.route('/chatbots/create_enhanced', methods=['GET'])
def create_chatbot_enhanced():
    """Enhanced chatbot creator with all features"""
    return render_template('admin/create_chatbot_enhanced.html')

@admin_bp.route('/chatbots/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_chatbot():
    """Create a new chatbot flow"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate required fields
            if not data:
                return jsonify({'success': False, 'error': 'No data provided'})
            
            if not data.get('name'):
                return jsonify({'success': False, 'error': 'Chatbot name is required'})
            
            if len(data['name'].strip()) < 3:
                return jsonify({'success': False, 'error': 'Chatbot name must be at least 3 characters long'})
            
            if not data.get('step_blocks'):
                return jsonify({'success': False, 'error': 'At least one step block is required'})
            
            # Validate step blocks
            for i, step_data in enumerate(data.get('step_blocks', [])):
                if not step_data.get('name'):
                    return jsonify({'success': False, 'error': f'Step {i + 1}: Step name is required'})
                
                if len(step_data['name'].strip()) < 2:
                    return jsonify({'success': False, 'error': f'Step {i + 1}: Step name must be at least 2 characters long'})
                
                if not step_data.get('questions'):
                    return jsonify({'success': False, 'error': f'Step "{step_data["name"]}": At least one question is required'})
                
                # Validate questions
                for j, question_data in enumerate(step_data.get('questions', [])):
                    if not question_data.get('question_text'):
                        return jsonify({'success': False, 'error': f'Step "{step_data["name"]}", Question {j + 1}: Question text is required'})
                    
                    if len(question_data['question_text'].strip()) < 5:
                        return jsonify({'success': False, 'error': f'Step "{step_data["name"]}", Question {j + 1}: Question text must be at least 5 characters long'})
                    
                    if not question_data.get('question_type'):
                        return jsonify({'success': False, 'error': f'Step "{step_data["name"]}", Question {j + 1}: Question type is required'})
                    
                    # Validate options for select/radio/checkbox
                    if question_data['question_type'] in ['select', 'radio', 'checkbox']:
                        if not question_data.get('options') or len(question_data['options']) < 2:
                            return jsonify({'success': False, 'error': f'Step "{step_data["name"]}", Question {j + 1}: At least 2 options are required for {question_data["question_type"]} question'})
                    
                    # Validate cascading dropdown
                    if question_data['question_type'] == 'cascading_dropdown':
                        cascading_config = question_data.get('cascading_config', {})
                        if not cascading_config.get('categories') or len(cascading_config['categories']) == 0:
                            return jsonify({'success': False, 'error': f'Step "{step_data["name"]}", Question {j + 1}: At least one category is required for cascading dropdown'})
            
            # Create the flow
            flow = ChatbotFlow(
                name=data['name'].strip(),
                description=data.get('description', '').strip(),
                flow_config=data.get('flow_config', {}),
                created_by=current_user.id
            )
            db.session.add(flow)
            db.session.flush()  # Get the flow ID
            
            # Create step blocks and questions
            for step_data in data.get('step_blocks', []):
                # Create step block
                step_block = ChatbotStepBlock(
                    flow_id=flow.id,
                    name=step_data['name'].strip(),
                    description=step_data.get('description', '').strip(),
                    step_order=step_data.get('step_order', 0),
                    is_required=step_data.get('is_required', True),
                    completion_message=step_data.get('completion_message', '').strip(),
                    created_by=current_user.id
                )
                db.session.add(step_block)
                db.session.flush()  # Get the step block ID
                
                # Create questions for this step block
                for question_data in step_data.get('questions', []):
                    question = ChatbotQuestion(
                        flow_id=flow.id,
                        step_block_id=step_block.id,
                        question_text=question_data['question_text'].strip(),
                        question_type=question_data['question_type'],
                        options=question_data.get('options'),
                        validation_rules=question_data.get('validation_rules', {}),
                        conditional_logic=question_data.get('conditional_logic', {}),
                        cascading_config=question_data.get('cascading_config', {}),
                        number_unit_config=question_data.get('number_unit_config', {}),
                        media_upload_config=question_data.get('media_upload_config', {}),
                        branching_logic=question_data.get('branching_logic', {}),
                        order_index=question_data.get('order_index', 0),
                        is_required=question_data.get('is_required', True),
                        question_classification=question_data.get('question_classification', 'essential'),
                        field_mapping=question_data.get('field_mapping', ''),
                        placeholder=question_data.get('placeholder', '').strip(),
                        help_text=question_data.get('help_text', '').strip(),
                        default_view=question_data.get('default_view', 'show')
                    )
                    db.session.add(question)
            
            db.session.commit()
            return jsonify({'success': True, 'flow_id': flow.id})
            
        except Exception as e:
            db.session.rollback()
            error_message = str(e)
            
            # Provide more specific error messages
            if 'UNIQUE constraint failed' in error_message:
                return jsonify({'success': False, 'error': 'A chatbot with this name already exists. Please choose a different name.'})
            elif 'NOT NULL constraint failed' in error_message:
                return jsonify({'success': False, 'error': 'Required fields are missing. Please check all required fields are filled.'})
            elif 'FOREIGN KEY constraint failed' in error_message:
                return jsonify({'success': False, 'error': 'Invalid data relationships. Please refresh the page and try again.'})
            else:
                return jsonify({'success': False, 'error': f'Database error: {error_message}'})
    
    return render_template('admin/create_chatbot.html')


@admin_bp.route('/chatbots/create-hybrid')
@login_required
@admin_required
def create_chatbot_hybrid():
    """Create a new hybrid chatbot with field mapping"""
    item_types = ItemType.query.filter_by(is_active=True, is_visible=True).order_by(ItemType.order_index, ItemType.name).all()
    banks = Bank.query.filter_by(is_active=True).order_by(Bank.name).all()
    return render_template('admin/create_chatbot_hybrid.html', item_types=item_types, banks=banks)

@admin_bp.route('/chatbots/create-hybrid', methods=['POST'])
@login_required
@admin_required
def create_chatbot_hybrid_post():
    """Handle hybrid chatbot creation with field mapping"""
    try:
        data = request.get_json() if request.is_json else request.form
        
        # Extract basic information
        name = data.get('name')
        description = data.get('description', '')
        item_type_id = data.get('item_type_id')
        bank_id = data.get('bank_id')
        
        if not name or not item_type_id:
            return jsonify({'success': False, 'message': 'Name and Item Type are required'})
        
        # Get item type
        item_type = ItemType.query.get(item_type_id)
        if not item_type:
            return jsonify({'success': False, 'message': 'Invalid Item Type'})
        
        # Create chatbot flow
        chatbot = ChatbotFlow(
            name=name,
            description=description,
            item_type_id=item_type_id,
            bank_id=bank_id if bank_id else None,
            created_by=current_user.id,
            is_active=True
        )
        
        db.session.add(chatbot)
        db.session.flush()  # Get the ID
        
        # Create field mapping configuration
        field_mapping_config = {
            'core_fields': {
                'title': data.get('core_title', 'What\'s the title?'),
                'description': data.get('core_description', 'Describe briefly'),
                'price': data.get('core_price', 'What\'s the price?'),
                'location': data.get('core_location', 'Where are you located?')
            },
            'category_fields': {},
            'questions': []
        }
        
        # Extract category-specific field mappings
        for key, value in data.items():
            if key.startswith('category_') and value:
                field_name = key.replace('category_', '')
                field_mapping_config['category_fields'][field_name] = value
        
        # Extract questions
        question_counter = 1
        while f'question_{question_counter}_text' in data:
            question_data = {
                'text': data.get(f'question_{question_counter}_text'),
                'type': data.get(f'question_{question_counter}_type', 'text'),
                'mapping': data.get(f'question_{question_counter}_mapping', ''),
                'required': data.get(f'question_{question_counter}_required') == 'on'
            }
            field_mapping_config['questions'].append(question_data)
            question_counter += 1
        
        # Store field mapping configuration
        chatbot.field_mapping_config = str(field_mapping_config)
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Hybrid chatbot created successfully',
            'chatbot_id': chatbot.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error creating chatbot: {str(e)}'})

@admin_bp.route('/chatbots/<int:flow_id>')
@login_required
@admin_required
def view_chatbot(flow_id):
    """View a specific chatbot flow"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    return render_template('admin/view_chatbot.html', flow=flow)




@admin_bp.route('/chatbots/<int:flow_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_chatbot(flow_id):
    """Edit a chatbot flow"""
    print(f"DEBUG: ===== EDIT CHATBOT ROUTE CALLED =====")
    print(f"DEBUG: Requested flow_id: {flow_id}")
    print(f"DEBUG: Request method: {request.method}")
    print(f"DEBUG: Request URL: {request.url}")
    
    # Check if flow exists
    flow = ChatbotFlow.query.get(flow_id)
    if not flow:
        print(f"DEBUG: ERROR - Flow with id {flow_id} not found!")
        return "Flow not found", 404
    
    print(f"DEBUG: Flow found: {flow}")
    print(f"DEBUG: Flow details:")
    print(f"DEBUG: - ID: {flow.id}")
    print(f"DEBUG: - Name: {flow.name}")
    print(f"DEBUG: - Description: {flow.description}")
    print(f"DEBUG: - Is Active: {flow.is_active}")
    print(f"DEBUG: - Created At: {flow.created_at}")
    print(f"DEBUG: - Created By: {flow.created_by}")
    
    # Check if flow has any step blocks
    step_blocks_count = ChatbotStepBlock.query.filter_by(flow_id=flow.id).count()
    print(f"DEBUG: Step blocks count for this flow: {step_blocks_count}")
    
    # Check if flow has any questions
    questions_count = ChatbotQuestion.query.filter_by(flow_id=flow.id).count()
    print(f"DEBUG: Questions count for this flow: {questions_count}")
    
    # Check all step blocks in database
    all_step_blocks = ChatbotStepBlock.query.all()
    print(f"DEBUG: Total step blocks in database: {len(all_step_blocks)}")
    for sb in all_step_blocks:
        print(f"DEBUG: - Step Block {sb.id}: flow_id={sb.flow_id}, name='{sb.name}'")
    
    # Check all questions in database
    all_questions = ChatbotQuestion.query.all()
    print(f"DEBUG: Total questions in database: {len(all_questions)}")
    for q in all_questions:
        print(f"DEBUG: - Question {q.id}: flow_id={q.flow_id}, step_block_id={q.step_block_id}, text='{q.question_text[:50]}...'")
    
    # Check all flows in database
    all_flows = ChatbotFlow.query.all()
    print(f"DEBUG: Total flows in database: {len(all_flows)}")
    for f in all_flows:
        print(f"DEBUG: - Flow {f.id}: name='{f.name}', active={f.is_active}")
    
    print(f"DEBUG: ===== END DATABASE DEBUG =====")
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Update flow
            flow.name = data['name']
            flow.description = data.get('description', '')
            flow.flow_config = data.get('flow_config', {})
            
            # Delete existing step blocks and questions
            ChatbotQuestion.query.filter_by(flow_id=flow.id).delete()
            ChatbotStepBlock.query.filter_by(flow_id=flow.id).delete()
            
            # Create step blocks and questions
            for step_data in data.get('step_blocks', []):
                # Create step block
                step_block = ChatbotStepBlock(
                    flow_id=flow.id,
                    name=step_data['name'],
                    description=step_data.get('description', ''),
                    step_order=step_data.get('step_order', 0),
                    is_required=step_data.get('is_required', True),
                    completion_message=step_data.get('completion_message', ''),
                    created_by=current_user.id
                )
                db.session.add(step_block)
                db.session.flush()  # Get the step block ID
                
                # Create questions for this step block
                for question_data in step_data.get('questions', []):
                    question = ChatbotQuestion(
                        flow_id=flow.id,
                        step_block_id=step_block.id,
                        question_text=question_data['question_text'],
                        question_type=question_data['question_type'],
                        options=question_data.get('options'),
                        validation_rules=question_data.get('validation_rules', {}),
                        conditional_logic=question_data.get('conditional_logic', {}),
                        cascading_config=question_data.get('cascading_config', {}),
                        number_unit_config=question_data.get('number_unit_config', {}),
                        media_upload_config=question_data.get('media_upload_config', {}),
                        branching_logic=question_data.get('branching_logic', {}),
                        order_index=question_data.get('order_index', 0),
                        is_required=question_data.get('is_required', True),
                        question_classification=question_data.get('question_classification', 'essential'),
                        field_mapping=question_data.get('field_mapping', ''),
                        placeholder=question_data.get('placeholder', ''),
                        help_text=question_data.get('help_text', ''),
                        default_view=question_data.get('default_view', 'show')
                    )
                    db.session.add(question)
            
            db.session.commit()
            return jsonify({'success': True})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    # Serialize the flow data for the template (moved outside POST block)
    flow_data = {
        'id': flow.id,
        'name': flow.name,
        'description': flow.description or '',
        'flow_config': flow.flow_config or {},
        'is_active': flow.is_active,
        'created_at': flow.created_at.isoformat() if flow.created_at else None,
        'step_blocks': []
    }
    
    print(f"DEBUG: flow_data created: {flow_data}")
    print(f"DEBUG: flow_data type: {type(flow_data)}")
    print(f"DEBUG: flow_data is None: {flow_data is None}")
    
    print(f"DEBUG: Loading flow {flow.id} for edit")
    print(f"DEBUG: Flow name: {flow.name}")
    print(f"DEBUG: Flow description: {flow.description}")
    
    # Get step blocks with questions
    print(f"DEBUG: ===== QUERYING STEP BLOCKS =====")
    step_blocks = ChatbotStepBlock.query.filter_by(flow_id=flow.id).order_by(ChatbotStepBlock.step_order).all()
    print(f"DEBUG: Found {len(step_blocks)} step blocks for flow_id {flow.id}")
    
    # Debug each step block
    for i, step_block in enumerate(step_blocks):
        print(f"DEBUG: Step Block {i+1}:")
        print(f"DEBUG: - ID: {step_block.id}")
        print(f"DEBUG: - Name: {step_block.name}")
        print(f"DEBUG: - Description: {step_block.description}")
        print(f"DEBUG: - Step Order: {step_block.step_order}")
        print(f"DEBUG: - Is Required: {step_block.is_required}")
        print(f"DEBUG: - Flow ID: {step_block.flow_id}")
        print(f"DEBUG: - Created By: {step_block.created_by}")
        
        # Check questions for this step block
        questions = ChatbotQuestion.query.filter_by(step_block_id=step_block.id).order_by(ChatbotQuestion.order_index).all()
        print(f"DEBUG: - Questions count: {len(questions)}")
        
        for j, question in enumerate(questions):
            print(f"DEBUG:   Question {j+1}:")
            print(f"DEBUG:   - ID: {question.id}")
            print(f"DEBUG:   - Text: {question.question_text[:50]}...")
            print(f"DEBUG:   - Type: {question.question_type}")
            print(f"DEBUG:   - Flow ID: {question.flow_id}")
            print(f"DEBUG:   - Step Block ID: {question.step_block_id}")
            print(f"DEBUG:   - Order Index: {question.order_index}")
    
    if len(step_blocks) == 0:
        print(f"DEBUG: WARNING - No step blocks found for flow_id {flow.id}")
        print(f"DEBUG: This means the chatbot has no steps/questions yet")
    else:
        print(f"DEBUG: Processing {len(step_blocks)} step blocks...")
    
    for step_block in step_blocks:
        print(f"DEBUG: Processing step block: {step_block.name}")
        step_data = {
            'id': step_block.id,
            'name': step_block.name,
            'description': step_block.description or '',
            'step_order': step_block.step_order,
            'is_required': step_block.is_required,
            'completion_message': step_block.completion_message or '',
            'questions': []
        }
        
        # Get questions for this step block
        questions = ChatbotQuestion.query.filter_by(step_block_id=step_block.id).order_by(ChatbotQuestion.order_index).all()
        print(f"DEBUG: Step '{step_block.name}' has {len(questions)} questions")
        
        for question in questions:
            question_data = {
                'id': question.id,
                'question_text': question.question_text,
                'question_type': question.question_type,
                'options': question.options,
                'validation_rules': question.validation_rules or {},
                'conditional_logic': question.conditional_logic or {},
                'cascading_config': question.cascading_config or {},
                'number_unit_config': question.number_unit_config or {},
                'media_upload_config': question.media_upload_config or {},
                'branching_logic': question.branching_logic or {},
                'order_index': question.order_index,
                'is_required': question.is_required,
                'question_classification': question.question_classification or 'essential',
                'field_mapping': question.field_mapping or '',
                'placeholder': question.placeholder or '',
                'help_text': question.help_text or '',
                'default_view': question.default_view or 'show'
            }
            step_data['questions'].append(question_data)
        
        flow_data['step_blocks'].append(step_data)
        print(f"DEBUG: Added step '{step_block.name}' to flow_data. Total steps now: {len(flow_data['step_blocks'])}")
    
    print(f"DEBUG: Final flow_data structure:")
    print(f"DEBUG: - Name: {flow_data['name']}")
    print(f"DEBUG: - Description: {flow_data['description']}")
    print(f"DEBUG: - Step blocks: {len(flow_data['step_blocks'])}")
    for i, step in enumerate(flow_data['step_blocks']):
        print(f"DEBUG:   - Step {i+1}: '{step['name']}' with {len(step['questions'])} questions")
    
    # Debug JSON serialization
    import json
    try:
        json_str = json.dumps(flow_data)
        print(f"DEBUG: JSON serialization successful, length: {len(json_str)}")
    except Exception as e:
        print(f"DEBUG: JSON serialization failed: {e}")
    
    # Check if flow_data is empty
    if not flow_data or not flow_data.get('step_blocks'):
        print(f"DEBUG: WARNING - flow_data is empty or has no step_blocks!")
        print(f"DEBUG: flow_data = {flow_data}")
        print(f"DEBUG: step_blocks = {flow_data.get('step_blocks') if flow_data else 'None'}")
    
    print(f"DEBUG: About to render template with flow_data: {flow_data is not None}")
    print(f"DEBUG: About to render template with is_edit: True")
    
    # Debug: Check cascading config in flow_data
    if flow_data and 'step_blocks' in flow_data:
        for i, step in enumerate(flow_data['step_blocks']):
            if 'questions' in step:
                for j, question in enumerate(step['questions']):
                    if question.get('question_type') == 'cascading_dropdown':
                        print(f"DEBUG: Step {i+1}, Question {j+1} cascading_config: {question.get('cascading_config')}")
    
    return render_template('admin/create_chatbot_enhanced.html', flow_data=flow_data, is_edit=True)


@admin_bp.route('/chatbots/<int:flow_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_chatbot(flow_id):
    """Delete a chatbot flow"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    
    try:
        # Delete all related records first (due to foreign key constraints)
        # 1. Delete all responses for this flow
        ChatbotResponse.query.filter_by(flow_id=flow_id).delete()
        
        # 2. Delete completions for this flow
        from models import ChatbotCompletion, DataStorageMapping, ItemType
        ChatbotCompletion.query.filter_by(chatbot_id=flow_id).delete()

        # 3. Delete storage mappings referencing this chatbot
        DataStorageMapping.query.filter_by(chatbot_id=flow_id).delete()

        # 4. Nullify chatbot reference on item types that point to this flow
        item_types_with_flow = ItemType.query.filter_by(chatbot_id=flow_id).all()
        for it in item_types_with_flow:
            it.chatbot_id = None

        # 5. Delete analytics/events that reference this chatbot (if present)
        try:
            from models import AnalyticsEvent
            AnalyticsEvent.query.filter_by(chatbot_id=flow_id).delete()
        except Exception:
            pass  # Table may not exist in some deployments

        # 6. Delete all questions for this flow
        ChatbotQuestion.query.filter_by(flow_id=flow_id).delete()
        
        # 7. Delete all step blocks for this flow
        ChatbotStepBlock.query.filter_by(flow_id=flow_id).delete()
        
        # 8. Finally delete the flow itself
        db.session.delete(flow)
        db.session.commit()
        
        flash('Chatbot flow deleted successfully', 'success')
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/chatbots/<int:flow_id>/duplicate', methods=['POST'])
@login_required
@admin_required
def duplicate_chatbot(flow_id):
    """Duplicate a chatbot flow"""
    original_flow = ChatbotFlow.query.get_or_404(flow_id)
    
    try:
        # Create new flow with duplicated data
        new_flow = ChatbotFlow(
            name=f"{original_flow.name} (Copy)",
            description=original_flow.description,
            flow_config=original_flow.flow_config,
            is_active=False,  # Start as inactive
            created_by=current_user.id
        )
        db.session.add(new_flow)
        db.session.flush()  # Get the new flow ID
        
        # Duplicate step blocks
        step_blocks = ChatbotStepBlock.query.filter_by(flow_id=flow_id).order_by(ChatbotStepBlock.step_order).all()
        step_id_map = {}
        question_id_map = {}
        new_questions_created = []  # (old_question, new_question)
        for step_block in step_blocks:
            new_step_block = ChatbotStepBlock(
                flow_id=new_flow.id,
                name=step_block.name,
                description=step_block.description,
                step_order=step_block.step_order,
                is_required=step_block.is_required,
                completion_message=step_block.completion_message,
                created_by=current_user.id
            )
            db.session.add(new_step_block)
            db.session.flush()  # Get the new step block ID
            step_id_map[step_block.id] = new_step_block.id
            
            # Duplicate questions for this step block
            questions = ChatbotQuestion.query.filter_by(step_block_id=step_block.id).order_by(ChatbotQuestion.order_index).all()
            for question in questions:
                new_question = ChatbotQuestion(
                    flow_id=new_flow.id,
                    step_block_id=new_step_block.id,
                    question_text=question.question_text,
                    question_type=question.question_type,
                    options=question.options,
                    validation_rules=question.validation_rules,
                    conditional_logic=question.conditional_logic,
                    cascading_config=question.cascading_config,
                    number_unit_config=question.number_unit_config,
                    media_upload_config=question.media_upload_config,
                    branching_logic=question.branching_logic,  # temporarily copy; will remap targets after all questions are created
                    order_index=question.order_index,
                    is_required=question.is_required,
                    placeholder=question.placeholder,
                    help_text=question.help_text,
                    default_view=question.default_view
                )
                db.session.add(new_question)
                db.session.flush()  # ensure new_question.id is available
                question_id_map[str(question.id)] = str(new_question.id)
                new_questions_created.append((question, new_question))
        
        # Remap branching rule targets to new question IDs
        for old_q, new_q in new_questions_created:
            try:
                logic = old_q.branching_logic or {}
                if isinstance(logic, dict) and logic.get('enabled') and isinstance(logic.get('rules'), list):
                    remapped = {'enabled': True, 'rules': []}
                    for rule in logic.get('rules', []):
                        new_rule = dict(rule) if isinstance(rule, dict) else rule
                        action = new_rule.get('action')
                        target = new_rule.get('target')
                        if action in ['show_question', 'hide_question'] and target is not None:
                            target_str = str(target)
                            if target_str in question_id_map:
                                new_rule['target'] = question_id_map[target_str]
                                new_rule['target_question_id'] = question_id_map[target_str]
                        # if action == 'go_to' and target references a step id, consider mapping by step_id_map if needed
                        remapped['rules'].append(new_rule)
                    new_q.branching_logic = remapped
            except Exception:
                # If anything goes wrong, keep original logic as-is for safety
                pass

        db.session.commit()
        return jsonify({'success': True, 'new_flow_id': new_flow.id})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/chatbots/<int:flow_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_chatbot(flow_id):
    """Toggle chatbot flow active status"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    
    try:
        flow.is_active = not flow.is_active
        db.session.commit()
        return jsonify({'success': True, 'is_active': flow.is_active})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/chatbots/<int:flow_id>/responses')
@login_required
@admin_required
def chatbot_responses(flow_id):
    """View chatbot responses"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    responses = ChatbotResponse.query.filter_by(flow_id=flow_id)\
        .order_by(ChatbotResponse.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/chatbot_responses.html', flow=flow, responses=responses)


@admin_bp.route('/chatbots/<int:flow_id>/analytics')
@login_required
@admin_required
def chatbot_analytics(flow_id):
    """View chatbot analytics"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    
    # Get analytics data
    total_responses = ChatbotResponse.query.filter_by(flow_id=flow_id).count()
    completed_responses = ChatbotResponse.query.filter_by(flow_id=flow_id, completed=True).count()
    completion_rate = (completed_responses / total_responses * 100) if total_responses > 0 else 0
    
    # Get responses by day (last 30 days)
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    daily_responses = db.session.query(
        db.func.date(ChatbotResponse.created_at).label('date'),
        db.func.count(ChatbotResponse.id).label('count')
    ).filter(
        ChatbotResponse.flow_id == flow_id,
        ChatbotResponse.created_at >= thirty_days_ago
    ).group_by(
        db.func.date(ChatbotResponse.created_at)
    ).all()
    
    analytics = {
        'total_responses': total_responses,
        'completed_responses': completed_responses,
        'completion_rate': round(completion_rate, 2),
        'daily_responses': [{'date': str(d[0]), 'count': d[1]} for d in daily_responses]
    }
    
    return render_template('admin/chatbot_analytics.html', flow=flow, analytics=analytics)


# Step Block Management Routes
@admin_bp.route('/chatbots/<int:flow_id>/step-blocks')
@login_required
@admin_required
def chatbot_step_blocks(flow_id):
    """Manage step blocks for a chatbot flow"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    step_blocks = ChatbotStepBlock.query.filter_by(flow_id=flow_id).order_by(ChatbotStepBlock.step_order).all()
    return render_template('admin/chatbot_step_blocks.html', flow=flow, step_blocks=step_blocks)


@admin_bp.route('/chatbots/<int:flow_id>/step-blocks/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_step_block(flow_id):
    """Create a new step block"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Get the next step order
            last_step = ChatbotStepBlock.query.filter_by(flow_id=flow_id).order_by(ChatbotStepBlock.step_order.desc()).first()
            next_order = (last_step.step_order + 1) if last_step else 1
            
            step_block = ChatbotStepBlock(
                flow_id=flow_id,
                name=data['name'],
                description=data.get('description', ''),
                step_order=next_order,
                is_required=data.get('is_required', True),
                completion_message=data.get('completion_message', ''),
                next_step_condition=data.get('next_step_condition', {}),
                created_by=current_user.id
            )
            
            db.session.add(step_block)
            db.session.commit()
            
            return jsonify({'success': True, 'step_block_id': step_block.id})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    return render_template('admin/create_step_block.html', flow=flow)


@admin_bp.route('/chatbots/<int:flow_id>/step-blocks/<int:step_block_id>')
@login_required
@admin_required
def view_step_block(flow_id, step_block_id):
    """View a specific step block"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    step_block = ChatbotStepBlock.query.get_or_404(step_block_id)
    questions = ChatbotQuestion.query.filter_by(step_block_id=step_block_id).order_by(ChatbotQuestion.order_index).all()
    
    return render_template('admin/view_step_block.html', flow=flow, step_block=step_block, questions=questions)


@admin_bp.route('/chatbots/<int:flow_id>/step-blocks/<int:step_block_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_step_block(flow_id, step_block_id):
    """Edit a step block"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    step_block = ChatbotStepBlock.query.get_or_404(step_block_id)
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            step_block.name = data['name']
            step_block.description = data.get('description', '')
            step_block.is_required = data.get('is_required', True)
            step_block.completion_message = data.get('completion_message', '')
            step_block.next_step_condition = data.get('next_step_condition', {})
            
            db.session.commit()
            return jsonify({'success': True})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    return render_template('admin/edit_step_block.html', flow=flow, step_block=step_block)


@admin_bp.route('/chatbots/<int:flow_id>/step-blocks/<int:step_block_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_step_block(flow_id, step_block_id):
    """Delete a step block"""
    step_block = ChatbotStepBlock.query.get_or_404(step_block_id)
    
    try:
        db.session.delete(step_block)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/chatbots/<int:flow_id>/step-blocks/<int:step_block_id>/questions', methods=['GET', 'POST'])
@login_required
@admin_required
def step_block_questions(flow_id, step_block_id):
    """Manage questions within a step block"""
    flow = ChatbotFlow.query.get_or_404(flow_id)
    step_block = ChatbotStepBlock.query.get_or_404(step_block_id)
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Get the next question order within this step
            last_question = ChatbotQuestion.query.filter_by(step_block_id=step_block_id).order_by(ChatbotQuestion.order_index.desc()).first()
            next_order = (last_question.order_index + 1) if last_question else 1
            
            question = ChatbotQuestion(
                flow_id=flow_id,
                step_block_id=step_block_id,
                question_text=data['question_text'],
                question_type=data['question_type'],
                options=data.get('options'),
                validation_rules=data.get('validation_rules', {}),
                conditional_logic=data.get('conditional_logic', {}),
                cascading_config=data.get('cascading_config', {}),
                branching_logic=data.get('branching_logic', {}),
                order_index=next_order,
                is_required=data.get('is_required', True),
                question_classification=data.get('question_classification', 'essential'),
                field_mapping=data.get('field_mapping', ''),
                placeholder=data.get('placeholder', ''),
                help_text=data.get('help_text', '')
            )
            
            db.session.add(question)
            db.session.commit()
            
            return jsonify({'success': True, 'question_id': question.id})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    questions = ChatbotQuestion.query.filter_by(step_block_id=step_block_id).order_by(ChatbotQuestion.order_index).all()
    return render_template('admin/step_block_questions.html', flow=flow, step_block=step_block, questions=questions)


# Category Management Routes
@admin_bp.route('/api/categories')
@login_required
@admin_required
def get_categories():
    """Get all categories with their subcategories"""
    categories = Category.query.filter_by(is_active=True).order_by(Category.sort_order).all()
    
    result = []
    for category in categories:
        subcategories = Subcategory.query.filter_by(category_id=category.id, is_active=True).order_by(Subcategory.sort_order).all()
        result.append({
            'id': category.id,
            'name': category.name,
            'description': category.description,
            'subcategories': [{'id': sub.id, 'name': sub.name} for sub in subcategories]
        })
    
    return jsonify({'success': True, 'categories': result})


@admin_bp.route('/api/categories/<int:category_id>/subcategories')
@login_required
@admin_required
def get_subcategories(category_id):
    """Get subcategories for a specific category"""
    subcategories = Subcategory.query.filter_by(category_id=category_id, is_active=True).order_by(Subcategory.sort_order).all()
    
    result = [{'id': sub.id, 'name': sub.name} for sub in subcategories]
    return jsonify({'success': True, 'subcategories': result})


# Content Management System Routes
@admin_bp.route('/cms')
@login_required
@admin_required
def cms_dashboard():
    """CMS Dashboard"""
    stats = {
        'total_pages': Page.query.count(),
        'published_pages': Page.query.filter_by(is_published=True).count(),
        'total_blocks': ContentBlock.query.count(),
        'total_menus': NavigationMenu.query.count(),
        'total_settings': SiteSetting.query.count(),
        'total_templates': EmailTemplate.query.count()
    }
    
    recent_pages = Page.query.order_by(Page.updated_at.desc()).limit(5).all()
    recent_blocks = ContentBlock.query.order_by(ContentBlock.updated_at.desc()).limit(5).all()
    
    return render_template('admin/cms_dashboard.html', stats=stats, recent_pages=recent_pages, recent_blocks=recent_blocks)


# Pages Management
@admin_bp.route('/cms/pages')
@login_required
@admin_required
def cms_pages():
    """List all pages"""
    pages = Page.query.order_by(Page.sort_order, Page.title).all()
    return render_template('admin/cms_pages.html', pages=pages)


@admin_bp.route('/cms/pages/create', methods=['GET', 'POST'])
@login_required
@admin_required
def cms_create_page():
    """Create a new page"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            page = Page(
                title=data['title'],
                slug=data['slug'],
                content=data.get('content', ''),
                meta_description=data.get('meta_description', ''),
                meta_keywords=data.get('meta_keywords', ''),
                is_published=data.get('is_published', True),
                is_homepage=data.get('is_homepage', False),
                template=data.get('template', 'page.html'),
                sort_order=data.get('sort_order', 0),
                created_by=current_user.id
            )
            
            db.session.add(page)
            db.session.commit()
            
            return jsonify({'success': True, 'page_id': page.id})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    return render_template('admin/cms_create_page.html')


@admin_bp.route('/cms/pages/<int:page_id>')
@login_required
@admin_required
def cms_view_page(page_id):
    """View a specific page"""
    page = Page.query.get_or_404(page_id)
    return render_template('admin/cms_view_page.html', page=page)


@admin_bp.route('/cms/pages/<int:page_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def cms_edit_page(page_id):
    """Edit a page"""
    page = Page.query.get_or_404(page_id)
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            page.title = data['title']
            page.slug = data['slug']
            page.content = data.get('content', '')
            page.meta_description = data.get('meta_description', '')
            page.meta_keywords = data.get('meta_keywords', '')
            page.is_published = data.get('is_published', True)
            page.is_homepage = data.get('is_homepage', False)
            page.template = data.get('template', 'page.html')
            page.sort_order = data.get('sort_order', 0)
            
            db.session.commit()
            return jsonify({'success': True})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    return render_template('admin/cms_edit_page.html', page=page)


# Content Blocks Management
@admin_bp.route('/cms/blocks')
@login_required
@admin_required
def cms_blocks():
    """List all content blocks"""
    blocks = ContentBlock.query.order_by(ContentBlock.sort_order, ContentBlock.title).all()
    return render_template('admin/cms_blocks.html', blocks=blocks)


@admin_bp.route('/cms/blocks/create', methods=['GET', 'POST'])
@login_required
@admin_required
def cms_create_block():
    """Create a new content block"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            block = ContentBlock(
                page_id=data.get('page_id'),
                title=data.get('title', ''),
                content=data.get('content', ''),
                block_type=data['block_type'],
                block_data=data.get('block_data', {}),
                css_class=data.get('css_class', ''),
                is_published=data.get('is_published', True),
                sort_order=data.get('sort_order', 0),
                created_by=current_user.id
            )
            
            db.session.add(block)
            db.session.commit()
            
            return jsonify({'success': True, 'block_id': block.id})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    pages = Page.query.filter_by(is_published=True).all()
    return render_template('admin/cms_create_block.html', pages=pages)


# Navigation Management
@admin_bp.route('/cms/navigation')
@login_required
@admin_required
def cms_navigation():
    """Manage navigation menus"""
    menus = NavigationMenu.query.order_by(NavigationMenu.name, NavigationMenu.sort_order).all()
    pages = Page.query.filter_by(is_published=True).all()
    return render_template('admin/cms_navigation.html', menus=menus, pages=pages)


@admin_bp.route('/cms/navigation/create', methods=['GET', 'POST'])
@login_required
@admin_required
def cms_create_menu():
    """Create a new menu item"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            menu = NavigationMenu(
                name=data['name'],
                title=data['title'],
                url=data.get('url', ''),
                page_id=data.get('page_id'),
                parent_id=data.get('parent_id'),
                icon=data.get('icon', ''),
                css_class=data.get('css_class', ''),
                is_published=data.get('is_published', True),
                sort_order=data.get('sort_order', 0),
                requires_auth=data.get('requires_auth', False),
                required_roles=data.get('required_roles', []),
                created_by=current_user.id
            )
            
            db.session.add(menu)
            db.session.commit()
            
            return jsonify({'success': True, 'menu_id': menu.id})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    pages = Page.query.filter_by(is_published=True).all()
    return render_template('admin/cms_create_menu.html', pages=pages)


# Site Settings Management
@admin_bp.route('/cms/settings')
@login_required
@admin_required
def cms_settings():
    """Manage site settings"""
    settings_list = SiteSetting.query.order_by(SiteSetting.category, SiteSetting.key).all()
    
    # Convert to dictionary for easier template access
    settings = {}
    for setting in settings_list:
        settings[setting.key] = setting.value
    
    return render_template('admin/cms_settings.html', settings=settings)


@admin_bp.route('/cms/settings/update', methods=['POST'])
@login_required
@admin_required
def cms_update_settings():
    """Update site settings"""
    try:
        data = request.get_json()
        
        for key, value in data.items():
            setting = SiteSetting.query.filter_by(key=key).first()
            if setting:
                setting.value = value
                setting.updated_by = current_user.id
            else:
                setting = SiteSetting(
                    key=key,
                    value=value,
                    updated_by=current_user.id
                )
                db.session.add(setting)
        
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


# Email Templates Management
@admin_bp.route('/cms/email-templates')
@login_required
@admin_required
def cms_email_templates():
    """Manage email templates"""
    templates = EmailTemplate.query.order_by(EmailTemplate.template_type, EmailTemplate.name).all()
    return render_template('admin/cms_email_templates.html', templates=templates)


@admin_bp.route('/cms/email-templates/create', methods=['GET', 'POST'])
@login_required
@admin_required
def cms_create_email_template():
    """Create a new email template"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            template = EmailTemplate(
                name=data['name'],
                subject=data['subject'],
                body_html=data.get('body_html', ''),
                body_text=data.get('body_text', ''),
                template_type=data['template_type'],
                variables=data.get('variables', {}),
                is_active=data.get('is_active', True),
                created_by=current_user.id
            )
            
            db.session.add(template)
            db.session.commit()
            
            return jsonify({'success': True, 'template_id': template.id})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    return render_template('admin/cms_create_email_template.html')


# Additional CMS routes for missing functionality
@admin_bp.route('/cms/pages/<int:page_id>/toggle', methods=['POST'])
@login_required
@admin_required
def cms_toggle_page(page_id):
    """Toggle page published status"""
    page = Page.query.get_or_404(page_id)
    
    try:
        page.is_published = not page.is_published
        db.session.commit()
        return jsonify({'success': True, 'is_published': page.is_published})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/cms/pages/<int:page_id>/delete', methods=['POST'])
@login_required
@admin_required
def cms_delete_page(page_id):
    """Delete a page"""
    page = Page.query.get_or_404(page_id)
    
    try:
        db.session.delete(page)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/cms/blocks/<int:block_id>/toggle', methods=['POST'])
@login_required
@admin_required
def cms_toggle_block(block_id):
    """Toggle block published status"""
    block = ContentBlock.query.get_or_404(block_id)
    
    try:
        block.is_published = not block.is_published
        db.session.commit()
        return jsonify({'success': True, 'is_published': block.is_published})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/cms/blocks/<int:block_id>/delete', methods=['POST'])
@login_required
@admin_required
def cms_delete_block(block_id):
    """Delete a content block"""
    block = ContentBlock.query.get_or_404(block_id)
    
    try:
        db.session.delete(block)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/cms/navigation/<int:menu_id>/toggle', methods=['POST'])
@login_required
@admin_required
def cms_toggle_menu(menu_id):
    """Toggle menu published status"""
    menu = NavigationMenu.query.get_or_404(menu_id)
    
    try:
        menu.is_published = not menu.is_published
        db.session.commit()
        return jsonify({'success': True, 'is_published': menu.is_published})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/cms/navigation/<int:menu_id>/delete', methods=['POST'])
@login_required
@admin_required
def cms_delete_menu(menu_id):
    """Delete a menu item"""
    menu = NavigationMenu.query.get_or_404(menu_id)
    
    try:
        db.session.delete(menu)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


# Page Builder Routes
@admin_bp.route('/cms/pages/<int:page_id>/builder')
@login_required
@admin_required
def cms_page_builder(page_id):
    """Page builder interface"""
    page = Page.query.get_or_404(page_id)
    widgets = PageWidget.query.filter_by(page_id=page_id).order_by(PageWidget.position, PageWidget.sort_order).all()
    
    # Get available widget templates
    widget_templates = WidgetTemplate.query.filter_by(is_system=True).all()
    
    return render_template('admin/cms_page_builder.html', page=page, widgets=widgets, widget_templates=widget_templates)


@admin_bp.route('/cms/pages/<int:page_id>/widgets', methods=['GET', 'POST'])
@login_required
@admin_required
def cms_page_widgets(page_id):
    """Manage page widgets"""
    page = Page.query.get_or_404(page_id)
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            widget = PageWidget(
                page_id=page_id,
                widget_type=data['widget_type'],
                widget_config=data.get('widget_config', {}),
                position=data.get('position', 'main'),
                sort_order=data.get('sort_order', 0),
                is_published=data.get('is_published', True),
                created_by=current_user.id
            )
            
            db.session.add(widget)
            db.session.commit()
            
            return jsonify({'success': True, 'widget_id': widget.id})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    widgets = PageWidget.query.filter_by(page_id=page_id).order_by(PageWidget.position, PageWidget.sort_order).all()
    return jsonify({
        'success': True,
        'widgets': [{
            'id': w.id,
            'widget_type': w.widget_type,
            'widget_config': w.widget_config,
            'position': w.position,
            'sort_order': w.sort_order,
            'is_published': w.is_published
        } for w in widgets]
    })


@admin_bp.route('/cms/pages/<int:page_id>/widgets/<int:widget_id>', methods=['PUT', 'DELETE'])
@login_required
@admin_required
def cms_page_widget(widget_id):
    """Update or delete a page widget"""
    widget = PageWidget.query.get_or_404(widget_id)
    
    if request.method == 'PUT':
        try:
            data = request.get_json()
            
            widget.widget_type = data.get('widget_type', widget.widget_type)
            widget.widget_config = data.get('widget_config', widget.widget_config)
            widget.position = data.get('position', widget.position)
            widget.sort_order = data.get('sort_order', widget.sort_order)
            widget.is_published = data.get('is_published', widget.is_published)
            
            db.session.commit()
            return jsonify({'success': True})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})
    
    elif request.method == 'DELETE':
        try:
            db.session.delete(widget)
            db.session.commit()
            return jsonify({'success': True})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/cms/widget-templates')
@login_required
@admin_required
def cms_widget_templates():
    """Get available widget templates"""
    templates = WidgetTemplate.query.filter_by(is_system=True).all()
    
    return jsonify({
        'success': True,
        'templates': [{
            'id': t.id,
            'name': t.name,
            'widget_type': t.widget_type,
            'template_config': t.template_config,
            'description': t.description,
            'category': t.category
        } for t in templates]
    })


@admin_bp.route('/cms/pages/<int:page_id>/preview')
@login_required
@admin_required
def cms_page_preview(page_id):
    """Preview a page with widgets"""
    page = Page.query.get_or_404(page_id)
    widgets = PageWidget.query.filter_by(page_id=page_id, is_published=True).order_by(PageWidget.position, PageWidget.sort_order).all()
    
    return render_template('admin/cms_page_preview.html', page=page, widgets=widgets)

# ============================================================================
# DYNAMIC MANAGEMENT SYSTEM ROUTES
# ============================================================================

@admin_bp.route('/dynamic/buttons')
@login_required
@admin_required
def dynamic_buttons():
    """Manage dashboard buttons"""
    buttons = ButtonConfiguration.query.order_by(ButtonConfiguration.order_index, ButtonConfiguration.created_at).all()
    return render_template('admin/dynamic_buttons.html', buttons=buttons)

@admin_bp.route('/dynamic/buttons/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_button():
    """Create a new dashboard button"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        button_key = data.get('button_key')
        button_label = data.get('button_label')
        button_description = data.get('button_description', '')
        target_type = data.get('target_type')
        target_value = data.get('target_value')
        icon_class = data.get('icon_class', 'fas fa-plus')
        button_color = data.get('button_color', 'primary')
        order_index = data.get('order_index', 0)
        
        if not button_key or not button_label or not target_type:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Button key, label, and target type are required'})
            flash('Button key, label, and target type are required', 'error')
            return render_template('admin/create_button.html')
        
        # Check if button key already exists
        existing_button = ButtonConfiguration.query.filter_by(button_key=button_key).first()
        if existing_button:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Button key already exists'})
            flash('Button key already exists', 'error')
            return render_template('admin/create_button.html')
        
        button = ButtonConfiguration(
            button_key=button_key,
            button_label=button_label,
            button_description=button_description,
            target_type=target_type,
            target_value=target_value,
            icon_class=icon_class,
            button_color=button_color,
            order_index=order_index,
            created_by=current_user.id
        )
        
        db.session.add(button)
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Button created successfully',
                'button_id': button.id
            })
        
        flash('Button created successfully', 'success')
        return redirect(url_for('admin.dynamic_buttons'))
    
    return render_template('admin/create_button.html')

@admin_bp.route('/dynamic/buttons/<int:button_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_button(button_id):
    """Edit a dashboard button"""
    button = ButtonConfiguration.query.get_or_404(button_id)
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        # Handle button_key change with uniqueness validation
        new_button_key = data.get('button_key', button.button_key)
        if new_button_key and new_button_key != button.button_key:
            existing = ButtonConfiguration.query.filter(
                ButtonConfiguration.button_key == new_button_key,
                ButtonConfiguration.id != button.id
            ).first()
            if existing:
                if request.is_json:
                    return jsonify({'success': False, 'message': 'Button key already exists'})
                flash('Button key already exists', 'error')
                return render_template('admin/edit_button.html', button=button)
            button.button_key = new_button_key
        
        button.button_label = data.get('button_label', button.button_label)
        button.button_description = data.get('button_description', button.button_description)
        button.target_type = data.get('target_type', button.target_type)
        button.target_value = data.get('target_value', button.target_value)
        button.icon_class = data.get('icon_class', button.icon_class)
        button.button_color = data.get('button_color', button.button_color)
        button.is_active = data.get('is_active', button.is_active)
        button.is_visible = data.get('is_visible', button.is_visible)
        button.order_index = data.get('order_index', button.order_index)
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Button updated successfully'})
        
        flash('Button updated successfully', 'success')
        return redirect(url_for('admin.dynamic_buttons'))
    
    return render_template('admin/edit_button.html', button=button)

@admin_bp.route('/dynamic/buttons/<int:button_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_button(button_id):
    """Delete a dashboard button"""
    button = ButtonConfiguration.query.get_or_404(button_id)
    
    db.session.delete(button)
    db.session.commit()
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Button deleted successfully'})
    
    flash('Button deleted successfully', 'success')
    return redirect(url_for('admin.dynamic_buttons'))

@admin_bp.route('/dynamic/item-types')
@login_required
@admin_required
def dynamic_item_types():
    """Manage item types"""
    item_types = ItemType.query.order_by(ItemType.order_index, ItemType.created_at).all()
    chatbots = ChatbotFlow.query.filter_by(is_active=True).all()
    banks = Bank.query.filter_by(is_active=True).all()
    
    return render_template('admin/dynamic_item_types.html', 
                         item_types=item_types, 
                         chatbots=chatbots, 
                         banks=banks)

@admin_bp.route('/dynamic/item-types/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_item_type():
    """Create a new item type"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        name = data.get('name')
        display_name = data.get('display_name')
        description = data.get('description', '')
        icon_class = data.get('icon_class', 'fas fa-box')
        button_color = data.get('button_color', 'primary')
        border_color = data.get('border_color', '#007bff')
        text_color = data.get('text_color', '#007bff')
        chatbot_id = data.get('chatbot_id')
        bank_id = data.get('bank_id')
        completion_action = data.get('completion_action', 'message')
        completion_message = data.get('completion_message', 'Item created successfully!')
        redirect_url = data.get('redirect_url', '')
        order_index = data.get('order_index', 0)
        
        if not name or not display_name:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Name and display name are required'})
            flash('Name and display name are required', 'error')
            return render_template('admin/create_item_type.html')
        
        # Check if name already exists
        existing_item_type = ItemType.query.filter_by(name=name).first()
        if existing_item_type:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Item type name already exists'})
            flash('Item type name already exists', 'error')
            return render_template('admin/create_item_type.html')
        
        item_type = ItemType(
            name=name,
            display_name=display_name,
            description=description,
            icon_class=icon_class,
            button_color=button_color,
            border_color=border_color,
            text_color=text_color,
            chatbot_id=int(chatbot_id) if chatbot_id is not None and chatbot_id != '' else None,
            bank_id=int(bank_id) if bank_id is not None and bank_id != '' else None,
            completion_action=completion_action,
            completion_message=completion_message,
            redirect_url=redirect_url,
            order_index=order_index,
            created_by=current_user.id
        )
        
        db.session.add(item_type)
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Item type created successfully',
                'item_type_id': item_type.id
            })
        
        flash('Item type created successfully', 'success')
        return redirect(url_for('admin.dynamic_item_types'))
    
    chatbots = ChatbotFlow.query.filter_by(is_active=True).all()
    banks = Bank.query.filter_by(is_active=True).all()
    return render_template('admin/create_item_type.html', chatbots=chatbots, banks=banks)

@admin_bp.route('/dynamic/item-types/<int:item_type_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_item_type(item_type_id):
    """Edit an item type"""
    item_type = ItemType.query.get_or_404(item_type_id)
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        item_type.display_name = data.get('display_name', item_type.display_name)
        item_type.description = data.get('description', item_type.description)
        item_type.icon_class = data.get('icon_class', item_type.icon_class)
        item_type.button_color = data.get('button_color', item_type.button_color)
        item_type.border_color = data.get('border_color', item_type.border_color)
        item_type.text_color = data.get('text_color', item_type.text_color)
        chatbot_id = data.get('chatbot_id')
        item_type.chatbot_id = int(chatbot_id) if chatbot_id is not None and chatbot_id != '' else None
        bank_id = data.get('bank_id')
        item_type.bank_id = int(bank_id) if bank_id is not None and bank_id != '' else None
        item_type.completion_action = data.get('completion_action', item_type.completion_action)
        item_type.completion_message = data.get('completion_message', item_type.completion_message)
        item_type.redirect_url = data.get('redirect_url', item_type.redirect_url)
        item_type.is_active = data.get('is_active', item_type.is_active)
        item_type.is_visible = data.get('is_visible', item_type.is_visible)
        item_type.order_index = data.get('order_index', item_type.order_index)
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Item type updated successfully'})
        
        flash('Item type updated successfully', 'success')
        return redirect(url_for('admin.dynamic_item_types'))
    
    chatbots = ChatbotFlow.query.filter_by(is_active=True).all()
    banks = Bank.query.filter_by(is_active=True).all()
    return render_template('admin/edit_item_type.html', 
                         item_type=item_type, 
                         chatbots=chatbots, 
                         banks=banks)

@admin_bp.route('/dynamic/item-types/<int:item_type_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_item_type(item_type_id):
    """Delete an item type"""
    item_type = ItemType.query.get_or_404(item_type_id)
    
    db.session.delete(item_type)
    db.session.commit()
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Item type deleted successfully'})
    
    flash('Item type deleted successfully', 'success')
    return redirect(url_for('admin.dynamic_item_types'))

@admin_bp.route('/dynamic/data-mappings')
@login_required
@admin_required
def dynamic_data_mappings():
    """Manage data storage mappings"""
    mappings = DataStorageMapping.query.order_by(DataStorageMapping.created_at.desc()).all()
    item_types = ItemType.query.filter_by(is_active=True).all()
    chatbots = ChatbotFlow.query.filter_by(is_active=True).all()
    banks = Bank.query.filter_by(is_active=True).all()
    
    return render_template('admin/dynamic_data_mappings.html', 
                         mappings=mappings,
                         item_types=item_types,
                         chatbots=chatbots,
                         banks=banks)

@admin_bp.route('/dynamic/data-mappings/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_data_mapping():
    """Create a new data storage mapping"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        item_type_id = data.get('item_type_id')
        chatbot_id = data.get('chatbot_id')
        bank_id = data.get('bank_id')
        storage_config = data.get('storage_config', {})
        data_mapping = data.get('data_mapping', {})
        validation_rules = data.get('validation_rules', {})
        
        if not item_type_id or not chatbot_id or not bank_id:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Item type, chatbot, and bank are required'})
            flash('Item type, chatbot, and bank are required', 'error')
            return render_template('admin/create_data_mapping.html')
        
        # Check if mapping already exists
        existing_mapping = DataStorageMapping.query.filter_by(
            item_type_id=item_type_id,
            chatbot_id=chatbot_id,
            bank_id=bank_id
        ).first()
        
        if existing_mapping:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Mapping already exists for this combination'})
            flash('Mapping already exists for this combination', 'error')
            return render_template('admin/create_data_mapping.html')
        
        mapping = DataStorageMapping(
            item_type_id=item_type_id,
            chatbot_id=chatbot_id,
            bank_id=bank_id,
            storage_config=storage_config,
            data_mapping=data_mapping,
            validation_rules=validation_rules,
            created_by=current_user.id
        )
        
        db.session.add(mapping)
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Data mapping created successfully',
                'mapping_id': mapping.id
            })
        
        flash('Data mapping created successfully', 'success')
        return redirect(url_for('admin.dynamic_data_mappings'))
    
    item_types = ItemType.query.filter_by(is_active=True).all()
    chatbots = ChatbotFlow.query.filter_by(is_active=True).all()
    banks = Bank.query.filter_by(is_active=True).all()
    
    return render_template('admin/create_data_mapping.html', 
                         item_types=item_types,
                         chatbots=chatbots,
                         banks=banks)

@admin_bp.route('/dynamic/data-mappings/<int:mapping_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_data_mapping(mapping_id):
    """Delete a data storage mapping"""
    mapping = DataStorageMapping.query.get_or_404(mapping_id)
    
    db.session.delete(mapping)
    db.session.commit()
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Data mapping deleted successfully'})
    
    flash('Data mapping deleted successfully', 'success')
    return redirect(url_for('admin.dynamic_data_mappings'))

@admin_bp.route('/dynamic/completions')
@login_required
@admin_required
def dynamic_completions():
    """View chatbot completions and data flow"""
    completions = ChatbotCompletion.query.order_by(ChatbotCompletion.completed_at.desc()).limit(100).all()
    return render_template('admin/dynamic_completions.html', completions=completions)

# ============================================================================
# ADVANCED ANALYTICS & MONITORING ROUTES
# ============================================================================

@admin_bp.route('/analytics/advanced')
@login_required
@admin_required
def advanced_analytics():
    """Advanced analytics dashboard"""
    return render_template('admin/advanced_analytics.html')

@admin_bp.route('/analytics/realtime')
@login_required
@admin_required
def realtime_analytics():
    """Get real-time analytics data"""
    try:
        from utils.analytics import PerformanceMonitoringService
        
        # Get system metrics
        metrics = PerformanceMonitoringService.get_system_metrics()
        
        # Get recent health record
        health = SystemHealth.query.order_by(SystemHealth.recorded_at.desc()).first()
        
        # Get active users (last 5 minutes)
        from datetime import datetime, timedelta
        five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
        active_users = AnalyticsEvent.query.filter(
            AnalyticsEvent.created_at >= five_minutes_ago
        ).with_entities(AnalyticsEvent.user_id).distinct().count()
        
        # Get average response time
        recent_metrics = PerformanceMetric.query.filter(
            PerformanceMetric.metric_name == 'response_time',
            PerformanceMetric.recorded_at >= five_minutes_ago
        ).all()
        
        avg_response_time = 0
        if recent_metrics:
            avg_response_time = sum(m.metric_value for m in recent_metrics) / len(recent_metrics)
        
        # Get error rate
        recent_errors = ErrorLog.query.filter(
            ErrorLog.occurred_at >= five_minutes_ago
        ).count()
        
        recent_events = AnalyticsEvent.query.filter(
            AnalyticsEvent.created_at >= five_minutes_ago
        ).count()
        
        error_rate = (recent_errors / recent_events * 100) if recent_events > 0 else 0
        
        return jsonify({
            'success': True,
            'active_users': active_users,
            'health_score': health.overall_score if health else 100,
            'response_time': round(avg_response_time, 2),
            'error_rate': round(error_rate, 2),
            'cpu_usage': metrics['cpu_usage'] if metrics else 0,
            'memory_usage': metrics['memory_usage'] if metrics else 0,
            'disk_usage': metrics['disk_usage'] if metrics else 0
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/analytics/ab-tests')
@login_required
@admin_required
def ab_tests():
    """Get A/B tests data"""
    try:
        tests = ABTest.query.order_by(ABTest.created_at.desc()).all()
        
        tests_data = []
        for test in tests:
            # Get assignment count
            assignments = ABTestAssignment.query.filter_by(test_id=test.id).count()
            
            tests_data.append({
                'id': test.id,
                'name': test.name,
                'description': test.description,
                'test_type': test.test_type,
                'target_metric': test.target_metric,
                'status': test.status,
                'assignments': assignments,
                'created_at': test.created_at.isoformat(),
                'results': test.results
            })
        
        return jsonify({'success': True, 'tests': tests_data})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/analytics/ab-tests/create', methods=['POST'])
@login_required
@admin_required
def create_ab_test():
    """Create a new A/B test"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'test_type', 'target_metric', 'variants', 'traffic_split']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'message': f'Missing required field: {field}'}), 400
        
        # Validate traffic split adds up to 100
        total_traffic = sum(data['traffic_split'].values())
        if total_traffic != 100:
            return jsonify({'success': False, 'message': 'Traffic split must add up to 100%'}), 400
        
        # Create test
        test = ABTest(
            name=data['name'],
            description=data.get('description', ''),
            test_type=data['test_type'],
            target_metric=data['target_metric'],
            variants=data['variants'],
            traffic_split=data['traffic_split'],
            created_by=current_user.id,
            status='draft'
        )
        
        db.session.add(test)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'A/B test created successfully',
            'test_id': test.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/analytics/errors')
@login_required
@admin_required
def error_logs():
    """Get error logs"""
    try:
        errors = ErrorLog.query.order_by(ErrorLog.occurred_at.desc()).limit(50).all()
        
        errors_data = []
        for error in errors:
            errors_data.append({
                'id': error.id,
                'error_type': error.error_type,
                'error_message': error.error_message,
                'user_id': error.user_id,
                'status': error.status,
                'occurred_at': error.occurred_at.isoformat(),
                'endpoint': error.endpoint,
                'method': error.method
            })
        
        return jsonify({'success': True, 'errors': errors_data})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@admin_bp.route('/analytics/performance')
@login_required
@admin_required
def performance_metrics():
    """Get performance metrics"""
    try:
        # Get query parameters
        metric_name = request.args.get('metric_name')
        hours = int(request.args.get('hours', 24))
        
        from datetime import datetime, timedelta
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Build query
        query = PerformanceMetric.query.filter(PerformanceMetric.recorded_at >= start_time)
        
        if metric_name:
            query = query.filter_by(metric_name=metric_name)
        
        metrics = query.order_by(PerformanceMetric.recorded_at.asc()).all()
        
        metrics_data = []
        for metric in metrics:
            metrics_data.append({
                'id': metric.id,
                'metric_name': metric.metric_name,
                'metric_value': metric.metric_value,
                'metric_unit': metric.metric_unit,
                'recorded_at': metric.recorded_at.isoformat(),
                'endpoint': metric.endpoint
            })
        
        return jsonify({'success': True, 'metrics': metrics_data})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/analytics/health')
@login_required
@admin_required
def system_health():
    """System health dashboard"""
    return render_template('admin/system_health.html')

@admin_bp.route('/analytics/health/data')
@login_required
@admin_required
def system_health_data():
    """Get system health data"""
    try:
        from utils.analytics import PerformanceMonitoringService
        
        # Record current health
        health = PerformanceMonitoringService.record_system_health()
        
        # Get recent health records
        from datetime import datetime, timedelta
        recent_health = SystemHealth.query.filter(
            SystemHealth.recorded_at >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(SystemHealth.recorded_at.desc()).limit(24).all()
        
        health_data = []
        for h in recent_health:
            health_data.append({
                'id': h.id,
                'health_status': h.health_status,
                'overall_score': h.overall_score,
                'response_time_avg': h.response_time_avg,
                'error_rate': h.error_rate,
                'memory_usage': h.memory_usage,
                'cpu_usage': h.cpu_usage,
                'active_users': h.active_users,
                'recorded_at': h.recorded_at.isoformat()
            })
        
        return jsonify({'success': True, 'health': health_data})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/analytics/track', methods=['POST'])
def track_analytics():
    """Track analytics events from frontend"""
    try:
        from utils.analytics import AnalyticsService
        
        data = request.get_json()
        
        # Validate required fields
        if not data or 'event_type' not in data or 'event_name' not in data:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Track the event
        event_id = AnalyticsService.track_event(
            event_type=data['event_type'],
            event_name=data['event_name'],
            properties=data.get('properties', {}),
            user_id=data.get('user_id'),
            page_url=data.get('page_url'),
            referrer=data.get('referrer'),
            user_agent=request.user_agent.string,
            ip_address=request.remote_addr
        )
        
        return jsonify({
            'success': True,
            'event_id': event_id
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/analytics/events')
@login_required
@admin_required
def analytics_events():
    """View analytics events"""
    try:
        # Get query parameters
        event_type = request.args.get('event_type')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = AnalyticsEvent.query
        
        if event_type:
            query = query.filter_by(event_type=event_type)
        
        events = query.order_by(AnalyticsEvent.created_at.desc()).offset(offset).limit(limit).all()
        
        events_data = []
        for event in events:
            events_data.append({
                'id': event.id,
                'event_type': event.event_type,
                'event_name': event.event_name,
                'user_id': event.user_id,
                'properties': event.properties,
                'created_at': event.created_at.isoformat(),
                'page_url': event.page_url
            })
        
        return render_template('admin/analytics_events.html', events=events_data)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# COMPREHENSIVE REPORTING ROUTES
# ============================================================================

@admin_bp.route('/reports')
@login_required
@admin_required
def comprehensive_reports():
    """Comprehensive reporting dashboard"""
    return render_template('admin/comprehensive_reports.html')

@admin_bp.route('/reports/overview')
@login_required
@admin_required
def overview_report():
    """Overview report dashboard"""
    return render_template('admin/overview_report.html')

@admin_bp.route('/reports/overview/data')
@login_required
@admin_required
def overview_report_data():
    """Get overview report data"""
    try:
        from datetime import datetime, timedelta
        
        # Get date range from query params
        days = int(request.args.get('days', 30))
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Total users
        total_users = User.query.count()
        
        # Total deals
        total_deals = Deal.query.count()
        
        # Total revenue
        total_revenue = db.session.query(db.func.sum(Earning.amount))\
            .filter(Earning.status == 'paid').scalar() or 0
        
        # Active users (last 24 hours)
        active_users = AnalyticsEvent.query.filter(
            AnalyticsEvent.created_at >= end_date - timedelta(hours=24)
        ).with_entities(AnalyticsEvent.user_id).distinct().count()
        
        # User growth over time
        user_growth = []
        for i in range(days):
            date = start_date + timedelta(days=i)
            next_date = date + timedelta(days=1)
            
            count = User.query.filter(
                User.created_at >= date,
                User.created_at < next_date
            ).count()
            
            user_growth.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        # User distribution by role
        user_distribution = {}
        for role in Role.query.all():
            count = User.query.join(User.roles).filter(Role.id == role.id).count()
            if count > 0:
                user_distribution[role.name] = count
        
        # Performance metrics
        recent_metrics = PerformanceMetric.query.filter(
            PerformanceMetric.recorded_at >= start_date
        ).all()
        
        performance_metrics = []
        metric_groups = {}
        for metric in recent_metrics:
            if metric.metric_name not in metric_groups:
                metric_groups[metric.metric_name] = []
            metric_groups[metric.metric_name].append(metric.metric_value)
        
        for metric_name, values in metric_groups.items():
            performance_metrics.append({
                'metric': metric_name,
                'value': sum(values) / len(values)  # Average value
            })
        
        # Error trends
        error_trends = []
        for i in range(days):
            date = start_date + timedelta(days=i)
            next_date = date + timedelta(days=1)
            
            count = ErrorLog.query.filter(
                ErrorLog.occurred_at >= date,
                ErrorLog.occurred_at < next_date
            ).count()
            
            error_trends.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        
        return jsonify({
            'success': True,
            'total_users': total_users,
            'total_deals': total_deals,
            'total_revenue': total_revenue,
            'active_users': active_users,
            'user_growth': user_growth,
            'user_distribution': user_distribution,
            'performance_metrics': performance_metrics,
            'error_trends': error_trends
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/reports/user-activity')
@login_required
@admin_required
def user_activity_report():
    """User activity report dashboard"""
    return render_template('admin/user_activity_report.html')

@admin_bp.route('/reports/user-activity/data')
@login_required
@admin_required
def user_activity_report_data():
    """Get user activity report data"""
    try:
        from datetime import datetime, timedelta
        
        # Get active users with their activity data
        users = User.query.limit(50).all()
        users_data = []
        
        for user in users:
            # Get last activity
            last_activity = AnalyticsEvent.query.filter_by(user_id=user.id)\
                .order_by(AnalyticsEvent.created_at.desc()).first()
            
            # Get total sessions (unique session IDs)
            total_sessions = AnalyticsEvent.query.filter_by(user_id=user.id)\
                .with_entities(AnalyticsEvent.session_id).distinct().count()
            
            # Get page views
            page_views = AnalyticsEvent.query.filter_by(
                user_id=user.id, 
                event_type='page_view'
            ).count()
            
            # Get total actions
            actions = AnalyticsEvent.query.filter_by(user_id=user.id).count()
            
            # Determine status
            status = 'active' if last_activity and last_activity.created_at > datetime.utcnow() - timedelta(hours=24) else 'inactive'
            
            users_data.append({
                'username': user.username,
                'last_activity': last_activity.created_at.isoformat() if last_activity else None,
                'total_sessions': total_sessions,
                'page_views': page_views,
                'actions': actions,
                'status': status
            })
        
        return jsonify({
            'success': True,
            'users': users_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/reports/system-performance')
@login_required
@admin_required
def system_performance_report():
    """Get system performance report data"""
    try:
        from datetime import datetime, timedelta
        from utils.analytics import PerformanceMonitoringService
        
        # Get current system metrics
        current_metrics = PerformanceMonitoringService.get_system_metrics()
        
        # Get response time trends (last 24 hours)
        response_times = PerformanceMetric.query.filter(
            PerformanceMetric.metric_name == 'response_time',
            PerformanceMetric.recorded_at >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(PerformanceMetric.recorded_at.asc()).all()
        
        response_time_data = []
        for metric in response_times:
            response_time_data.append({
                'time': metric.recorded_at.strftime('%H:%M'),
                'value': metric.metric_value
            })
        
        return jsonify({
            'success': True,
            'response_times': response_time_data,
            'cpu_usage': current_metrics['cpu_usage'] if current_metrics else 0,
            'memory_usage': current_metrics['memory_usage'] if current_metrics else 0,
            'disk_usage': current_metrics['disk_usage'] if current_metrics else 0
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/reports/business-metrics')
@login_required
@admin_required
def business_metrics_report():
    """Get business metrics report data"""
    try:
        from datetime import datetime, timedelta
        
        # Calculate conversion rate (simplified)
        total_visitors = AnalyticsEvent.query.filter_by(event_type='page_view').count()
        total_conversions = AnalyticsEvent.query.filter_by(event_type='chatbot_completion').count()
        conversion_rate = (total_conversions / total_visitors * 100) if total_visitors > 0 else 0
        
        # Calculate retention rate (simplified)
        # Users who came back within 7 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        new_users = User.query.filter(User.created_at >= thirty_days_ago).count()
        
        returning_users = 0
        for user in User.query.filter(User.created_at >= thirty_days_ago).all():
            # Check if user had activity after first day
            first_day = user.created_at + timedelta(days=1)
            if AnalyticsEvent.query.filter(
                AnalyticsEvent.user_id == user.id,
                AnalyticsEvent.created_at >= first_day
            ).first():
                returning_users += 1
        
        retention_rate = (returning_users / new_users * 100) if new_users > 0 else 0
        
        # Calculate average session time (simplified)
        sessions = AnalyticsEvent.query.with_entities(AnalyticsEvent.session_id).distinct().all()
        total_session_time = 0
        valid_sessions = 0
        
        for (session_id,) in sessions:
            session_events = AnalyticsEvent.query.filter_by(session_id=session_id)\
                .order_by(AnalyticsEvent.created_at.asc()).all()
            
            if len(session_events) > 1:
                session_duration = (session_events[-1].created_at - session_events[0].created_at).total_seconds() / 60
                total_session_time += session_duration
                valid_sessions += 1
        
        avg_session_time = total_session_time / valid_sessions if valid_sessions > 0 else 0
        
        return jsonify({
            'success': True,
            'conversion_rate': round(conversion_rate, 2),
            'retention_rate': round(retention_rate, 2),
            'avg_session_time': round(avg_session_time, 2)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/reports/security-events')
@login_required
@admin_required
def security_events_report():
    """Get security events report data"""
    try:
        # Get recent security events
        events = ErrorLog.query.filter(
            ErrorLog.error_type.in_(['ValueError', 'KeyError', 'DatabaseError', 'TimeoutError', 'ConnectionError'])
        ).order_by(ErrorLog.occurred_at.desc()).limit(50).all()
        
        events_data = []
        for event in events:
            # Determine severity based on error type
            severity = 'high' if event.error_type in ['DatabaseError', 'ConnectionError'] else 'medium'
            
            events_data.append({
                'timestamp': event.occurred_at.isoformat(),
                'event_type': event.error_type,
                'severity': severity,
                'ip_address': event.ip_address,
                'user': event.user_id,
                'description': event.error_message,
                'status': event.status
            })
        
        return jsonify({
            'success': True,
            'events': events_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/reports/ab-test-results')
@login_required
@admin_required
def ab_test_results_report():
    """Get A/B test results report data"""
    try:
        # Get all A/B tests with their results
        tests = ABTest.query.all()
        
        tests_data = []
        for test in tests:
            # Get participant count
            participants = ABTestAssignment.query.filter_by(test_id=test.id).count()
            
            tests_data.append({
                'id': test.id,
                'name': test.name,
                'description': test.description,
                'status': test.status,
                'participants': participants,
                'results': test.results or {}
            })
        
        return jsonify({
            'success': True,
            'tests': tests_data
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Data Collection and Bank Management Routes

@admin_bp.route('/data-collectors')
@admin_required
def data_collectors():
    """Data collectors management page"""
    collectors = DataCollector.query.all()
    return render_template('admin/data_collectors.html', collectors=collectors)

@admin_bp.route('/data-collectors/create', methods=['GET', 'POST'])
@admin_required
def create_data_collector():
    """Create advanced data collector"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Build filter rules with all collector configuration
            filter_rules = {
                'url': data.get('url'),
                'selectors': data.get('selectors', {}),
                'use_selenium': data.get('use_selenium', False),
                'chatbot_id': data.get('chatbot_id'),
                'field_mapping': data.get('field_mapping', {}),
                'schedule_type': data.get('schedule_type', 'manual'),
                'schedule_value': data.get('schedule_value', ''),
                'auto_approve': data.get('auto_approve', False)
            }
            
            collector = DataCollector(
                name=data['name'],
                description=data['description'],
                data_type=data['data_type'],
                subcategory=data.get('subcategory'),
                filter_rules=filter_rules,
                created_by=current_user.id
            )
            
            db.session.add(collector)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Advanced data collector created successfully!'})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    # Get available chatbots for the form
    from models import ChatbotFlow
    chatbots = ChatbotFlow.query.filter_by(is_active=True).all()
    
    return render_template('admin/create_data_collector.html', chatbots=chatbots)

@admin_bp.route('/data-collectors/test', methods=['POST'])
@admin_required
def test_collector():
    """Test a collector configuration"""
    try:
        data = request.get_json()
        
        from utils.advanced_data_collector import advanced_collector
        
        result = advanced_collector.test_collector({
            'url': data.get('url'),
            'selectors': data.get('selectors', {}),
            'use_selenium': data.get('use_selenium', False)
        })
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@admin_bp.route('/data-collectors/<int:collector_id>/test', methods=['POST'])
@admin_required
def test_individual_collector(collector_id):
    """Test a specific collector"""
    try:
        from utils.advanced_data_collector import advanced_collector
        
        result = advanced_collector.test_collector(collector_id)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@admin_bp.route('/data-collectors/<int:collector_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_data_collector(collector_id):
    """Edit a data collector"""
    collector = DataCollector.query.get_or_404(collector_id)
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Update collector fields
            collector.name = data.get('name', collector.name)
            collector.description = data.get('description', collector.description)
            collector.data_type = data.get('data_type', collector.data_type)
            collector.subcategory = data.get('subcategory', collector.subcategory)
            
            # Update filter rules
            if 'filter_rules' in data:
                collector.filter_rules = data['filter_rules']
            
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Collector updated successfully!'})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    # GET request - show edit form
    from models import ChatbotFlow
    chatbots = ChatbotFlow.query.filter_by(is_active=True).all()
    
    return render_template('admin/edit_data_collector.html', collector=collector, chatbots=chatbots)

@admin_bp.route('/data-collectors/<int:collector_id>/run', methods=['POST'])
@admin_required
def run_collector(collector_id):
    """Run a specific collector manually"""
    try:
        from utils.advanced_data_collector import advanced_collector
        
        success = advanced_collector.run_collector(collector_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Collector run completed successfully'})
        else:
            return jsonify({'success': False, 'message': 'Collector run failed'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/data-collectors/<int:collector_id>/toggle', methods=['POST'])
@admin_required
def toggle_collector(collector_id):
    """Toggle collector active status"""
    try:
        collector = DataCollector.query.get_or_404(collector_id)
        collector.is_active = not collector.is_active
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Collector {"activated" if collector.is_active else "deactivated"} successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/data-collectors/<int:collector_id>/delete', methods=['POST'])
@admin_required
def delete_collector(collector_id):
    """Delete collector"""
    try:
        collector = DataCollector.query.get_or_404(collector_id)
        db.session.delete(collector)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Collector deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/data-collectors/monitoring')
@admin_required
def collector_monitoring():
    """Collector monitoring dashboard"""
    collectors = DataCollector.query.all()
    active_collectors = DataCollector.query.filter_by(is_active=True).count()
    
    total_success_count = sum(c.success_count for c in collectors)
    total_error_count = sum(c.error_count for c in collectors)
    
    return render_template('admin/collector_monitoring.html', 
                         collectors=collectors,
                         active_collectors=active_collectors,
                         total_success_count=total_success_count,
                         total_error_count=total_error_count)

@admin_bp.route('/data-collectors/run-all', methods=['POST'])
@admin_required
def run_all_collectors():
    """Run all active collectors"""
    try:
        from utils.advanced_data_collector import advanced_collector
        
        active_collectors = DataCollector.query.filter_by(is_active=True).all()
        results = []
        
        for collector in active_collectors:
            success = advanced_collector.run_collector(collector.id)
            results.append({
                'collector_id': collector.id,
                'name': collector.name,
                'success': success
            })
        
        success_count = sum(1 for r in results if r['success'])
        
        return jsonify({
            'success': True, 
            'message': f'Started {len(active_collectors)} collectors, {success_count} completed successfully',
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/data-collectors/<int:collector_id>/logs')
@admin_required
def collector_logs(collector_id):
    """Get collector logs"""
    try:
        # This would typically read from a log file or database
        # For now, return sample logs
        logs = [
            {
                'timestamp': '2025-01-22 13:30:00',
                'level': 'INFO',
                'message': 'Collector started successfully'
            },
            {
                'timestamp': '2025-01-22 13:30:05',
                'level': 'INFO',
                'message': 'Scraped 15 items from website'
            },
            {
                'timestamp': '2025-01-22 13:30:10',
                'level': 'INFO',
                'message': 'Successfully created 15 items in database'
            }
        ]
        
        return jsonify({'success': True, 'logs': logs})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/data-collectors/<int:collector_id>/data')
@admin_required
def collector_data(collector_id):
    """View data collected by a specific collector"""
    try:
        collector = DataCollector.query.get_or_404(collector_id)
        
        # Get chatbot responses from this collector
        chatbot_responses = ChatbotResponse.query.filter(
            ChatbotResponse.session_id.like(f'collector_{collector_id}_%')
        ).order_by(ChatbotResponse.created_at.desc()).all()
        
        # Get items created by this collector, filtered by subcategory
        if collector.data_type == 'items' and collector.subcategory:
            from models import ItemType
            item_type = ItemType.query.filter_by(name=collector.subcategory).first()
            if item_type:
                collected_items = Item.query.filter(
                    Item.item_type_id == item_type.id
                ).order_by(Item.created_at.desc()).all()
            else:
                collected_items = []
        else:
            collected_items = Item.query.filter(
                Item.creator_name.like(f'%{collector.name}%')
            ).order_by(Item.created_at.desc()).all()
        
        # Get organizations created by this collector, filtered by subcategory
        if collector.data_type == 'organizations' and collector.subcategory:
            from models import OrganizationType
            org_type = OrganizationType.query.filter_by(name=collector.subcategory).first()
            if org_type:
                collected_organizations = Organization.query.filter(
                    Organization.organization_type_id == org_type.id
                ).order_by(Organization.created_at.desc()).all()
            else:
                collected_organizations = []
        else:
            collected_organizations = Organization.query.filter(
                Organization.created_by == collector.created_by
            ).order_by(Organization.created_at.desc()).all()
        
        # Get recent test results (simulated)
        recent_tests = []
        if collector.last_run:
            recent_tests.append({
                'timestamp': collector.last_run,
                'status': 'success' if collector.success_count > collector.error_count else 'error',
                'items_found': collector.success_count,
                'message': f'Last run found {collector.success_count} items'
            })
        
        return render_template('admin/collector_data.html', 
                             collector=collector,
                             chatbot_responses=chatbot_responses,
                             collected_items=collected_items,
                             collected_organizations=collected_organizations,
                             recent_tests=recent_tests)
        
    except Exception as e:
        flash(f'Error loading collector data: {str(e)}', 'error')
        return redirect(url_for('admin.data_collectors'))

@admin_bp.route('/banks/api/list')
@admin_required
def banks_api_list():
    """API endpoint to get list of banks for dropdowns"""
    try:
        banks = Bank.query.filter_by(is_active=True).all()
        banks_data = []
        for bank in banks:
            banks_data.append({
                'id': bank.id,
                'name': bank.name,
                'bank_type': bank.bank_type,
                'description': bank.description
            })
        
        return jsonify({
            'success': True,
            'banks': banks_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })

@admin_bp.route('/data-collectors/<int:collector_id>/add-to-bank', methods=['POST'])
@admin_required
def add_collector_data_to_bank(collector_id):
    """Add collected data from a collector to a bank"""
    try:
        from models import Bank, Item, Organization, BankContent
        
        collector = DataCollector.query.get_or_404(collector_id)
        bank_id = request.form.get('bank_id')
        
        if not bank_id:
            return jsonify({'success': False, 'message': 'Bank ID is required'})
        
        bank = Bank.query.get_or_404(bank_id)
        
        added_count = 0
        
        # Add organizations to bank
        if collector.data_type == 'organizations' and collector.subcategory:
            from models import OrganizationType
            org_type = OrganizationType.query.filter_by(name=collector.subcategory).first()
            if org_type:
                organizations = Organization.query.filter_by(organization_type_id=org_type.id).all()
            else:
                organizations = []
        else:
            organizations = Organization.query.filter(
                Organization.created_by == collector.created_by
            ).all()
        
        for org in organizations:
            # Check if already exists in bank
            existing = BankContent.query.filter_by(
                bank_id=bank.id,
                content_type='organization',
                content_id=org.id
            ).first()
            
            if not existing:
                bank_content = BankContent(
                    bank_id=bank.id,
                    content_type='organization',
                    content_id=org.id,
                    title=org.name,
                    description=org.description or f"Organization: {org.name}",
                    added_by=current_user.id
                )
                db.session.add(bank_content)
                added_count += 1
        
        # Add items to bank
        if collector.data_type == 'items' and collector.subcategory:
            from models import ItemType
            item_type = ItemType.query.filter_by(name=collector.subcategory).first()
            if item_type:
                items = Item.query.filter_by(item_type_id=item_type.id).all()
            else:
                items = []
        else:
            items = Item.query.filter(
                Item.creator_name.like(f'%{collector.name}%')
            ).all()
        
        for item in items:
            # Check if already exists in bank
            existing = BankContent.query.filter_by(
                bank_id=bank.id,
                content_type='item',
                content_id=item.id
            ).first()
            
            if not existing:
                bank_content = BankContent(
                    bank_id=bank.id,
                    content_type='item',
                    content_id=item.id,
                    title=item.title,
                    description=item.description or f"Item: {item.title}",
                    added_by=current_user.id
                )
                db.session.add(bank_content)
                added_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully added {added_count} items to {bank.name}',
            'added_count': added_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        })

@admin_bp.route('/data-collectors/add-item-to-bank', methods=['POST'])
@admin_required
def add_item_to_bank():
    """Add a specific item or organization to a bank"""
    try:
        from models import Bank, Item, Organization, BankContent
        
        bank_id = request.form.get('bank_id')
        item_id = request.form.get('item_id')
        item_type = request.form.get('item_type')
        
        if not bank_id or not item_id or not item_type:
            return jsonify({'success': False, 'message': 'Bank ID, Item ID, and Item Type are required'})
        
        bank = Bank.query.get_or_404(bank_id)
        
        # Check if already exists in bank
        existing = BankContent.query.filter_by(
            bank_id=bank.id,
            content_type=item_type,
            content_id=item_id
        ).first()
        
        if existing:
            return jsonify({
                'success': False,
                'message': 'This item is already in the selected bank'
            })
        
        # Get the item/organization
        if item_type == 'item':
            item = Item.query.get_or_404(item_id)
            title = item.title
            description = item.description or f"Item: {item.title}"
        elif item_type == 'organization':
            item = Organization.query.get_or_404(item_id)
            title = item.name
            description = item.description or f"Organization: {item.name}"
        else:
            return jsonify({'success': False, 'message': 'Invalid item type'})
        
        # Add to bank
        bank_content = BankContent(
            bank_id=bank.id,
            content_type=item_type,
            content_id=item_id,
            title=title,
            description=description,
            added_by=current_user.id
        )
        db.session.add(bank_content)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully added {title} to {bank.name}',
            'item_name': title,
            'bank_name': bank.name
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        })

@admin_bp.route('/data-collectors/add-all-to-bank', methods=['POST'])
@admin_required
def add_all_collected_data_to_bank():
    """Add all collected data from all collectors to a bank"""
    try:
        from models import Bank, Item, Organization, BankContent
        
        bank_id = request.form.get('bank_id')
        
        if not bank_id:
            return jsonify({'success': False, 'message': 'Bank ID is required'})
        
        bank = Bank.query.get_or_404(bank_id)
        
        added_count = 0
        
        # Add all organizations
        organizations = Organization.query.all()
        for org in organizations:
            # Check if already exists in bank
            existing = BankContent.query.filter_by(
                bank_id=bank.id,
                content_type='organization',
                content_id=org.id
            ).first()
            
            if not existing:
                bank_content = BankContent(
                    bank_id=bank.id,
                    content_type='organization',
                    content_id=org.id,
                    title=org.name,
                    description=org.description or f"Organization: {org.name}",
                    added_by=current_user.id
                )
                db.session.add(bank_content)
                added_count += 1
        
        # Add all items
        items = Item.query.all()
        for item in items:
            # Check if already exists in bank
            existing = BankContent.query.filter_by(
                bank_id=bank.id,
                content_type='item',
                content_id=item.id
            ).first()
            
            if not existing:
                bank_content = BankContent(
                    bank_id=bank.id,
                    content_type='item',
                    content_id=item.id,
                    title=item.title,
                    description=item.description or f"Item: {item.title}",
                    added_by=current_user.id
                )
                db.session.add(bank_content)
                added_count += 1
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Successfully added {added_count} items to {bank.name}',
            'added_count': added_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        })

@admin_bp.route('/data-collectors/collected-data')
@admin_required
def collected_data():
    """View all data collected by data collectors"""
    try:
        # Get all collectors with their collected data
        collectors = DataCollector.query.all()
        
        # Get chatbot responses from collectors
        chatbot_responses = ChatbotResponse.query.filter(
            ChatbotResponse.session_id.like('collector_%')
        ).order_by(ChatbotResponse.created_at.desc()).all()
        
        # Get items created by collectors
        collected_items = Item.query.filter(
            Item.creator_name.like('%Data Collector%')
        ).order_by(Item.created_at.desc()).all()
        
        # Get organizations created by collectors
        collected_organizations = Organization.query.filter(
            Organization.created_by == 1  # Assuming collector user ID is 1
        ).order_by(Organization.created_at.desc()).all()
        
        return render_template('admin/collected_data.html', 
                             collectors=collectors,
                             chatbot_responses=chatbot_responses,
                             collected_items=collected_items,
                             collected_organizations=collected_organizations)
        
    except Exception as e:
        flash(f'Error loading collected data: {str(e)}', 'error')
        return redirect(url_for('admin.data_collectors'))

@admin_bp.route('/banks-management')
@admin_required
def banks_management():
    """Banks management page"""
    banks = Bank.query.order_by(Bank.sort_order.asc(), Bank.name.asc()).all()
    collectors = DataCollector.query.filter_by(is_active=True).all()
    
    return render_template('admin/banks_management.html', banks=banks, collectors=collectors)

@admin_bp.route('/banks/create', methods=['GET', 'POST'])
@admin_required
def create_bank():
    """Create new bank"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            bank = Bank(
                name=data['name'],
                slug=data['slug'],
                description=data['description'],
                bank_type=data['bank_type'],
                item_type_id=data.get('item_type_id'),
                organization_type_id=data.get('organization_type_id'),
                user_filter=data.get('user_filter'),
                privacy_filter=data.get('privacy_filter', 'all'),
                organization_type=data.get('organization_type'),  # Keep for backward compatibility
                icon=data.get('icon', 'fas fa-database'),
                color=data.get('color', '#2988a8'),
                sort_order=data.get('sort_order', 0),
                is_public=data.get('is_public', True),
                created_by=current_user.id
            )
            
            db.session.add(bank)
            db.session.commit()
            
            # Connect to collectors if specified
            if data.get('collector_ids'):
                for collector_id in data['collector_ids']:
                    bank_collector = BankCollector(
                        bank_id=bank.id,
                        collector_id=collector_id
                    )
                    db.session.add(bank_collector)
            
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Bank created successfully'})
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    collectors = DataCollector.query.filter_by(is_active=True).all()
    
    # Get item types, organization types, and profile types for the form
    from models import ItemType, OrganizationType, ProfileType
    item_types = ItemType.query.filter_by(is_active=True).order_by(ItemType.display_name).all()
    organization_types = OrganizationType.query.filter_by(is_active=True).order_by(OrganizationType.display_name).all()
    profile_types = ProfileType.query.filter_by(is_active=True).order_by(ProfileType.order_index.asc()).all()
    
    return render_template('admin/create_bank.html', 
                         collectors=collectors,
                         item_types=item_types,
                         organization_types=organization_types,
                         profile_types=profile_types)

@admin_bp.route('/banks/<int:bank_id>/content')
@admin_required
def bank_content(bank_id):
    """View bank content"""
    bank = Bank.query.get_or_404(bank_id)
    content = BankContent.query.filter_by(bank_id=bank_id).all()
    
    return render_template('admin/bank_content.html', bank=bank, content=content)

@admin_bp.route('/banks/<int:bank_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_bank(bank_id):
    """Edit bank"""
    bank = Bank.query.get_or_404(bank_id)
    
    if request.method == 'POST':
        data = request.get_json()
        
        bank.name = data.get('name', bank.name)
        bank.slug = data.get('slug', bank.slug)
        bank.description = data.get('description', bank.description)
        bank.bank_type = data.get('bank_type', bank.bank_type)
        bank.item_type_id = data.get('item_type_id', bank.item_type_id)
        bank.organization_type_id = data.get('organization_type_id', bank.organization_type_id)
        bank.user_filter = data.get('user_filter', bank.user_filter)
        bank.privacy_filter = data.get('privacy_filter', bank.privacy_filter)
        bank.organization_type = data.get('organization_type', bank.organization_type)  # Keep for backward compatibility
        bank.icon = data.get('icon', bank.icon)
        bank.color = data.get('color', bank.color)
        bank.sort_order = data.get('sort_order', bank.sort_order)
        bank.is_active = data.get('is_active', bank.is_active)
        bank.is_public = data.get('is_public', bank.is_public)
        
        try:
            db.session.commit()
            return jsonify({'success': True, 'message': 'Bank updated successfully!'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    # Get item types, organization types, and profile types for the form
    from models import ItemType, OrganizationType, ProfileType
    item_types = ItemType.query.filter_by(is_active=True).order_by(ItemType.display_name).all()
    organization_types = OrganizationType.query.filter_by(is_active=True).order_by(OrganizationType.display_name).all()
    profile_types = ProfileType.query.filter_by(is_active=True).order_by(ProfileType.order_index.asc()).all()
    
    return render_template('admin/edit_bank.html', 
                         bank=bank,
                         item_types=item_types,
                         organization_types=organization_types,
                         profile_types=profile_types)

@admin_bp.route('/banks/<int:bank_id>/delete', methods=['POST'])
@admin_required
def delete_bank(bank_id):
    """Delete bank"""
    bank = Bank.query.get_or_404(bank_id)
    
    try:
        # Delete associated content
        BankContent.query.filter_by(bank_id=bank_id).delete()
        BankCollector.query.filter_by(bank_id=bank_id).delete()
        
        # Delete the bank
        db.session.delete(bank)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Bank deleted successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

# Enhanced Permission Management Routes
@admin_bp.route('/roles/<int:role_id>', methods=['GET'])
@login_required
@admin_required
def get_role(role_id):
    """Get role details for editing"""
    role = Role.query.get_or_404(role_id)
    return jsonify({
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'is_internal': role.is_internal,
        'is_active': role.is_active,
        'created_at': role.created_at.isoformat(),
        'updated_at': role.updated_at.isoformat() if role.updated_at else None
    })

@admin_bp.route('/roles', methods=['POST'])
@login_required
@admin_required
def create_role_api():
    """Create a new role via API"""
    try:
        data = request.get_json()
        
        role = Role(
            name=data['name'],
            description=data.get('description', ''),
            is_internal=data.get('is_internal', False),
            is_active=data.get('is_active', True)
        )
        
        db.session.add(role)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Role created successfully', 'role_id': role.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/roles/<int:role_id>', methods=['PUT'])
@login_required
@admin_required
def update_role(role_id):
    """Update a role via API"""
    try:
        role = Role.query.get_or_404(role_id)
        data = request.get_json()
        
        role.name = data.get('name', role.name)
        role.description = data.get('description', role.description)
        role.is_internal = data.get('is_internal', role.is_internal)
        role.is_active = data.get('is_active', role.is_active)
        role.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Role updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/roles/<int:role_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_role_api(role_id):
    """Delete a role via API"""
    try:
        role = Role.query.get_or_404(role_id)
        
        # Check if role is assigned to any users
        if role.users:
            return jsonify({'success': False, 'message': 'Cannot delete role that is assigned to users'})
        
        db.session.delete(role)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Role deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/roles/<int:role_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_role_status(role_id):
    """Toggle role active status"""
    try:
        role = Role.query.get_or_404(role_id)
        role.is_active = not role.is_active
        role.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Role {"activated" if role.is_active else "deactivated"} successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@admin_bp.route('/users/<int:user_id>/roles')
@login_required
@admin_required
def get_user_roles(user_id):
    """Get user roles for management"""
    from models import UserRole
    
    user = User.query.get_or_404(user_id)
    all_roles = Role.query.all()
    
    # Get user role assignments from UserRole table
    user_role_assignments = UserRole.query.filter_by(user_id=user_id, is_active=True).all()
    user_role_ids = {ur.role_id for ur in user_role_assignments}
    
    result = []
    for role in all_roles:
        result.append({
            'id': role.id,
            'name': role.name,
            'description': role.description,
            'is_internal': role.is_internal,
            'assigned': role.id in user_role_ids
        })
    
    return jsonify({'roles': result})

@admin_bp.route('/users/<int:user_id>/roles', methods=['POST'])
@login_required
@admin_required
def update_user_roles(user_id):
    """Update user roles"""
    try:
        from models import UserRole
        
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        roles = data.get('roles', [])
        
        # Clear existing roles for this user
        UserRole.query.filter_by(user_id=user_id).delete()
        
        # Add new roles
        for role_data in roles:
            if role_data['assigned']:
                user_role = UserRole(
                    user_id=user_id,
                    role_id=role_data['role_id'],
                    assigned_by=current_user.id
                )
                db.session.add(user_role)
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User roles updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/item-types/api/list')
@login_required
def item_types_api_list():
    """API endpoint to get all item types for dashboard"""
    try:
        item_types = ItemType.query.filter_by(is_active=True).all()
        return jsonify({
            'success': True,
            'item_types': [{
                'id': item_type.id,
                'name': item_type.name,
                'description': item_type.description,
                'icon_class': item_type.icon_class,
                'is_active': item_type.is_active,
                'created_at': item_type.created_at.isoformat() if item_type.created_at else None
            } for item_type in item_types]
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/organization-types-management')
@login_required
@admin_required
def organization_types_management():
    """Manage organization types"""
    organization_types = OrganizationType.query.order_by(OrganizationType.order_index, OrganizationType.created_at).all()
    
    return render_template('admin/organization_types_management.html', 
                         organization_types=organization_types)

@admin_bp.route('/organization-types/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_organization_type():
    """Create a new organization type"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        name = data.get('name')
        display_name = data.get('display_name')
        description = data.get('description', '')
        icon_class = data.get('icon_class', 'fas fa-building')
        color_class = data.get('color_class', '#2988a8')
        max_profiles_per_user = int(data.get('max_profiles_per_user', 10))
        # Handle both string and boolean values for checkboxes
        requires_verification = data.get('requires_verification', False)
        if isinstance(requires_verification, str):
            requires_verification = requires_verification.lower() == 'true'
        else:
            requires_verification = bool(requires_verification)
            
        is_active = data.get('is_active', True)
        if isinstance(is_active, str):
            is_active = is_active.lower() == 'true'
        else:
            is_active = bool(is_active)
        
        if not name or not display_name:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Name and display name are required'})
            flash('Name and display name are required', 'error')
            return redirect(url_for('admin.organization_types_management'))
        
        # Check if name already exists
        existing = OrganizationType.query.filter_by(name=name).first()
        if existing:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Organization type with this name already exists'})
            flash('Organization type with this name already exists', 'error')
            return redirect(url_for('admin.organization_types_management'))
        
        # Get next order index
        last_type = OrganizationType.query.order_by(OrganizationType.order_index.desc()).first()
        order_index = (last_type.order_index + 1) if last_type else 1
        
        organization_type = OrganizationType(
            name=name,
            display_name=display_name,
            description=description,
            icon_class=icon_class,
            color_class=color_class,
            max_profiles_per_user=max_profiles_per_user,
            requires_verification=requires_verification,
            is_active=is_active,
            order_index=order_index
        )
        
        db.session.add(organization_type)
        db.session.commit()
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Organization type created successfully'})
        flash('Organization type created successfully', 'success')
        return redirect(url_for('admin.organization_types_management'))
    
    return render_template('admin/create_organization_type.html')

@admin_bp.route('/organization-types/<int:org_type_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_organization_type(org_type_id):
    """Edit an organization type"""
    organization_type = OrganizationType.query.get_or_404(org_type_id)
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        organization_type.display_name = data.get('display_name', organization_type.display_name)
        organization_type.description = data.get('description', organization_type.description)
        organization_type.icon_class = data.get('icon_class', organization_type.icon_class)
        organization_type.color_class = data.get('color_class', organization_type.color_class)
        organization_type.max_profiles_per_user = int(data.get('max_profiles_per_user', organization_type.max_profiles_per_user))
        # Handle both string and boolean values for checkboxes
        requires_verification = data.get('requires_verification', False)
        if isinstance(requires_verification, str):
            organization_type.requires_verification = requires_verification.lower() == 'true'
        else:
            organization_type.requires_verification = bool(requires_verification)
            
        is_active = data.get('is_active', True)
        if isinstance(is_active, str):
            organization_type.is_active = is_active.lower() == 'true'
        else:
            organization_type.is_active = bool(is_active)
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Organization type updated successfully'})
        flash('Organization type updated successfully', 'success')
        return redirect(url_for('admin.organization_types_management'))
    
    return render_template('admin/edit_organization_type.html', organization_type=organization_type)

@admin_bp.route('/organization-types/<int:org_type_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_organization_type(org_type_id):
    """Delete an organization type"""
    organization_type = OrganizationType.query.get_or_404(org_type_id)
    
    # Check if there are any organizations using this type
    from models import Organization
    organizations_count = Organization.query.filter_by(organization_type_id=org_type_id).count()
    
    if organizations_count > 0:
        if request.is_json:
            return jsonify({'success': False, 'message': f'Cannot delete organization type. {organizations_count} organizations are using this type.'})
        flash(f'Cannot delete organization type. {organizations_count} organizations are using this type.', 'error')
        return redirect(url_for('admin.organization_types_management'))
    
    db.session.delete(organization_type)
    db.session.commit()
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Organization type deleted successfully'})
    flash('Organization type deleted successfully', 'success')
    return redirect(url_for('admin.organization_types_management'))

@admin_bp.route('/organizations-management')
@login_required
@admin_required
def organizations_management():
    """Manage organizations"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    type_filter = request.args.get('type', '')
    
    query = Organization.query
    
    # Apply search filter
    if search:
        query = query.filter(
            db.or_(
                Organization.name.contains(search),
                Organization.description.contains(search),
                Organization.slug.contains(search)
            )
        )
    
    # Apply type filter
    if type_filter:
        query = query.join(OrganizationType).filter(OrganizationType.name == type_filter)
    
    # Get paginated results
    organizations = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get all organization types for filter
    org_types = OrganizationType.query.all()
    
    return render_template('admin/organizations.html', 
                         organizations=organizations, 
                         org_types=org_types, 
                         search=search, 
                         type_filter=type_filter)

@admin_bp.route('/organizations/<int:org_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_organization_status(org_id):
    """Toggle organization status"""
    organization = Organization.query.get_or_404(org_id)
    
    # Toggle between active and suspended
    if organization.status == 'active':
        organization.status = 'suspended'
    else:
        organization.status = 'active'
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'status': organization.status,
        'message': f'Organization {"activated" if organization.status == "active" else "suspended"} successfully'
    })

@admin_bp.route('/organizations/<int:org_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_organization(org_id):
    """Delete an organization permanently"""
    organization = Organization.query.get_or_404(org_id)
    
    try:
        # Delete organization memberships
        from models import OrganizationMember
        OrganizationMember.query.filter_by(organization_id=org_id).delete()
        
        # Delete organization content (items and needs through OrganizationContent)
        from models import OrganizationContent
        OrganizationContent.query.filter_by(organization_id=org_id).delete()
        
        # Delete organization history
        from models import OrganizationHistory
        OrganizationHistory.query.filter_by(organization_id=org_id).delete()
        
        # Delete organization reviews (if any exist with organization references)
        from models import Review
        # Note: Reviews typically reference users, not organizations directly
        # But we'll check if there are any organization-specific review fields
        # Review.query.filter(db.or_(
        #     Review.reviewer_id == org_id,
        #     Review.reviewee_id == org_id
        # )).delete()
        
        # Delete the organization
        db.session.delete(organization)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Organization deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error deleting organization: {str(e)}'
        }), 500

@admin_bp.route('/organizations/<int:org_id>/view')
@login_required
@admin_required
def view_organization(org_id):
    """View organization details"""
    organization = Organization.query.get_or_404(org_id)
    
    # Get organization members
    from models import OrganizationMember
    members = OrganizationMember.query.filter_by(organization_id=org_id).all()
    
    # Get organization items through OrganizationContent
    from models import OrganizationContent, Item
    org_content = OrganizationContent.query.filter_by(organization_id=org_id, content_type='item').all()
    items = [content.item for content in org_content if content.item]
    
    # Get organization needs through OrganizationContent
    from models import UserNeed
    org_needs_content = OrganizationContent.query.filter_by(organization_id=org_id, content_type='need').all()
    needs = [content.need for content in org_needs_content if content.need]
    
    return render_template('admin/organization_detail.html', 
                         organization=organization,
                         members=members,
                         items=items,
                         needs=needs)

@admin_bp.route('/organizations/<slug>/view')
@login_required
@admin_required
def view_organization_by_slug(slug):
    """View organization details by slug"""
    organization = Organization.query.filter_by(slug=slug).first_or_404()
    
    # Get organization members
    from models import OrganizationMember
    members = OrganizationMember.query.filter_by(organization_id=organization.id).all()
    
    # Get organization items through OrganizationContent
    from models import OrganizationContent, Item
    org_content = OrganizationContent.query.filter_by(organization_id=organization.id, content_type='item').all()
    items = [content.item for content in org_content if content.item]
    
    # Get organization needs through OrganizationContent
    from models import UserNeed
    org_needs_content = OrganizationContent.query.filter_by(organization_id=organization.id, content_type='need').all()
    needs = [content.need for content in org_needs_content if content.need]
    
    return render_template('admin/organization_detail.html', 
                         organization=organization,
                         members=members,
                         items=items,
                         needs=needs)

# Profile Management Routes
@admin_bp.route('/profile-types-management')
@login_required
@admin_required
def profile_types_management():
    """Manage profile types"""
    profile_types = ProfileType.query.order_by(ProfileType.order_index, ProfileType.created_at).all()
    
    return render_template('admin/profile_types_management.html', 
                         profile_types=profile_types)

@admin_bp.route('/profile-types/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_profile_type():
    """Create a new profile type"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        name = data.get('name')
        display_name = data.get('display_name')
        description = data.get('description', '')
        icon_class = data.get('icon_class', 'fas fa-user')
        color_class = data.get('color_class', 'primary')
        max_profiles_per_user = int(data.get('max_profiles_per_user', 5))
        # Handle both string and boolean values for checkboxes
        requires_verification = data.get('requires_verification', False)
        if isinstance(requires_verification, str):
            requires_verification = requires_verification.lower() == 'true'
        else:
            requires_verification = bool(requires_verification)
            
        is_active = data.get('is_active', True)
        if isinstance(is_active, str):
            is_active = is_active.lower() == 'true'
        else:
            is_active = bool(is_active)
        
        if not name or not display_name:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Name and display name are required'})
            flash('Name and display name are required', 'error')
            return redirect(url_for('admin.profile_types_management'))
        
        # Check if name already exists
        existing = ProfileType.query.filter_by(name=name).first()
        if existing:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Profile type with this name already exists'})
            flash('Profile type with this name already exists', 'error')
            return redirect(url_for('admin.profile_types_management'))
        
        # Get next order index
        last_type = ProfileType.query.order_by(ProfileType.order_index.desc()).first()
        order_index = (last_type.order_index + 1) if last_type else 1
        
        profile_type = ProfileType(
            name=name,
            display_name=display_name,
            description=description,
            icon_class=icon_class,
            color_class=color_class,
            max_profiles_per_user=max_profiles_per_user,
            requires_verification=requires_verification,
            is_active=is_active,
            order_index=order_index
        )
        
        db.session.add(profile_type)
        db.session.commit()
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Profile type created successfully'})
        flash('Profile type created successfully', 'success')
        return redirect(url_for('admin.profile_types_management'))
    
    return render_template('admin/create_profile_type.html')

@admin_bp.route('/profile-types/<int:profile_type_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_type(profile_type_id):
    """Edit a profile type"""
    profile_type = ProfileType.query.get_or_404(profile_type_id)
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        profile_type.display_name = data.get('display_name', profile_type.display_name)
        profile_type.description = data.get('description', profile_type.description)
        profile_type.icon_class = data.get('icon_class', profile_type.icon_class)
        profile_type.color_class = data.get('color_class', profile_type.color_class)
        profile_type.max_profiles_per_user = int(data.get('max_profiles_per_user', profile_type.max_profiles_per_user))
        # Handle both string and boolean values for checkboxes
        requires_verification = data.get('requires_verification', False)
        if isinstance(requires_verification, str):
            profile_type.requires_verification = requires_verification.lower() == 'true'
        else:
            profile_type.requires_verification = bool(requires_verification)
            
        is_active = data.get('is_active', True)
        if isinstance(is_active, str):
            profile_type.is_active = is_active.lower() == 'true'
        else:
            profile_type.is_active = bool(is_active)
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Profile type updated successfully'})
        flash('Profile type updated successfully', 'success')
        return redirect(url_for('admin.profile_types_management'))
    
    return render_template('admin/edit_profile_type.html', profile_type=profile_type)

@admin_bp.route('/profile-types/<int:profile_type_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_profile_type(profile_type_id):
    """Delete a profile type"""
    profile_type = ProfileType.query.get_or_404(profile_type_id)
    
    # Check if any profiles are using this type
    profiles_count = Profile.query.filter_by(profile_type_id=profile_type_id).count()
    if profiles_count > 0:
        flash(f'Cannot delete profile type "{profile_type.display_name}" because {profiles_count} profiles are using it', 'error')
        return redirect(url_for('admin.profile_types_management'))
    
    db.session.delete(profile_type)
    db.session.commit()
    
    flash(f'Profile type "{profile_type.display_name}" deleted successfully', 'success')
    return redirect(url_for('admin.profile_types_management'))

@admin_bp.route('/profiles-management')
@login_required
@admin_required
def profiles_management():
    """Manage profiles"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    type_filter = request.args.get('type', '')
    status_filter = request.args.get('status', '')
    
    query = Profile.query.join(User)
    
    # Apply search filter
    if search:
        query = query.filter(
            db.or_(
                Profile.name.contains(search),
                Profile.description.contains(search),
                User.username.contains(search),
                User.email.contains(search)
            )
        )
    
    # Apply type filter
    if type_filter:
        query = query.filter(Profile.profile_type == type_filter)
    
    # Apply status filter
    if status_filter == 'active':
        query = query.filter(Profile.is_active == True)
    elif status_filter == 'inactive':
        query = query.filter(Profile.is_active == False)
    elif status_filter == 'public':
        query = query.filter(Profile.is_public == True)
    elif status_filter == 'private':
        query = query.filter(Profile.is_public == False)
    elif status_filter == 'default':
        query = query.filter(Profile.is_default == True)
    
    # Get paginated results
    profiles = query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get profile type choices for filter
    from forms import ProfileForm
    form = ProfileForm()
    profile_type_choices = form.profile_type.choices
    
    return render_template('admin/profiles_management.html', 
                         profiles=profiles, 
                         profile_type_choices=profile_type_choices,
                         search=search, 
                         type_filter=type_filter,
                         status_filter=status_filter)

@admin_bp.route('/profiles/<int:profile_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_profile_status(profile_id):
    """Toggle profile active status"""
    profile = Profile.query.get_or_404(profile_id)
    profile.is_active = not profile.is_active
    db.session.commit()
    
    status = 'activated' if profile.is_active else 'deactivated'
    if request.is_json:
        return jsonify({'success': True, 'message': f'Profile {status} successfully', 'is_active': profile.is_active})
    flash(f'Profile {status} successfully', 'success')
    return redirect(url_for('admin.profiles_management'))

@admin_bp.route('/profiles/<int:profile_id>/toggle-visibility', methods=['POST'])
@login_required
@admin_required
def toggle_profile_visibility(profile_id):
    """Toggle profile public/private status"""
    profile = Profile.query.get_or_404(profile_id)
    profile.is_public = not profile.is_public
    db.session.commit()
    
    visibility = 'public' if profile.is_public else 'private'
    if request.is_json:
        return jsonify({'success': True, 'message': f'Profile set to {visibility} successfully', 'is_public': profile.is_public})
    flash(f'Profile set to {visibility} successfully', 'success')
    return redirect(url_for('admin.profiles_management'))

@admin_bp.route('/profiles/<int:profile_id>/detail')
@login_required
@admin_required
def profile_detail(profile_id):
    """View profile details"""
    profile = Profile.query.get_or_404(profile_id)
    
    # Get profile items
    items = Item.query.filter_by(profile_id=profile.id).order_by(Item.created_at.desc()).all()
    
    # Get profile projects if they exist
    projects = []
    try:
        projects = Project.query.filter_by(profile_id=profile.id).order_by(Project.created_at.desc()).all()
    except:
        pass  # Projects table might not exist
    
    return render_template('admin/profile_detail.html', 
                         profile=profile,
                         items=items,
                         projects=projects)

@admin_bp.route('/profiles/<int:profile_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_profile(profile_id):
    """Delete a profile"""
    profile = Profile.query.get_or_404(profile_id)
    
    # Check if this is the user's default profile
    if profile.is_default:
        if request.is_json:
            return jsonify({'success': False, 'message': 'Cannot delete default profile'})
        flash('Cannot delete default profile', 'error')
        return redirect(url_for('admin.profiles_management'))
    
    # Delete the profile (cascade will handle items)
    db.session.delete(profile)
    db.session.commit()
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Profile deleted successfully'})
    flash('Profile deleted successfully', 'success')
    return redirect(url_for('admin.profiles_management'))


# ==================== WALLET ADMIN ROUTES ====================

@admin_bp.route('/wallet-management')
@login_required
@require_permission('wallet_admin', 'view_all')
def wallet_management():
    """Admin wallet management dashboard"""
    from models import Wallet, WithdrawalRequest, WalletTransaction
    from utils.wallet_service import WalletService
    
    # Get wallet statistics
    total_wallets = Wallet.query.count()
    active_wallets = Wallet.query.filter_by(is_active=True).count()
    
    # Get total balance across all wallets
    total_balance = db.session.query(db.func.sum(Wallet.balance)).scalar() or 0
    
    # Get pending withdrawal requests
    pending_withdrawals = WithdrawalRequest.query.filter_by(status='pending').count()
    
    # Get recent withdrawal requests
    recent_withdrawals = WithdrawalRequest.query.order_by(WithdrawalRequest.created_at.desc()).limit(10).all()
    
    # Get recent transactions
    recent_transactions = WalletTransaction.query.order_by(WalletTransaction.created_at.desc()).limit(10).all()
    
    stats = {
        'total_wallets': total_wallets,
        'active_wallets': active_wallets,
        'total_balance': total_balance,
        'pending_withdrawals': pending_withdrawals
    }
    
    return render_template('admin/wallet_management.html',
                         stats=stats,
                         recent_withdrawals=recent_withdrawals,
                         recent_transactions=recent_transactions)


@admin_bp.route('/withdrawal-requests')
@login_required
@require_permission('wallet_admin', 'process_withdrawals')
def withdrawal_requests():
    """View all withdrawal requests"""
    from models import WithdrawalRequest
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get withdrawal requests with pagination
    withdrawals = WithdrawalRequest.query.order_by(WithdrawalRequest.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/withdrawal_requests.html', withdrawals=withdrawals)


@admin_bp.route('/process-withdrawal/<int:withdrawal_id>', methods=['POST'])
@login_required
@require_permission('wallet_admin', 'process_withdrawals')
def process_withdrawal(withdrawal_id):
    """Process a withdrawal request (approve/reject)"""
    from models import WithdrawalRequest
    from utils.wallet_service import WalletService
    
    withdrawal_request = WithdrawalRequest.query.get_or_404(withdrawal_id)
    
    data = request.get_json() if request.is_json else request.form
    action = data.get('action')  # 'approve' or 'reject'
    admin_notes = data.get('admin_notes', '')
    
    if action not in ['approve', 'reject']:
        return jsonify({'success': False, 'message': 'Invalid action'})
    
    # Process the withdrawal
    success = WalletService.process_withdrawal(
        withdrawal_request_id=withdrawal_request.id,
        admin_id=current_user.id,
        approved=(action == 'approve'),
        admin_notes=admin_notes
    )
    
    if success:
        message = f'Withdrawal {action}d successfully'
        if request.is_json:
            return jsonify({'success': True, 'message': message})
        flash(message, 'success')
    else:
        message = f'Error processing withdrawal request'
        if request.is_json:
            return jsonify({'success': False, 'message': message})
        flash(message, 'error')
    
    return redirect(url_for('admin.withdrawal_requests'))


@admin_bp.route('/wallet-transactions')
@login_required
@require_permission('transactions', 'view_all')
def wallet_transactions():
    """View all wallet transactions"""
    from models import WalletTransaction
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get transactions with pagination
    transactions = WalletTransaction.query.order_by(WalletTransaction.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/wallet_transactions.html', transactions=transactions)


@admin_bp.route('/user-wallet/<int:user_id>')
@login_required
@require_permission('wallet_admin', 'view_all')
def user_wallet_detail(user_id):
    """View detailed wallet information for a specific user"""
    from models import User, Wallet
    from utils.wallet_service import WalletService
    
    user = User.query.get_or_404(user_id)
    
    # Get wallet summary
    summary = WalletService.get_wallet_summary(user.id)
    
    # Get all transactions
    transactions = summary['wallet'].transactions.order_by(
        WalletTransaction.created_at.desc()
    ).limit(50).all()
    
    # Get all withdrawal requests
    withdrawal_requests = WithdrawalRequest.query.filter_by(
        user_id=user.id
    ).order_by(WithdrawalRequest.created_at.desc()).all()
    
    return render_template('admin/user_wallet_detail.html',
                         user=user,
                         summary=summary,
                         transactions=transactions,
                         withdrawal_requests=withdrawal_requests)
