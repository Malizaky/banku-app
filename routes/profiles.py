from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from models import Profile, Item, Project, ProjectContributor, User, db, Need, Activity, ProductCategory, ItemType, ChatbotFlow, Organization, OrganizationMember
from utils.permissions import require_permission
from forms import ProfileForm
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename

profiles_bp = Blueprint('profiles', __name__)

@profiles_bp.route('/')
@login_required
@require_permission('profiles', 'read')
def index():
    profiles = Profile.query.filter_by(user_id=current_user.id).all()
    return render_template('profiles/index.html', profiles=profiles)

# NEW DYNAMIC ITEM CREATION SYSTEM
@profiles_bp.route('/create-item')
@login_required
@require_permission('items', 'create')
def create_item_redirect():
    """Redirect to dynamic item creation based on ItemTypes"""
    # Get all active item types
    item_types = ItemType.query.filter_by(is_active=True, is_visible=True).order_by(ItemType.order_index, ItemType.name).all()
    
    # Check if user has a profile
    profile = Profile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        flash('Please create a profile first', 'error')
        return redirect(url_for('profiles.create'))
    
    return render_template('profiles/create_item_dynamic.html', profile=profile, item_types=item_types)

@profiles_bp.route('/create-<item_type_name>')
@login_required  
def create_item_by_type(item_type_name):
    """Dynamic item creation route - redirects to assigned chatbot"""
    # Find the item type
    item_type = ItemType.query.filter_by(name=item_type_name, is_active=True, is_visible=True).first()
    
    if not item_type:
        flash(f'Item type "{item_type_name}" not found', 'error')
        return redirect(url_for('profiles.create_item_redirect'))
    
    # Check if item type has an assigned chatbot
    if not item_type.chatbot_id:
        flash(f'No chatbot assigned to "{item_type.display_name}" item type. Please contact admin.', 'error')
        return redirect(url_for('profiles.create_item_redirect'))
    
    # Check if chatbot exists and is active
    chatbot = ChatbotFlow.query.filter_by(id=item_type.chatbot_id, is_active=True).first()
    if not chatbot:
        flash(f'Assigned chatbot for "{item_type.display_name}" is not available', 'error')
        return redirect(url_for('profiles.create_item_redirect'))
    
    # Redirect to chatbot flow
    return redirect(url_for('chatbot.start_flow', flow_id=chatbot.id))

# LEGACY ROUTE REDIRECTS REMOVED
# All item creation now uses the dynamic system above

@profiles_bp.route('/create', methods=['GET', 'POST'])
@login_required
@require_permission('profiles', 'create')
def create():
    form = ProfileForm()
    
    # Get profile types for template
    from models import ProfileType
    profile_types = ProfileType.query.filter_by(is_active=True).order_by(ProfileType.order_index, ProfileType.display_name).all()
    profile_types_dict = {str(pt.id): pt for pt in profile_types}
    
    if form.validate_on_submit():
        # Handle file upload for photo
        photo_filename = None
        if form.photo.data and hasattr(form.photo.data, 'filename') and form.photo.data.filename:
            file = form.photo.data
            filename = secure_filename(file.filename)
            # Create unique filename
            photo_filename = f"{current_user.id}_photo_{filename}"
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], photo_filename)
            file.save(file_path)
        
        # Handle ProfileType - could be ID (new system) or string (legacy)
        profile_type_value = form.profile_type.data
        profile_type_id = None
        profile_type_string = None
        
        try:
            # Try to convert to int (new ProfileType ID system)
            profile_type_id = int(profile_type_value)
            # Get the ProfileType to also set the string for backward compatibility
            from models import ProfileType
            profile_type_obj = ProfileType.query.get(profile_type_id)
            if profile_type_obj:
                profile_type_string = profile_type_obj.name
        except (ValueError, TypeError):
            # Legacy string system
            profile_type_string = profile_type_value
        
        profile = Profile(
            user_id=current_user.id,
            name=form.name.data,
            profile_type=profile_type_string,  # Keep for backward compatibility
            profile_type_id=profile_type_id,   # New foreign key system
            description=form.description.data,
            website=form.website.data,
            location=form.location.data,
            photo=photo_filename,
            is_public=form.is_public.data
        )
        
        db.session.add(profile)
        db.session.commit()
        
        flash('Profile created successfully', 'success')
        return redirect(url_for('profiles.detail', profile_id=profile.id))
    
    return render_template('profiles/create.html', form=form, profile_types_dict=profile_types_dict)

@profiles_bp.route('/<int:profile_id>')
@login_required
@require_permission('profiles', 'read')
def detail(profile_id):
    profile = Profile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()
    
    # Get all profile's items
    all_items = Item.query.filter_by(profile_id=profile_id).order_by(Item.created_at.desc()).all()
    
    # Separate items and needs based on category or content_type
    items = [item for item in all_items if item.category != 'need' and getattr(item, 'content_type', None) != 'need']
    needs = [item for item in all_items if item.category == 'need' or getattr(item, 'content_type', None) == 'need']
    
    # Get profile's projects
    projects = Project.query.filter_by(profile_id=profile_id).order_by(Project.created_at.desc()).all()
    
    return render_template('profiles/detail_new.html', profile=profile, items=items, needs=needs, projects=projects)

@profiles_bp.route('/<int:profile_id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission('profiles', 'update')
def edit(profile_id):
    profile = Profile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()
    form = ProfileForm()
    
    if request.method == 'GET':
        # Pre-populate form with existing data
        form.name.data = profile.name
        form.description.data = profile.description
        form.website.data = profile.website
        form.location.data = profile.location
        form.is_public.data = profile.is_public
    
    if form.validate_on_submit():
        # Handle file upload for photo
        if form.photo.data and hasattr(form.photo.data, 'filename') and form.photo.data.filename:
            file = form.photo.data
            filename = secure_filename(file.filename)
            photo_filename = f"{current_user.id}_photo_{filename}"
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], photo_filename)
            file.save(file_path)
            profile.photo = photo_filename
        
        # Update profile fields
        profile.name = form.name.data
        profile.description = form.description.data
        profile.website = form.website.data
        profile.location = form.location.data
        profile.is_public = form.is_public.data
        
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profiles.detail', profile_id=profile.id))
    
    return render_template('profiles/edit.html', profile=profile, form=form)

@profiles_bp.route('/<int:profile_id>/delete', methods=['POST'])
@login_required
@require_permission('profiles', 'delete')
def delete_profile(profile_id):
    profile = Profile.query.filter_by(id=profile_id, user_id=current_user.id).first_or_404()
    
    # Prevent deletion of default profile
    if profile.is_default:
        flash('Cannot delete your default profile. This profile is required for account management.', 'error')
        return redirect(url_for('profiles.index'))
    
    # Delete all items associated with this profile
    Item.query.filter_by(profile_id=profile_id).delete()
    
    # Delete the profile
    db.session.delete(profile)
    db.session.commit()
    
    flash('Profile deleted successfully', 'success')
    return redirect(url_for('profiles.index'))

@profiles_bp.route('/item/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
@require_permission('items', 'update')
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    # Check if user owns this item
    if item.profile.user_id != current_user.id:
        flash('You do not have permission to edit this item', 'error')
        return redirect(url_for('auth.profile'))
    
    if request.method == 'POST':
        item.title = request.form.get('title')
        item.description = request.form.get('description')
        item.category = request.form.get('category')
        item.location = request.form.get('location')
        price = request.form.get('price')
        item.price = float(price) if price else None
        item.currency = request.form.get('currency', 'USD')
        
        db.session.commit()
        flash('Item updated successfully', 'success')
        return redirect(url_for('auth.profile'))
    
    return render_template('profiles/edit_item.html', item=item)

@profiles_bp.route('/item/<int:item_id>/delete', methods=['POST'])
@login_required
@require_permission('items', 'delete')
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    # Check if user owns this item
    if item.profile.user_id != current_user.id:
        if request.is_json:
            return jsonify({'success': False, 'message': 'Permission denied'})
        flash('You do not have permission to delete this item', 'error')
        return redirect(url_for('auth.profile'))
    
    db.session.delete(item)
    db.session.commit()
    
    if request.is_json:
        return jsonify({'success': True, 'message': 'Item deleted successfully'})
    
    flash('Item deleted successfully', 'success')
    return redirect(url_for('auth.profile'))

@profiles_bp.route('/items/<int:item_id>')
@login_required
def item_detail(item_id):
    """View item details with activity history"""
    item = Item.query.get_or_404(item_id)
    profile = Profile.query.get_or_404(item.profile_id)
    
    # Get activities for this item
    activities = Activity.query.filter_by(item_id=item_id).order_by(Activity.created_at.desc()).all()
    
    return render_template('profiles/item_detail.html', 
                         item=item, 
                         profile=profile, 
                         activities=activities)

@profiles_bp.route('/check-welcome-popup')
@login_required
def check_welcome_popup():
    """Check if user should see welcome popup (once per day)"""
    try:
        now = datetime.utcnow()
        should_show = True
        
        if current_user.last_welcome_popup:
            # Check if it's been at least 24 hours since last popup
            time_diff = now - current_user.last_welcome_popup
            should_show = time_diff >= timedelta(days=1)
        
        return jsonify({'show_popup': should_show})
    except Exception as e:
        return jsonify({'show_popup': False, 'error': str(e)})

@profiles_bp.route('/update-welcome-popup', methods=['POST'])
@login_required
def update_welcome_popup():
    """Update the user's last welcome popup time"""
    try:
        current_user.last_welcome_popup = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@profiles_bp.route('/users/<username>')
def user_profile(username):
    """User profile page"""
    user = User.query.filter_by(username=username).first_or_404()
    
    # Get user's items
    user_items = Item.query.filter_by(creator_id=user.id, creator_type='user').all()
    
    # Get user's organizations
    user_organizations = Organization.query.join(OrganizationMember).filter(
        OrganizationMember.user_id == user.id,
        OrganizationMember.status == 'active'
    ).all()
    
    return render_template('profiles/user_profile.html', 
                         user=user, 
                         items=user_items, 
                         organizations=user_organizations)
