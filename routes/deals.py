from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from models import Deal, DealItem, DealMessage, Item, User, UserNeed, UserRole, Role, Earning, Notification, Profile, db
from utils.permissions import require_permission
from datetime import datetime

deals_bp = Blueprint('deals', __name__)

@deals_bp.route('/')
@login_required
@require_permission('deals', 'read')
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    status_filter = request.args.get('status', 'all')
    
    # Build query based on user's role
    query = Deal.query.filter(
        (Deal.provider_id == current_user.id) | 
        (Deal.consumer_id == current_user.id) |
        (Deal.connector_id == current_user.id)
    )
    
    if status_filter != 'all':
        query = query.filter(Deal.status == status_filter)
    
    deals = query.order_by(Deal.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('deals/index.html', deals=deals, status_filter=status_filter)

@deals_bp.route('/create', methods=['GET', 'POST'])
@login_required
@require_permission('deals', 'create')
def create():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        
        # Get data from form
        consumer_id = data.get('consumer_id')
        provider_id = data.get('provider_id')
        need_url = data.get('need_url')
        item_url = data.get('item_url')
        connector_id = data.get('connector_id')
        title = data.get('title')
        description = data.get('description')
        total_amount = float(data.get('total_amount', 0))
        
        # Set connector to current user if not specified
        if not connector_id:
            connector_id = current_user.id
        
        # Extract IDs from URLs
        need_id = None
        item_id = None
        if need_url:
            need_match = need_url.split('/needs/')[-1].split('/')[0]
            if need_match.isdigit():
                need_id = int(need_match)
        if item_url:
            item_match = item_url.split('/items/')[-1].split('/')[0]
            if item_match.isdigit():
                item_id = int(item_match)
        
        if not provider_id or not consumer_id or not need_url or not item_url or not need_id or not item_id:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Valid need and item URLs are required'})
            flash('Valid need and item URLs are required', 'error')
            return render_template('deals/create.html')
        
        if not title or not description:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Title and description are required'})
            flash('Title and description are required', 'error')
            return render_template('deals/create.html')
        
        if total_amount <= 0:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Total amount must be greater than 0'})
            flash('Total amount must be greater than 0', 'error')
            return render_template('deals/create.html')
        
        # Create deal
        deal = Deal(
            provider_id=provider_id,
            consumer_id=consumer_id,
            connector_id=connector_id,
            title=title,
            description=description,
            total_amount=total_amount,
            currency=data.get('currency', 'USD'),
            escrow_amount=total_amount * 0.1  # 10% escrow
        )
        
        db.session.add(deal)
        db.session.flush()  # Get deal ID
        
        # Add the selected item to deal
        item = Item.query.get(item_id)
        if item:
            deal_item = DealItem(
                deal_id=deal.id,
                item_id=item.id,
                unit_price=item.price or 0
            )
            db.session.add(deal_item)
        
        # Create system message
        system_message = DealMessage(
            deal_id=deal.id,
            sender_id=current_user.id,
            message=f"Deal created by {current_user.first_name} {current_user.last_name}",
            is_system=True
        )
        db.session.add(system_message)
        
        # Create notifications
        provider = User.query.get(provider_id)
        consumer = User.query.get(consumer_id)
        
        if provider:
            notification = Notification(
                user_id=provider.id,
                title="New Deal Created",
                message=f"A new deal '{title}' has been created with you as provider",
                notification_type="deal_created",
                data={'deal_id': deal.id}
            )
            db.session.add(notification)
        
        if consumer and consumer.id != current_user.id:
            notification = Notification(
                user_id=consumer.id,
                title="New Deal Created",
                message=f"A new deal '{title}' has been created for you",
                notification_type="deal_created",
                data={'deal_id': deal.id}
            )
            db.session.add(notification)
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Deal created successfully',
                'deal_id': deal.id
            })
        
        flash('Deal created successfully', 'success')
        return redirect(url_for('deals.detail', deal_id=deal.id))
    
    return render_template('deals/create.html')

@deals_bp.route('/<int:deal_id>')
@login_required
@require_permission('deals', 'read')
def detail(deal_id):
    deal = Deal.query.get_or_404(deal_id)
    
    # Check if user has access to this deal
    if not (deal.provider_id == current_user.id or 
            deal.consumer_id == current_user.id or 
            deal.connector_id == current_user.id):
        flash('You do not have access to this deal', 'error')
        return redirect(url_for('deals.index'))
    
    # Get deal messages
    messages = DealMessage.query.filter_by(deal_id=deal_id)\
        .order_by(DealMessage.created_at.asc()).all()
    
    # Get deal needs (needs associated with this deal)
    # For now, we'll get needs from the consumer - in a real implementation,
    # you might want to store deal-need relationships in the database
    deal_needs = UserNeed.query.filter_by(user_id=deal.consumer_id).limit(5).all()
    
    # Get deal activities (combine messages and deal events)
    deal_activities = []
    
    # Add deal creation activity
    deal_activities.append({
        'type': 'deal_created',
        'title': 'Deal Created',
        'description': f'Deal "{deal.title}" was created',
        'created_at': deal.created_at,
        'user': deal.connector or deal.provider
    })
    
    # Add status change activities from messages
    for message in messages:
        if message.is_system and 'status changed' in message.message.lower():
            deal_activities.append({
                'type': 'status_changed',
                'title': 'Status Updated',
                'description': message.message,
                'created_at': message.created_at,
                'user': message.sender
            })
        elif not message.is_system:
            deal_activities.append({
                'type': 'message_sent',
                'title': 'Message Sent',
                'description': message.message[:100] + ('...' if len(message.message) > 100 else ''),
                'created_at': message.created_at,
                'user': message.sender
            })
    
    # Add item addition activities
    for deal_item in deal.items:
        deal_activities.append({
            'type': 'item_added',
            'title': 'Item Added',
            'description': f'Item "{deal_item.item.title}" was added to the deal',
            'created_at': deal.created_at,  # Use deal creation time as approximation
            'user': deal.provider
        })
    
    # Sort activities by creation time (newest first)
    deal_activities.sort(key=lambda x: x['created_at'], reverse=True)
    
    return render_template('deals/detail.html', deal=deal, messages=messages, deal_needs=deal_needs, deal_activities=deal_activities)

@deals_bp.route('/<int:deal_id>/update-status', methods=['POST'])
@login_required
@require_permission('deals', 'update')
def update_status(deal_id):
    deal = Deal.query.get_or_404(deal_id)
    
    # Check if user has permission to update status
    if not (deal.provider_id == current_user.id or 
            deal.consumer_id == current_user.id or 
            deal.connector_id == current_user.id):
        return jsonify({'success': False, 'message': 'Permission denied'})
    
    data = request.get_json()
    new_status = data.get('status')
    
    if new_status not in ['pending', 'in_progress', 'completed', 'cancelled']:
        return jsonify({'success': False, 'message': 'Invalid status'})
    
    old_status = deal.status
    deal.status = new_status
    
    if new_status == 'completed':
        deal.completed_at = datetime.utcnow()
        
        # Calculate earnings
        commission = deal.total_amount * deal.commission_rate
        provider_earning = deal.total_amount - commission
        
        # Create earnings records
        if deal.connector_id:
            connector_earning = Earning(
                user_id=deal.connector_id,
                deal_id=deal.id,
                amount=commission * 0.5,  # 50% of commission to connector
                earning_type='connector',
                description=f'Commission from deal: {deal.title}',
                status='pending'
            )
            db.session.add(connector_earning)
        
        provider_earning_record = Earning(
            user_id=deal.provider_id,
            deal_id=deal.id,
            amount=provider_earning,
            earning_type='deal_completion',
            description=f'Payment from deal: {deal.title}',
            status='pending'
        )
        db.session.add(provider_earning_record)
    
    # Create system message
    system_message = DealMessage(
        deal_id=deal.id,
        sender_id=current_user.id,
        message=f"Deal status changed from {old_status} to {new_status}",
        is_system=True
    )
    db.session.add(system_message)
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Status updated successfully'})

@deals_bp.route('/<int:deal_id>/message', methods=['POST'])
@login_required
@require_permission('deals', 'update')
def send_message(deal_id):
    deal = Deal.query.get_or_404(deal_id)
    
    # Check if user has access to this deal
    if not (deal.provider_id == current_user.id or 
            deal.consumer_id == current_user.id or 
            deal.connector_id == current_user.id):
        return jsonify({'success': False, 'message': 'Permission denied'})
    
    data = request.get_json()
    message_text = data.get('message')
    
    if not message_text:
        return jsonify({'success': False, 'message': 'Message cannot be empty'})
    
    message = DealMessage(
        deal_id=deal_id,
        sender_id=current_user.id,
        message=message_text
    )
    
    db.session.add(message)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Message sent successfully'})

@deals_bp.route('/<int:deal_id>/update-status', methods=['POST'])
@login_required
def update_deal_status(deal_id):
    """Update deal status via AJAX"""
    deal = Deal.query.get_or_404(deal_id)
    
    # Check if user has permission to update this deal
    if not (deal.provider_id == current_user.id or 
            deal.consumer_id == current_user.id or 
            deal.connector_id == current_user.id):
        return jsonify({'success': False, 'message': 'Permission denied'})
    
    data = request.get_json()
    new_status = data.get('status')
    
    if not new_status:
        return jsonify({'success': False, 'message': 'Status is required'})
    
    if new_status not in ['pending', 'in_progress', 'completed', 'cancelled']:
        return jsonify({'success': False, 'message': 'Invalid status'})
    
    old_status = deal.status
    deal.status = new_status
    deal.updated_at = datetime.utcnow()
    
    # Create system message
    system_message = DealMessage(
        deal_id=deal.id,
        sender_id=current_user.id,
        message=f"Deal status changed from {old_status} to {new_status} by {current_user.first_name} {current_user.last_name}",
        is_system=True
    )
    db.session.add(system_message)
    
    # Create notifications for other participants
    participants = [deal.provider, deal.consumer]
    if deal.connector:
        participants.append(deal.connector)
    
    for participant in participants:
        if participant and participant.id != current_user.id:
            notification = Notification(
                user_id=participant.id,
                title="Deal Status Updated",
                message=f"Deal '{deal.title}' status changed to {new_status.replace('_', ' ').title()}",
                notification_type="deal_status_update",
                data={'deal_id': deal.id, 'status': new_status}
            )
            db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Deal status updated to {new_status.replace("_", " ").title()}'
    })

@deals_bp.route('/api/needs/<int:need_id>')
@login_required
def api_get_need(need_id):
    """API endpoint to get need data by ID"""
    need = UserNeed.query.get_or_404(need_id)
    
    return jsonify({
        'success': True,
        'need': {
            'id': need.id,
            'title': need.title,
            'description': need.description,
            'user_id': need.user_id,
            'user': {
                'id': need.user.id,
                'first_name': need.user.first_name,
                'last_name': need.user.last_name,
                'email': need.user.email
            }
        }
    })

@deals_bp.route('/api/items/<int:item_id>')
@login_required
def api_get_item(item_id):
    """API endpoint to get item data by ID"""
    item = Item.query.get_or_404(item_id)
    
    return jsonify({
        'success': True,
        'item': {
            'id': item.id,
            'title': item.title,
            'description': item.description,
            'price': item.price,
            'creator_id': item.creator_id,
            'creator': {
                'id': item.creator.id,
                'first_name': item.creator.first_name,
                'last_name': item.creator.last_name,
                'email': item.creator.email
            }
        }
    })

@deals_bp.route('/api/users/<int:user_id>')
@login_required
def api_get_user(user_id):
    """API endpoint to get user data by ID"""
    user = User.query.get_or_404(user_id)
    
    return jsonify({
        'success': True,
        'user': {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'username': user.username
        }
    })
