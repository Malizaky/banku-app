from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from models import Item, Bank, Tag, Profile, ProductCategory, SearchAnalytics, ItemVisibilityScore, ItemCredibilityScore, ItemReviewScore, ItemType, OrganizationType, Organization, User, db
from sqlalchemy import or_, and_
from datetime import datetime

banks_bp = Blueprint('banks', __name__)

@banks_bp.route('/')
@login_required
def index():
    banks = Bank.query.filter_by(is_active=True).order_by(Bank.sort_order.asc(), Bank.name.asc()).all()
    
    # Icon and color mapping for each bank type
    bank_icons = {
        'products': 'fas fa-box',
        'services': 'fas fa-cogs',
        'ideas': 'fas fa-lightbulb',
        'projects': 'fas fa-project-diagram',
        'funders': 'fas fa-dollar-sign',
        'events': 'fas fa-calendar-alt',
        'auctions': 'fas fa-gavel',
        'experiences': 'fas fa-star',
        'opportunities': 'fas fa-briefcase',
        'information': 'fas fa-database',
        'observations': 'fas fa-eye',
        'hidden_gems': 'fas fa-gem',
        'needs': 'fas fa-heart',
        'people': 'fas fa-users'
    }
    
    bank_colors = {
        'products': '#007bff',
        'services': '#28a745',
        'ideas': '#ffc107',
        'projects': '#17a2b8',
        'funders': '#28a745',
        'events': '#dc3545',
        'auctions': '#ffc107',
        'experiences': '#6f42c1',
        'opportunities': '#17a2b8',
        'information': '#007bff',
        'observations': '#6c757d',
        'hidden_gems': '#ffc107',
        'needs': '#dc3545',
        'people': '#28a745'
    }
    
    # Add item counts, icons, and colors for each bank
    for bank in banks:
        # Map bank types to item categories
        category_map = {
            'items': 'all_items',  # Special case: count all items
            'products': 'product',
            'services': 'service', 
            'ideas': 'idea',
            'projects': 'project',
            'funders': 'fund',
            'events': 'event',
            'auctions': 'auction',
            'experiences': 'experience',
            'opportunities': 'opportunity',
            'information': 'information',
            'observations': 'observation',
            'hidden_gems': 'hidden_gem',
            'needs': 'need',
            'people': 'people'
        }
        
        # Use smart filtering for item count
        if bank.bank_type == 'items':
            if bank.item_type_id:
                # Bank is configured for a specific item type
                item_type = ItemType.query.get(bank.item_type_id)
                if item_type:
                    bank.item_count = Item.query.filter_by(category=item_type.name, is_available=True).count()
                else:
                    bank.item_count = Item.query.filter_by(is_available=True).count()
            else:
                # Show all items if no specific type configured
                bank.item_count = Item.query.filter_by(is_available=True).count()
        elif bank.bank_type == 'organizations':
            if bank.organization_type_id:
                # Bank is configured for a specific organization type
                bank.item_count = Organization.query.filter_by(
                    organization_type_id=bank.organization_type_id,
                    is_public=True,
                    status='active'
                ).count()
            else:
                # Show all organizations if no specific type configured
                bank.item_count = Organization.query.filter_by(is_public=True, status='active').count()
        elif bank.bank_type == 'users':
            # Count users based on filter
            if bank.user_filter == 'public':
                bank.item_count = User.query.filter_by(is_active=True).count()  # Add public profile filter when available
            else:
                bank.item_count = User.query.filter_by(is_active=True).count()
        else:
            # Fallback to old system for backward compatibility
            category = category_map.get(bank.bank_type, bank.bank_type)
            if category == 'all_items':
                bank.item_count = Item.query.filter_by(is_available=True).count()
            else:
                bank.item_count = Item.query.filter_by(category=category, is_available=True).count()
        
        # Use database icon and color, fallback to defaults if not set
        if not bank.icon:
            bank.icon = bank_icons.get(bank.bank_type, 'fas fa-database')
        if not bank.color:
            bank.color = bank_colors.get(bank.bank_type, '#007bff')
    
    return render_template('banks/index.html', banks=banks)

@banks_bp.route('/product-categories')
@login_required
def product_categories():
    # Get main product categories (level 1)
    main_categories = ProductCategory.query.filter_by(level=1, is_active=True).all()
    
    # Convert to the format expected by the template
    categories = []
    for cat in main_categories:
        categories.append({
            'id': cat.id,
            'name': cat.name,
            'description': cat.description,
            'icon': get_category_icon(cat.name),
            'color': get_category_color(cat.name)
        })
    
    return render_template('banks/product_categories.html', categories=categories)

def get_category_icon(category_name):
    """Get appropriate icon for category"""
    icon_map = {
        'Physical Products': 'fas fa-cube',
        'Digital Products': 'fas fa-laptop-code',
        'Knowledge Products': 'fas fa-graduation-cap',
        'Ideas': 'fas fa-lightbulb',
        'Plans & Strategies': 'fas fa-project-diagram',
        'Imaginations & Innovations': 'fas fa-rocket',
        'Rights & Licenses': 'fas fa-certificate'
    }
    return icon_map.get(category_name, 'fas fa-box')

def get_category_color(category_name):
    """Get appropriate color for category"""
    color_map = {
        'Physical Products': 'primary',
        'Digital Products': 'info',
        'Knowledge Products': 'warning',
        'Ideas': 'danger',
        'Plans & Strategies': 'secondary',
        'Imaginations & Innovations': 'purple',
        'Rights & Licenses': 'success'
    }
    return color_map.get(category_name, 'primary')


@banks_bp.route('/<bank_type>')
@login_required
def bank_items(bank_type):
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')
    
    # Map bank types to actual item types
    bank_type_mapping = {
        'items': 'all_items',  # Special case: show all items regardless of category
        'products': 'product',
        'services': 'service', 
        'needs': 'need',  # Changed from 'idea' to 'need' to match your need items
        'ideas': 'idea',
        'projects': 'project',
        'people': 'people',
        'funders': 'fund',
        'information': 'information',
        'experiences': 'experience',
        'opportunities': 'opportunity',
        'events': 'event',
        'auctions': 'auction',
        'observations': 'observation',
        'hidden_gems': 'hidden_gem',
        # Product subcategories
        'physical': 'product',
        'digital': 'product',
        'knowledge': 'product',
        'rights_licenses': 'product',
        'plans_strategies': 'product',
        'imagination_innovations': 'product'
    }
    
    actual_item_type = bank_type_mapping.get(bank_type, bank_type)
    
    # Build query using smart filtering
    query = Item.query.join(Profile).filter(Item.is_available == True)
    
    # Apply smart filtering based on bank configuration
    # First, get the bank to check if it has specific filtering configured
    bank = Bank.query.filter_by(bank_type=bank_type).first()
    
    if bank and bank.item_type_id:
        # Bank is configured for a specific item type
        item_type = ItemType.query.get(bank.item_type_id)
        if item_type:
            query = query.filter(Item.category == item_type.name)
    elif actual_item_type != 'all_items':
        # Fallback to old mapping system for backward compatibility
        query = query.filter(Item.category == actual_item_type)
    
    # If it's a product subcategory, filter by subcategory
    if bank_type in ['physical', 'digital', 'knowledge', 'rights_licenses', 'plans_strategies', 'imagination_innovations']:
        query = query.filter(Item.subcategory == bank_type)
    
    # Apply filters
    if search:
        query = query.filter(
            or_(
                Item.title.contains(search),
                Item.description.contains(search)
            )
        )
    
    if category:
        query = query.filter(Item.category == category)
    
    # For products, add product category filtering
    product_category_id = request.args.get('product_category_id', type=int)
    if bank_type == 'products' and product_category_id:
        query = query.filter(Item.product_category_id == product_category_id)
    
    if location:
        query = query.filter(Item.location.contains(location))
    
    if min_price is not None:
        query = query.filter(Item.price >= min_price)
    
    if max_price is not None:
        query = query.filter(Item.price <= max_price)
    
    # Apply sorting
    if sort_by == 'price':
        if sort_order == 'asc':
            query = query.order_by(Item.price.asc())
        else:
            query = query.order_by(Item.price.desc())
    elif sort_by == 'rating':
        if sort_order == 'asc':
            query = query.order_by(Item.rating.asc())
        else:
            query = query.order_by(Item.rating.desc())
    else:  # created_at
        if sort_order == 'asc':
            query = query.order_by(Item.created_at.asc())
        else:
            query = query.order_by(Item.created_at.desc())
    
    # Add scoring data to the query
    query = query.options(
        db.joinedload(Item.visibility_score),
        db.joinedload(Item.credibility_score),
        db.joinedload(Item.review_score)
    )
    
    items = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Debug: Log query details
    print(f"DEBUG - Bank type: {bank_type}, Actual item type: {actual_item_type}")
    print(f"DEBUG - Total items found: {items.total}")
    print(f"DEBUG - Query filters: category={actual_item_type}, is_available=True")
    
    # Get filter options
    if actual_item_type == 'all_items':
        # For 'items' bank, show all categories
        categories = db.session.query(Item.category).filter(
            Item.category.isnot(None)
        ).distinct().all()
        categories = [cat[0] for cat in categories]
        
        locations = db.session.query(Item.location).filter(
            Item.location.isnot(None)
        ).distinct().all()
        locations = [loc[0] for loc in locations]
    else:
        # For specific bank types, filter by category
        categories = db.session.query(Item.category).filter(
            Item.category == actual_item_type,
            Item.category.isnot(None)
        ).distinct().all()
        categories = [cat[0] for cat in categories]
        
        locations = db.session.query(Item.location).filter(
            Item.category == actual_item_type,
            Item.location.isnot(None)
        ).distinct().all()
        locations = [loc[0] for loc in locations]
    
    # Get product categories for products bank
    product_categories = []
    if bank_type == 'products':
        product_categories = ProductCategory.query.filter_by(level=1, is_active=True).all()
    
    # Track search analytics
    try:
        track_search_analytics(actual_item_type, search, category, location, product_category_id)
    except Exception as e:
        print(f"Error tracking search analytics: {e}")
    
    return render_template('banks/items.html', 
                         items=items,
                         bank_type=bank_type,
                         categories=categories,
                         locations=locations,
                         product_categories=product_categories,
                         search=search,
                         category=category,
                         location=location,
                         min_price=min_price,
                         max_price=max_price,
                         sort_by=sort_by,
                         sort_order=sort_order)

@banks_bp.route('/bank/<int:bank_id>')
@login_required
def bank_detail(bank_id):
    bank = Bank.query.get_or_404(bank_id)
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')
    
    # Map bank types to actual item types
    bank_type_mapping = {
        'organizations': 'organizations',
        'users': 'users',
        'items': 'all_items',  # Special case: show all items regardless of category
        'needs': 'need',  # Changed from 'idea' to 'need' to match your need items
        'ideas': 'idea',
        'products': 'product',
        'services': 'service', 
        'people': 'people',
        'funders': 'fund',
        'information': 'information',
        'experiences': 'experience',
        'opportunities': 'opportunity',
        'events': 'event',
        'observations': 'observation',
        'hidden_gems': 'hidden_gem'
    }
    
    actual_item_type = bank_type_mapping.get(bank.bank_type, bank.bank_type)
    
    # Build query based on bank type using smart filtering
    if bank.bank_type == 'organizations':
        # For organizations, we need to query Organization model
        from models import Organization
        query = Organization.query.filter(Organization.is_public == True)
        if bank.organization_type_id:
            # Use smart filtering - organization_type_id
            query = query.filter(Organization.organization_type_id == bank.organization_type_id)
        elif bank.organization_type:
            # Fallback to old organization_type field
            org_type = OrganizationType.query.filter_by(name=bank.organization_type).first()
            if org_type:
                query = query.filter(Organization.organization_type_id == org_type.id)
    elif bank.bank_type == 'users':
        # For users, query User model
        from models import User
        query = User.query.filter(User.is_active == True)
        # Apply user filter if configured
        if bank.user_filter == 'public':
            # Add public profile filter when available
            pass  # For now, show all active users
    else:
        # For items and needs, query Item model using smart filtering
        query = Item.query.join(Profile).filter(Item.is_available == True)
        
        if bank.item_type_id:
            # Bank is configured for a specific item type - use smart filtering
            item_type = ItemType.query.get(bank.item_type_id)
            if item_type:
                query = query.filter(Item.category == item_type.name)
        elif actual_item_type != 'all_items':
            # Fallback to old mapping system for backward compatibility
            query = query.filter(Item.category == actual_item_type)
    
    # Apply filters
    if search:
        if bank.bank_type == 'organizations':
            query = query.filter(Organization.name.contains(search))
        elif bank.bank_type == 'users':
            query = query.filter(
                or_(
                    User.first_name.contains(search),
                    User.last_name.contains(search),
                    User.username.contains(search)
                )
            )
        else:
            query = query.filter(
                or_(
                    Item.title.contains(search),
                    Item.description.contains(search)
                )
            )
    
    if category and bank.bank_type not in ['organizations', 'users']:
        query = query.filter(Item.category == category)
    
    if location and bank.bank_type not in ['organizations', 'users']:
        query = query.filter(Item.location.contains(location))
    
    if min_price is not None and bank.bank_type not in ['organizations', 'users']:
        query = query.filter(Item.price >= min_price)
    
    if max_price is not None and bank.bank_type not in ['organizations', 'users']:
        query = query.filter(Item.price <= max_price)
    
    # Apply sorting
    if bank.bank_type == 'organizations':
        if sort_by == 'name':
            if sort_order == 'asc':
                query = query.order_by(Organization.name.asc())
            else:
                query = query.order_by(Organization.name.desc())
        else:  # created_at
            if sort_order == 'asc':
                query = query.order_by(Organization.created_at.asc())
            else:
                query = query.order_by(Organization.created_at.desc())
    elif bank.bank_type == 'users':
        if sort_by == 'name':
            if sort_order == 'asc':
                query = query.order_by(User.first_name.asc())
            else:
                query = query.order_by(User.first_name.desc())
        else:  # created_at
            if sort_order == 'asc':
                query = query.order_by(User.created_at.asc())
            else:
                query = query.order_by(User.created_at.desc())
    else:
        if sort_by == 'price':
            if sort_order == 'asc':
                query = query.order_by(Item.price.asc())
            else:
                query = query.order_by(Item.price.desc())
        elif sort_by == 'rating':
            if sort_order == 'asc':
                query = query.order_by(Item.rating.asc())
            else:
                query = query.order_by(Item.rating.desc())
        else:  # created_at
            if sort_order == 'asc':
                query = query.order_by(Item.created_at.asc())
            else:
                query = query.order_by(Item.created_at.desc())
    
    items = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get filter options
    categories = []
    locations = []
    if bank.bank_type not in ['organizations', 'users']:
        categories = db.session.query(Item.category).filter(
            Item.category == actual_item_type,
            Item.category.isnot(None)
        ).distinct().all()
        categories = [cat[0] for cat in categories]
        
        locations = db.session.query(Item.location).filter(
            Item.category == actual_item_type,
            Item.location.isnot(None)
        ).distinct().all()
        locations = [loc[0] for loc in locations]
    
    return render_template('banks/bank_detail.html', 
                         bank=bank,
                         items=items,
                         categories=categories,
                         locations=locations,
                         search=search,
                         category=category,
                         location=location,
                         min_price=min_price,
                         max_price=max_price,
                         sort_by=sort_by,
                         sort_order=sort_order)

@banks_bp.route('/item/<int:item_id>')
@login_required
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)
    
    # Get similar items
    similar_items = Item.query.filter(
        Item.category == item.category,
        Item.id != item.id,
        Item.is_available == True
    ).limit(6).all()
    
    return render_template('banks/item_detail.html', 
                         item=item, 
                         similar_items=similar_items)

@banks_bp.route('/debug-items')
@login_required
def debug_items():
    items = Item.query.all()
    debug_info = []
    for item in items:
        debug_info.append({
            'id': item.id,
            'title': item.title,
            'category': item.category,
            'subcategory': item.subcategory,
            'is_available': item.is_available,
            'profile_id': item.profile_id
        })
    return jsonify({
        'total_items': len(items),
        'items': debug_info
    })

@banks_bp.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    bank_type = request.args.get('type', '')
    
    if not query:
        return jsonify({'items': []})
    
    # Search across all items
    search_query = Item.query.join(Profile).filter(
        Item.is_available == True,
        or_(
            Item.title.contains(query),
            Item.description.contains(query),
            Item.category.contains(query)
        )
    )
    
    if bank_type:
        search_query = search_query.filter(Item.category == bank_type)
    
    items = search_query.limit(10).all()
    
    results = []
    for item in items:
        results.append({
            'id': item.id,
            'title': item.title,
            'description': item.description[:100] + '...' if len(item.description) > 100 else item.description,
            'type': item.category,
            'price': item.price,
            'rating': item.rating,
            'profile_name': item.profile.name
        })
    
    return jsonify({'items': results})

@banks_bp.route('/recommendations')
@login_required
def recommendations():
    # Get user's tags and preferences
    user_tags = [tag.name for tag in current_user.tags]
    
    # Find items that match user's tags or are popular
    recommended_items = Item.query.join(Profile).filter(
        Item.is_available == True,
        Item.is_verified == True
    ).order_by(Item.rating.desc(), Item.review_count.desc()).limit(10).all()
    
    return jsonify({
        'items': [{
            'id': item.id,
            'title': item.title,
            'description': item.description[:100] + '...' if len(item.description) > 100 else item.description,
            'type': item.category,
            'price': item.price,
            'rating': item.rating,
            'profile_name': item.profile.name
        } for item in recommended_items]
    })

@banks_bp.route('/stats')
@login_required
def stats():
    # Get bank statistics
    stats = {
        'products': Item.query.filter_by(category='product', is_available=True).count(),
        'services': Item.query.filter_by(category='service', is_available=True).count(),
        'needs': Item.query.filter_by(category='idea', is_available=True).count(),
        'people': Item.query.filter_by(category='people', is_available=True).count(),
        'funders': Item.query.filter_by(category='funding', is_available=True).count(),
        'information': Item.query.filter_by(category='information', is_available=True).count(),
        'experiences': Item.query.filter_by(category='experience', is_available=True).count(),
        'opportunities': Item.query.filter_by(category='opportunity', is_available=True).count(),
        'events': Item.query.filter_by(category='event', is_available=True).count(),
        'observations': Item.query.filter_by(category='observation', is_available=True).count(),
        'hidden_gems': Item.query.filter_by(category='hidden_gem', is_available=True).count()
    }
    return jsonify(stats)

@banks_bp.route('/product-stats')
@login_required
def product_stats():
    # Get product statistics
    total_products = Item.query.filter_by(category='product', is_available=True).count()
    verified_products = Item.query.filter_by(category='product', is_available=True, is_verified=True).count()
    
    # Calculate average rating
    avg_rating_result = db.session.query(db.func.avg(Item.rating)).filter(
        Item.category == 'product',
        Item.is_available == True,
        Item.rating > 0
    ).scalar()
    avg_rating = float(avg_rating_result) if avg_rating_result else 0.0
    
    # Count active sellers (profiles with products)
    active_sellers = db.session.query(Profile).join(Item).filter(
        Item.category == 'product',
        Item.is_available == True
    ).distinct().count()
    
    return jsonify({
        'total_products': total_products,
        'verified_products': verified_products,
        'avg_rating': avg_rating,
        'active_sellers': active_sellers
    })

@banks_bp.route('/product-categories/<int:category_id>')
@login_required
def product_subcategories(category_id):
    # Get the main category
    main_category = ProductCategory.query.get_or_404(category_id)
    
    # Get subcategories (level 2)
    subcategories = ProductCategory.query.filter_by(parent_id=category_id, level=2, is_active=True).all()
    
    return render_template('banks/product_subcategories.html', 
                         main_category=main_category, 
                         subcategories=subcategories)

@banks_bp.route('/product-categories/<int:category_id>/<int:subcategory_id>')
@login_required
def product_sub_subcategories(category_id, subcategory_id):
    # Get the subcategory
    subcategory = ProductCategory.query.get_or_404(subcategory_id)
    
    # Get sub-subcategories (level 3)
    sub_subcategories = ProductCategory.query.filter_by(parent_id=subcategory_id, level=3, is_active=True).all()
    
    return render_template('banks/product_sub_subcategories.html', 
                         subcategory=subcategory, 
                         sub_subcategories=sub_subcategories)

@banks_bp.route('/product-categories/<int:category_id>/<int:subcategory_id>/<int:sub_subcategory_id>')
@login_required
def product_items_by_category(category_id, subcategory_id, sub_subcategory_id):
    # Get the final category
    final_category = ProductCategory.query.get_or_404(sub_subcategory_id)
    
    # Get items for this category
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search = request.args.get('search', '')
    
    # Build query
    query = Item.query.join(Profile).filter(
        Item.category == 'product',
        Item.product_category_id == sub_subcategory_id,
        Item.is_available == True
    )
    
    # Apply search filter
    if search:
        query = query.filter(
            or_(
                Item.title.contains(search),
                Item.description.contains(search)
            )
        )
    
    items = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('banks/product_items.html', 
                         category=final_category,
                         items=items,
                         search=search)

@banks_bp.route('/update-banks-data')
@login_required
def update_banks_data():
    from flask import flash, redirect, url_for
    
    # Delete all existing banks
    Bank.query.delete()
    
    # Create the 14 banks requested (Ideas before Projects)
    banks_data = [
        {'name': 'Bank of Products', 'bank_type': 'products', 'description': 'Physical & digital items'},
        {'name': 'Bank of Services', 'bank_type': 'services', 'description': 'Professional services'},
        {'name': 'Bank of Ideas', 'bank_type': 'ideas', 'description': 'Creative concepts'},
        {'name': 'Bank of Projects', 'bank_type': 'projects', 'description': 'Project collaborations'},
        {'name': 'Bank of Funds', 'bank_type': 'funders', 'description': 'Funding opportunities'},
        {'name': 'Bank of Events', 'bank_type': 'events', 'description': 'Organized gatherings'},
        {'name': 'Bank of Auctions', 'bank_type': 'auctions', 'description': 'Competitive bidding'},
        {'name': 'Bank of Experiences', 'bank_type': 'experiences', 'description': 'Shared experiences'},
        {'name': 'Bank of Opportunities', 'bank_type': 'opportunities', 'description': 'Business opportunities'},
        {'name': 'Bank of Informations', 'bank_type': 'information', 'description': 'Knowledge & insights'},
        {'name': 'Bank of Observations', 'bank_type': 'observations', 'description': 'Market observations'},
        {'name': 'Bank of Hidden Gems', 'bank_type': 'hidden_gems', 'description': 'Undiscovered treasures'},
        {'name': 'Bank of Needs', 'bank_type': 'needs', 'description': 'What people need'},
        {'name': 'Bank of People', 'bank_type': 'people', 'description': 'Connect with others'}
    ]
    
    for bank_info in banks_data:
        bank = Bank(
            name=bank_info['name'],
            bank_type=bank_info['bank_type'],
            description=bank_info['description'],
            is_active=True
        )
        db.session.add(bank)
    
    db.session.commit()
    
    flash(f'Successfully updated {len(banks_data)} banks!', 'success')
    return redirect(url_for('admin.index'))

def track_search_analytics(item_type, search_term, category, location, product_category_id):
    """Track search analytics for optimization"""
    try:
        # Track general search
        if search_term:
            existing = SearchAnalytics.query.filter_by(
                item_type=item_type,
                search_term=search_term,
                filter_field='general_search',
                filter_value='title_description'
            ).first()
            
            if existing:
                existing.search_count += 1
                existing.last_searched = datetime.utcnow()
            else:
                analytics = SearchAnalytics(
                    item_type=item_type,
                    search_term=search_term,
                    filter_field='general_search',
                    filter_value='title_description',
                    search_count=1,
                    user_id=current_user.id if current_user.is_authenticated else None
                )
                db.session.add(analytics)
        
        # Track category filter
        if category:
            existing = SearchAnalytics.query.filter_by(
                item_type=item_type,
                filter_field='category',
                filter_value=category
            ).first()
            
            if existing:
                existing.search_count += 1
                existing.last_searched = datetime.utcnow()
            else:
                analytics = SearchAnalytics(
                    item_type=item_type,
                    filter_field='category',
                    filter_value=category,
                    search_count=1,
                    user_id=current_user.id if current_user.is_authenticated else None
                )
                db.session.add(analytics)
        
        # Track location filter
        if location:
            existing = SearchAnalytics.query.filter_by(
                item_type=item_type,
                filter_field='location',
                filter_value=location
            ).first()
            
            if existing:
                existing.search_count += 1
                existing.last_searched = datetime.utcnow()
            else:
                analytics = SearchAnalytics(
                    item_type=item_type,
                    filter_field='location',
                    filter_value=location,
                    search_count=1,
                    user_id=current_user.id if current_user.is_authenticated else None
                )
                db.session.add(analytics)
        
        # Track product category filter
        if product_category_id:
            existing = SearchAnalytics.query.filter_by(
                item_type=item_type,
                filter_field='product_category_id',
                filter_value=str(product_category_id)
            ).first()
            
            if existing:
                existing.search_count += 1
                existing.last_searched = datetime.utcnow()
            else:
                analytics = SearchAnalytics(
                    item_type=item_type,
                    filter_field='product_category_id',
                    filter_value=str(product_category_id),
                    search_count=1,
                    user_id=current_user.id if current_user.is_authenticated else None
                )
                db.session.add(analytics)
        
        db.session.commit()
        
    except Exception as e:
        print(f"Error in track_search_analytics: {e}")
        db.session.rollback()
