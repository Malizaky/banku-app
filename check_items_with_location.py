#!/usr/bin/env python3
"""
Check items with locations in the database
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import Item

def check_items_with_location():
    """Check which items have locations"""
    app = create_app()
    
    with app.app_context():
        items_with_location = Item.query.filter(Item.location.isnot(None), Item.location != '').all()
        
        print(f"Found {len(items_with_location)} items with locations:")
        for item in items_with_location:
            print(f"Item ID: {item.id}")
            print(f"Title: {item.title}")
            print(f"Location: {item.location}")
            print(f"Location type: {type(item.location)}")
            print(f"Location length: {len(str(item.location)) if item.location else 0}")
            print("---")
        
        # Also check all items to see the total
        all_items = Item.query.all()
        print(f"Total items in database: {len(all_items)}")

if __name__ == "__main__":
    check_items_with_location()





