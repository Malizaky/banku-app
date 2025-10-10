#!/usr/bin/env python3
"""
Simple check for items with locations
"""

import sqlite3
import os

def check_items_with_location():
    """Check items with locations using direct SQLite"""
    db_path = 'instance/app.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get items with locations
    cursor.execute("""
        SELECT id, title, location, category, subcategory 
        FROM item 
        WHERE location IS NOT NULL AND location != ''
        ORDER BY id DESC
    """)
    
    items = cursor.fetchall()
    
    print(f"Found {len(items)} items with locations:")
    for item in items:
        item_id, title, location, category, subcategory = item
        print(f"ID: {item_id}")
        print(f"Title: {title}")
        print(f"Location: {location}")
        print(f"Category: {category}")
        print(f"Subcategory: {subcategory}")
        print("---")
    
    conn.close()
    
    # Suggest which item to test
    if items:
        latest_item = items[0]
        print(f"\n🔍 Test this item: http://localhost:5000/banks/item/{latest_item[0]}")
        print(f"Item: {latest_item[1]}")

if __name__ == "__main__":
    check_items_with_location()





