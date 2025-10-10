#!/usr/bin/env python3
"""
Check specific item data
"""

import sqlite3
import os
import json

def check_item_data(item_id):
    """Check specific item data"""
    db_path = 'instance/app.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get specific item
    cursor.execute("""
        SELECT id, title, location, category, subcategory, type_data, images_media
        FROM item 
        WHERE id = ?
    """, (item_id,))
    
    item = cursor.fetchone()
    
    if item:
        item_id, title, location, category, subcategory, type_data, images_media = item
        print(f"Item ID: {item_id}")
        print(f"Title: {title}")
        print(f"Location: {location}")
        print(f"Category: {category}")
        print(f"Subcategory: {subcategory}")
        print(f"Type Data: {type_data}")
        print(f"Images Media: {images_media}")
        
        # Try to parse type_data as JSON
        if type_data:
            try:
                parsed_data = json.loads(type_data)
                print(f"✅ Type data is valid JSON")
                print(f"Type data content: {json.dumps(parsed_data, indent=2)}")
            except json.JSONDecodeError as e:
                print(f"❌ Type data is NOT valid JSON: {e}")
        else:
            print("❌ Type data is None/empty")
            
    else:
        print(f"Item {item_id} not found")
    
    conn.close()

if __name__ == "__main__":
    check_item_data(16)





