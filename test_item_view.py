#!/usr/bin/env python3
"""
Test script to check item view functionality
"""

import requests
import sys

def test_item_view():
    """Test viewing an item with location"""
    try:
        # Test the item detail endpoint directly
        response = requests.get('http://localhost:5000/banks/item/10', timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response Length: {len(response.text)}")
        
        if response.status_code == 200:
            print("✅ Item view successful!")
            print("Response preview:")
            print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
        else:
            print("❌ Item view failed!")
            print("Response:")
            print(response.text[:1000])
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to Flask app. Make sure it's running on localhost:5000")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    test_item_view()





