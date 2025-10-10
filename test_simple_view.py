#!/usr/bin/env python3
"""
Simple test to view item details
"""

import requests
import sys

def test_item_view():
    """Test viewing an item with location"""
    try:
        # Test with a session to simulate login
        session = requests.Session()
        
        # First, try to login
        login_data = {
            'email': 'admin',
            'password': 'admin123'
        }
        
        login_response = session.post('http://localhost:5000/auth/login', data=login_data)
        print(f"Login Status: {login_response.status_code}")
        
        if login_response.status_code == 200 or login_response.status_code == 302:
            # Now try to view the item
            item_response = session.get('http://localhost:5000/banks/item/16')
            print(f"Item View Status: {item_response.status_code}")
            
            if item_response.status_code == 200:
                print("✅ Item view successful!")
                # Check if the response contains error indicators
                if "Error Details" in item_response.text:
                    print("❌ Error page returned!")
                elif "dfsdf" in item_response.text:
                    print("✅ Item content found in response!")
                else:
                    print("⚠️  Unexpected response content")
                    
                # Save response for debugging
                with open('item_response.html', 'w', encoding='utf-8') as f:
                    f.write(item_response.text)
                print("📄 Response saved to item_response.html")
            else:
                print(f"❌ Item view failed with status {item_response.status_code}")
                print("Response preview:")
                print(item_response.text[:500])
        else:
            print(f"❌ Login failed with status {login_response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to Flask app. Make sure it's running on localhost:5000")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    test_item_view()





