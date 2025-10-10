#!/usr/bin/env python3
"""
Test with proper redirect handling
"""

import requests
import sys
from urllib.parse import urljoin

def test_item_view_with_redirect():
    """Test viewing an item with proper redirect handling"""
    try:
        session = requests.Session()
        
        # First, try to access the item page directly (should redirect to login)
        item_url = 'http://localhost:5000/banks/item/16'
        print(f"Testing URL: {item_url}")
        
        # Try to get the item page first
        response = session.get(item_url, allow_redirects=False)
        print(f"Initial response status: {response.status_code}")
        
        if response.status_code == 302:  # Redirect to login
            print("✅ Redirected to login as expected")
            login_url = urljoin(item_url, response.headers['Location'])
            print(f"Login URL: {login_url}")
            
            # Now login with the next parameter
            login_data = {
                'email': 'admin',
                'password': 'admin123',
                'next': item_url  # This should redirect back to the item page
            }
            
            login_response = session.post(login_url, data=login_data, allow_redirects=False)
            print(f"Login response status: {login_response.status_code}")
            
            if login_response.status_code == 302:  # Should redirect back to item page
                final_url = urljoin(login_url, login_response.headers['Location'])
                print(f"Final redirect URL: {final_url}")
                
                # Get the final page
                final_response = session.get(final_url)
                print(f"Final response status: {final_response.status_code}")
                
                if final_response.status_code == 200:
                    if "dfsdf" in final_response.text:
                        print("✅ Successfully viewed item page!")
                    elif "Error Details" in final_response.text:
                        print("❌ Error page returned!")
                    else:
                        print("⚠️  Unexpected content")
                        
                    # Save response for debugging
                    with open('final_response.html', 'w', encoding='utf-8') as f:
                        f.write(final_response.text)
                    print("📄 Final response saved to final_response.html")
                else:
                    print(f"❌ Final request failed with status {final_response.status_code}")
            else:
                print(f"❌ Login didn't redirect as expected: {login_response.status_code}")
        else:
            print(f"❌ Expected redirect to login, got status {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    test_item_view_with_redirect()





