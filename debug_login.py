#!/usr/bin/env python3
"""
Debug login form submission
"""

import requests
import sys
from urllib.parse import urljoin

def debug_login():
    """Debug login form submission"""
    try:
        session = requests.Session()
        
        # First, get the login page to see the form
        login_url = 'http://localhost:5000/auth/login?next=%2Fbanks%2Fitem%2F16'
        print(f"Getting login page: {login_url}")
        
        response = session.get(login_url)
        print(f"Login page status: {response.status_code}")
        
        if response.status_code == 200:
            # Check if the next parameter is in the form
            if 'name="next" value="/banks/item/16"' in response.text:
                print("✅ Next parameter found in form!")
            else:
                print("❌ Next parameter NOT found in form!")
                # Let's see what's actually in the form
                if 'name="next"' in response.text:
                    print("⚠️  Next field exists but value might be wrong")
                else:
                    print("❌ No next field at all")
        
        # Now try to submit the login form
        login_data = {
            'login_field': 'admin',
            'password': 'admin123',
            'next': '/banks/item/16'  # Explicitly set it
        }
        
        print(f"Submitting login with data: {login_data}")
        
        login_response = session.post('http://localhost:5000/auth/login', data=login_data, allow_redirects=False)
        print(f"Login response status: {login_response.status_code}")
        
        if login_response.status_code == 302:
            redirect_url = login_response.headers.get('Location', '')
            print(f"Redirect URL: {redirect_url}")
            
            if '/banks/item/16' in redirect_url:
                print("✅ Successfully redirected to item page!")
            elif '/dashboard' in redirect_url:
                print("❌ Still redirecting to dashboard")
            else:
                print(f"⚠️  Redirected to: {redirect_url}")
        else:
            print(f"❌ Login failed with status {login_response.status_code}")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    debug_login()





