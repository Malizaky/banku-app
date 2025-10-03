#!/usr/bin/env python3
"""
Advanced Data Collector Examples

This script demonstrates how to use the advanced data collector system
to scrape various websites and auto-fill chatbot forms.
"""

from utils.advanced_data_collector import advanced_collector

def example_google_maps_scraper():
    """Example: Scrape Google Maps for business information"""
    print("=== Google Maps Scraper Example ===")
    
    # Scrape restaurants in Dubai
    results = advanced_collector.scrape_google_maps("restaurants", "Dubai")
    
    print(f"Found {len(results)} restaurants:")
    for i, restaurant in enumerate(results[:3]):  # Show first 3
        print(f"{i+1}. {restaurant}")
    
    return results

def example_wikipedia_scraper():
    """Example: Scrape Wikipedia for company information"""
    print("\n=== Wikipedia Scraper Example ===")
    
    # Scrape information about a company
    results = advanced_collector.scrape_wikipedia("Apple Inc.")
    
    print(f"Found {len(results)} Wikipedia entries:")
    for i, entry in enumerate(results[:3]):  # Show first 3
        print(f"{i+1}. {entry}")
    
    return results

def example_custom_website_scraper():
    """Example: Scrape any custom website"""
    print("\n=== Custom Website Scraper Example ===")
    
    # Example: Scrape a news website
    url = "https://news.ycombinator.com"
    selectors = {
        'title': '.titleline > a',
        'score': '.score',
        'comments': '.subtext a:last-child'
    }
    
    results = advanced_collector.scrape_website(url, selectors)
    
    print(f"Found {len(results)} news items:")
    for i, item in enumerate(results[:3]):  # Show first 3
        print(f"{i+1}. {item}")
    
    return results

def example_auto_fill_chatbot():
    """Example: Auto-fill chatbot forms with scraped data"""
    print("\n=== Auto-fill Chatbot Example ===")
    
    # Sample scraped data
    scraped_data = [
        {
            'company_name': 'TechCorp Dubai',
            'phone': '+971 4 123 4567',
            'address': 'Dubai Marina, UAE',
            'website': 'https://techcorp.ae'
        },
        {
            'company_name': 'Innovation Hub',
            'phone': '+971 4 987 6543',
            'address': 'Business Bay, Dubai',
            'website': 'https://innovationhub.ae'
        }
    ]
    
    # Map scraped data to chatbot fields
    field_mapping = {
        'organization_name': 'company_name',
        'contact_phone': 'phone',
        'location': 'address',
        'website_url': 'website'
    }
    
    mapped_data = advanced_collector.map_data_to_chatbot_fields(scraped_data, field_mapping)
    
    print("Mapped data for chatbot:")
    for i, item in enumerate(mapped_data):
        print(f"{i+1}. {item}")
    
    # Note: In real usage, you would call:
    # advanced_collector.auto_fill_chatbot_form(chatbot_id=1, form_data=mapped_data)
    
    return mapped_data

def main():
    """Run all examples"""
    print("Advanced Data Collector Examples")
    print("=" * 50)
    
    try:
        # Example 1: Google Maps scraping
        google_results = example_google_maps_scraper()
        
        # Example 2: Wikipedia scraping
        wiki_results = example_wikipedia_scraper()
        
        # Example 3: Custom website scraping
        custom_results = example_custom_website_scraper()
        
        # Example 4: Auto-fill chatbot
        chatbot_data = example_auto_fill_chatbot()
        
        print("\n" + "=" * 50)
        print("All examples completed successfully!")
        print(f"Google Maps: {len(google_results)} items")
        print(f"Wikipedia: {len(wiki_results)} items")
        print(f"Custom Website: {len(custom_results)} items")
        print(f"Chatbot Data: {len(chatbot_data)} items")
        
    except Exception as e:
        print(f"Error running examples: {e}")

if __name__ == "__main__":
    main()














