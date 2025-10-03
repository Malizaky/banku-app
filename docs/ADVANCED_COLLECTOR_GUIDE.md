# Advanced Data Collector System

## 🎯 Overview

The Advanced Data Collector is a powerful system that can:
- **Scrape any website** using CSS selectors or XPath
- **Auto-fill chatbot forms** with scraped data
- **Schedule collection** (manual, every X seconds/minutes/hours/days)
- **Map data fields** from scraped content to chatbot forms
- **Handle JavaScript-heavy sites** with Selenium

## 🚀 Features

### 1. **Open Website Scraping**
- Scrape **any website** by providing URL and selectors
- Support for **CSS selectors** and **XPath**
- **JavaScript support** with Selenium for dynamic content
- **Custom headers** and user agents

### 2. **Flexible Scheduling**
- **Manual**: Run only when you click "Run Now"
- **Every X Seconds**: Real-time data collection
- **Every X Minutes**: Regular updates
- **Every X Hours**: Daily collection
- **Every X Days**: Weekly/monthly collection
- **Custom Time**: Run at specific times (e.g., 09:00 daily)

### 3. **Chatbot Integration**
- **Choose any chatbot** to auto-fill
- **Field mapping** from scraped data to chatbot fields
- **Auto-submit** forms to create items
- **Data validation** before submission

### 4. **Data Sources**
- **Google Maps**: Business listings, phone numbers, addresses
- **Wikipedia**: Company information, descriptions
- **Company Websites**: Contact details, services
- **E-commerce Sites**: Product listings, prices
- **Social Media**: LinkedIn profiles, Twitter accounts
- **Any Website**: Custom scraping with selectors

## 📋 How to Use

### Step 1: Create a Collector

1. Go to **Admin → Data Collectors → Create New Collector**
2. Fill in basic information:
   - **Name**: "Dubai Companies Scraper"
   - **Description**: "Scrape company information from Google Maps"
   - **Data Type**: Organizations

### Step 2: Configure Website

1. **Website URL**: `https://www.google.com/maps/search/companies+in+dubai`
2. **Use Selenium**: Check if site needs JavaScript
3. **Add Selectors**:
   - Field: `company_name`, Selector: `.company-name`
   - Field: `phone`, Selector: `.phone-number`
   - Field: `address`, Selector: `.address`

### Step 3: Set Up Chatbot Integration

1. **Target Chatbot**: Select which chatbot to auto-fill
2. **Field Mapping**:
   ```json
   {
     "organization_name": "company_name",
     "contact_phone": "phone",
     "location": "address"
   }
   ```

### Step 4: Configure Scheduling

1. **Schedule Type**: Choose from manual, seconds, minutes, hours, days
2. **Schedule Value**: Enter number or time (e.g., 30, 09:00)
3. **Auto Approve**: Choose manual review or auto-approve

### Step 5: Test and Run

1. Click **"Test Collector"** to verify configuration
2. Click **"Run Now"** to execute immediately
3. Monitor results in the collector management page

## 🔧 Examples

### Example 1: Google Maps Business Scraper

```python
# Configuration
url = "https://www.google.com/maps/search/restaurants+in+dubai"
selectors = {
    'name': '[data-value="Directions"]',
    'phone': '[data-value="Phone"]',
    'address': '[data-value="Address"]',
    'rating': '[data-value="Rating"]'
}
use_selenium = True  # Google Maps needs JavaScript
```

### Example 2: Wikipedia Company Scraper

```python
# Configuration
url = "https://en.wikipedia.org/wiki/Apple_Inc."
selectors = {
    'title': 'h1.firstHeading',
    'description': '.mw-parser-output > p:first-of-type',
    'infobox': '.infobox tr'
}
use_selenium = False  # Wikipedia works with requests
```

### Example 3: E-commerce Product Scraper

```python
# Configuration
url = "https://example-store.com/products"
selectors = {
    'product_name': '.product-title',
    'price': '.price',
    'description': '.product-description',
    'image': '.product-image img'
}
use_selenium = False
```

## 🎛️ Admin Interface

### Collector Management
- **View all collectors** with status and statistics
- **Test collectors** before running
- **Run collectors manually** with "Run Now"
- **Edit collector** configuration
- **Toggle active/inactive** status
- **Delete collectors** when no longer needed

### Monitoring
- **Success rate** tracking
- **Last run** timestamps
- **Error logging** and debugging
- **Data count** statistics

## 🔄 Workflow

1. **Admin creates collector** with website and selectors
2. **System scrapes website** using configured selectors
3. **Data is mapped** to chatbot fields
4. **Chatbot form is auto-filled** with scraped data
5. **Items are created** automatically in the system
6. **Items appear in banks** based on data type

## 🛠️ Technical Details

### Web Scraping Engine
- **BeautifulSoup**: For HTML parsing
- **Selenium**: For JavaScript-heavy sites
- **Requests**: For simple HTTP requests
- **Custom headers**: To avoid blocking

### Scheduling System
- **Schedule library**: For cron-like scheduling
- **Background threads**: Non-blocking execution
- **Error handling**: Graceful failure recovery

### Data Mapping
- **Flexible mapping**: Any field to any field
- **Data validation**: Ensure data quality
- **Type conversion**: Automatic data type handling

## 🚨 Best Practices

### 1. **Respectful Scraping**
- Use appropriate delays between requests
- Respect robots.txt files
- Don't overload target servers

### 2. **Error Handling**
- Test collectors before scheduling
- Monitor error rates
- Set up alerts for failures

### 3. **Data Quality**
- Validate scraped data
- Use manual review for important data
- Clean and normalize data

### 4. **Performance**
- Use Selenium only when necessary
- Cache results when possible
- Monitor resource usage

## 🔍 Troubleshooting

### Common Issues

1. **"No data scraped"**
   - Check if selectors are correct
   - Verify website structure hasn't changed
   - Try using Selenium for JavaScript sites

2. **"Selenium errors"**
   - Ensure Chrome/ChromeDriver is installed
   - Check if website blocks automated access
   - Try different user agents

3. **"Chatbot integration fails"**
   - Verify chatbot ID exists
   - Check field mapping configuration
   - Ensure chatbot is active

### Debug Tips

1. **Use Test Collector** to verify configuration
2. **Check browser console** for JavaScript errors
3. **Monitor collector logs** for detailed error messages
4. **Test selectors** in browser developer tools

## 📈 Future Enhancements

- **Machine Learning**: Auto-detect selectors
- **Proxy support**: For large-scale scraping
- **Data validation**: AI-powered quality checks
- **Real-time monitoring**: Live dashboard
- **API integration**: Connect to external services

---

## 🎉 Conclusion

The Advanced Data Collector system provides a powerful, flexible way to automatically gather data from any website and integrate it seamlessly with your chatbot system. With proper configuration, it can significantly reduce manual work while ensuring data quality and consistency.

For more examples and advanced configurations, see the `examples/` directory.














