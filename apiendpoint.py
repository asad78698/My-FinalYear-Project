import requests
from bs4 import BeautifulSoup
import re

def extract_endpoints(url, limit=4):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all URLs in the website's HTML
    urls = [a['href'] for a in soup.find_all('a', href=True)]

    # Extract API endpoints using a more comprehensive pattern
    pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    api_endpoints = [url for url in urls if re.match(pattern, url)]

    # Limit the number of URLs to show
    api_endpoints = api_endpoints[:limit]

    return api_endpoints

def is_secure(endpoint):
    # Check if the endpoint uses HTTPS
    return endpoint.startswith('https://')

def analyze_endpoints(website_url, limit=4):
    endpoints = extract_endpoints(website_url, limit=limit)

    if not endpoints:
        return f"No API endpoints found on the website {website_url}"

    all_secure = all(is_secure(endpoint) for endpoint in endpoints)

    if all_secure:
        return "All API endpoints on this website are secure."
    else:
        return "API endpoints are not secure on this website."
