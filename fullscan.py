import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
import re
import html
import ssl
import socket


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax;": "Possible MySQL SQL Injection",
        "warning: mysql": "Possible MySQL SQL Injection",
        "unclosed quotation mark after the character string": "Possible SQL Server SQL Injection",
        "quoted string not properly terminated": "Possible Oracle SQL Injection",
    }
    for error, solution in errors.items():
        if error in response.content.decode().lower():
            return True, solution
    return False, None

def scan_sql_injection(url):
    for c in "\"'":
        new_url = f"{url}{c}"
        res = s.get(new_url)
        is_vuln, solution = is_vulnerable(res)
        if is_vuln:
            return f"SQL injection found in the URL. Payload: {new_url}\nSolution: {solution}\nTo prevent SQL injection, use parameterized queries or prepared statements in your database queries. These methods ensure that user inputs are treated as data and not executable code."

    forms = get_all_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    data[input_tag["name"]] = input_tag["value"] + c
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            form_url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(form_url, data=data)
            elif form_details["method"] == "get":
                res = s.get(form_url, params=data)
            is_vuln, solution = is_vulnerable(res)
            if is_vuln:
                return f"SQL injection found in the HTML form(s). Form Action: {form_url}, Method: {form_details['method']}"
    return f"No SQL injection vulnerabilities found on {url}."

def check_security_misconfiguration(url):
    try:
        response = requests.get(url)
        vulnerabilities_detected = []

        if response.status_code == 200:
            sensitive_headers = ['server', 'x-powered-by']
            for header in sensitive_headers:
                if header in response.headers:
                    vulnerabilities_detected.append(f"Sensitive header '{header}' found.")
            if 'Index of /' in response.text:
                vulnerabilities_detected.append("Directory listing is enabled.")
        else:
            return f"Error: Failed to retrieve the URL '{url}'."

        if vulnerabilities_detected:
            details = "\n".join(vulnerabilities_detected)
            return f"Potential security misconfigurations detected on {url}:\n{details}"
        else:
            return f"No security misconfigurations detected on {url}."

    except requests.RequestException as e:
        return f"Error: Request failed for URL '{url}' due to an exception: {str(e)}."

def check_http_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        secure_headers = ["Strict-Transport-Security", "Content-Security-Policy"]
        result_headers = []

        for header in secure_headers:
            if headers.get(header):
                result_headers.append(f"The website has {header} header, indicating a secure configuration.")
            else:
                result_headers.append(f"The website does not have {header} header, which may indicate a less secure configuration.")

        if all(headers.get(header) for header in secure_headers):
            result_headers.append("The website is considered secure based on the required security headers.")
        else:
            result_headers.append("The website is considered not secure based on the absence of required security headers.")
        
        return "\n".join(result_headers)

    except requests.exceptions.RequestException as e:
        return f"An error occurred: {str(e)}."

def get_trusted_domains():
    api_key = '3d6a2ae51d943edd9e4e9668dd9fa689bc3fc3943bc1f9fe932413aac7c25648'
    url = 'https://www.virustotal.com/api/v3/domains?limit=100'
    headers = {
        'x-apikey': api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        domains = [item['id'] for item in data.get('data', [])]
        return domains
    else:
        return []

def is_open_redirect(url):
    trusted_domains = get_trusted_domains()
    parsed_url = urlparse(url)
    base_url = parsed_url.netloc

    if base_url not in trusted_domains:
        full_url = urljoin(url, '/')  
        response = requests.get(full_url, allow_redirects=False)

        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_url = response.headers.get('Location')
            if redirect_url:
                redirect_base_url = urlparse(redirect_url).netloc

                if redirect_base_url not in trusted_domains:
                    return f"The URL is vulnerable to open redirects. Original URL: {url}, Redirect URL: {redirect_url}"
    
    return f"The URL is not vulnerable to open redirects. Original URL: {url}"

import requests
import re
import html

def check_url_for_xss(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses

        # Check headers for potential XSS
        for header, value in response.headers.items():
            if re.search(r'<script.*?>', value, re.IGNORECASE):
                return f"Potential XSS in header '{header}': {url}"

        # Check URL parameters for potential XSS
        params = requests.utils.urlparse(url).query
        decoded_params = html.unescape(params)
        if re.search(r'<script.*?>', decoded_params, re.IGNORECASE):
            return f"Potential XSS in decoded URL parameters: {decoded_params} in {url}"

        # Check attribute values in the HTML content for potential XSS
        attribute_values = re.findall(r'\w+="(.*?)"', response.text)
        for value in attribute_values:
            decoded_value = html.unescape(value)
            if re.search(r'<script.*?>', decoded_value, re.IGNORECASE):
                return f"Potential XSS in decoded HTML attribute value: {decoded_value} in {url}"

        # Check inline script tags in the HTML content
        script_tags = re.findall(r'<script(.*?)>(.*?)</script>', response.text, re.IGNORECASE | re.DOTALL)
        for script_tag in script_tags:
            if re.search(r'<script.*?>', script_tag[1], re.IGNORECASE):
                return f"Potential XSS in inline script tag: {script_tag[1]} in {url}"

        # Check for potential XSS using additional XSS payloads
        additional_xss_payloads = [
            '<script>alert(1)</script>',
            '<IMG SRC="javascript:alert(\'XSS\');">',
            '<BODY ONLOAD=alert(\'XSS\')>',
            '"><script>alert(\'XSS\')</script>'
        ]
        for payload in additional_xss_payloads:
            if payload.lower() in response.text.lower():  # Case insensitive check
                return f"Potential XSS detected with common payload: {payload} in {url}"

        return f"The URL is not vulnerable to Cross-Site Scripting (XSS) attacks: {url}"

    except requests.exceptions.RequestException as e:
        return f"Error occurred: {e}"

def crosssitescripting_result(url):
    return check_url_for_xss(url)


def extract_endpoints(url, limit=4):
    response = requests.get(url)
    soup = bs(response.content, 'html.parser')

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

    


def check_tls_security(url):
    try:
        hostname = url.split('//')[-1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    protocol = ssock.version()
                    key_exchange = ssock.shared_ciphers()
                    return f"The {url} is using a secure connection. \t Protocol: {protocol}, \n \n  Cipher Name: {cipher[0]}, Cipher Version: {cipher[1]}, Cipher Bits: {cipher[2]}, Key Exchange: {key_exchange}"
                else:
                    return "The website is not using a secure cipher."

    except (ssl.SSLError, socket.error) as e:
        return f"An error occurred: {str(e)}"


def full_security_check(url):
    results = []
    results.append(scan_sql_injection(url))
    results.append(check_security_misconfiguration(url))
    results.append(check_http_security_headers(url))
    results.append(is_open_redirect(url))
    results.append(check_url_for_xss(url))
    results.append(analyze_endpoints(url))
    results.append(check_tls_security(url))
    return results
