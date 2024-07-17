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

