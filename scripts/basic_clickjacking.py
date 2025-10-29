#!/usr/bin/env python3
import requests
def test_clickjacking_protection(url):
    """Test for clickjacking protection headers"""
    try:
        response = requests.head(url, timeout=10)
        headers = response.headers
        
        print(f"Testing: {url}")
        print("-" * 40)
        
        # Check X-Frame-Options
        x_frame = headers.get('X-Frame-Options', 'NOT SET')
        print(f"X-Frame-Options: {x_frame}")
        
        # Check Content-Security-Policy
        csp = headers.get('Content-Security-Policy', 'NOT SET')
        print(f"Content-Security-Policy: {csp}")
        
        # Vulnerability assessment
        if x_frame.upper() in ['DENY', 'SAMEORIGIN']:
            print("✅ Protected by X-Frame-Options")
        elif 'frame-ancestors' in csp.lower():
            print("✅ Protected by CSP")
        else:
            print("❌ Potentially vulnerable to clickjacking")
            
    except Exception as e:
        print(f"Error testing {url}: {e}")
# Usage (only on authorized targets)
if __name__ == "__main__":
    test_clickjacking_protection("https://example.com")