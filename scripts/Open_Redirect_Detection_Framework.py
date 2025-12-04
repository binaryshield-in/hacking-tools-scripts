#!/usr/bin/env python3
"""
Open Redirect Detection Framework
Tests for open redirect vulnerabilities
"""

import requests
import sys
from urllib.parse import quote

class OpenRedirectDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
    
    def test_redirects(self):
        print(f"[*] Testing Open Redirects on: {self.target_url}\n")
        
        redirect_params = [
            'redirect', 'url', 'next', 'return', 'redir', 'rurl', 
            'goto', 'destination', 'dest', 'target', 'link', 'view',
            'continue', 'out', 'to', 'callback', 'returnUrl', 'redirect_uri'
        ]
        
        payloads = [
            'https://evil.com',
            '//evil.com',
            '///evil.com',
            '////evil.com',
            'https:evil.com',
            'https:/evil.com',
            '\\\\evil.com',
            '/\\evil.com',
            'https://example.com@evil.com',
            'https://evil.com%23@example.com',
            'https://evil.com/',
            '//evil.com/%2f..',
            'https://evil.com%2f..',
            '/redirect?url=//evil.com',
            'javascript:alert(1)//',
            'data:text/html,<script>alert(1)</script>',
            'https://evil.com%00.example.com',
            'https://evil.com?.example.com',
            'https://evil.com#.example.com'
        ]
        
        for param in redirect_params:
            for payload in payloads:
                try:
                    sep = '&' if '?' in self.target_url else '?'
                    test_url = f"{self.target_url}{sep}{param}={quote(payload, safe='')}"
                    
                    r = requests.get(test_url, timeout=5, allow_redirects=False)
                    location = r.headers.get('Location', '')
                    
                    # Check if redirect to evil domain
                    if 'evil.com' in location.lower():
                        self.vulnerabilities.append({
                            'type': 'Open Redirect - Confirmed',
                            'severity': 'HIGH',
                            'parameter': param,
                            'payload': payload,
                            'redirect_to': location,
                            'status': r.status_code
                        })
                    elif r.status_code in [301, 302, 303, 307, 308]:
                        # Potential redirect
                        if location and not location.startswith(('http', '//')):
                            self.vulnerabilities.append({
                                'type': 'Potential Open Redirect',
                                'severity': 'MEDIUM',
                                'parameter': param,
                                'payload': payload,
                                'redirect_to': location,
                                'status': r.status_code
                            })
                except Exception as e:
                    pass
        
        return self.vulnerabilities
    
    def print_report(self):
        if not self.vulnerabilities:
            print("[+] No open redirect vulnerabilities found!")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} potential vulnerabilities:\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{i}] {vuln['type']} [{vuln['severity']}]")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    print(f"    {key}: {value}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python open_redirect_detector.py <target_url>")
        print("Example: python open_redirect_detector.py https://example.com/redirect")
        sys.exit(1)
    
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    detector = OpenRedirectDetector(target)
    detector.test_redirects()
    detector.print_report()

if __name__ == "__main__":
    main()