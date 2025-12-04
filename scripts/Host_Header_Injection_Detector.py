#!/usr/bin/env python3
"""
Host Header Injection Detector
Tests for Host Header injection vulnerabilities
"""

import requests
import sys
from urllib.parse import urlparse
import re

class HostHeaderInjectionDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.original_host = self.parsed_url.netloc
        self.vulnerabilities = []
        
    def test_basic_injection(self):
        """Test basic host header replacement"""
        test_hosts = [
            'evil.com',
            'attacker.com',
            '127.0.0.1',
            'localhost'
        ]
        
        for evil_host in test_hosts:
            try:
                headers = {'Host': evil_host}
                r = requests.get(self.target_url, headers=headers, timeout=5, allow_redirects=False)
                
                # Check if evil host appears in response
                if evil_host in r.text or evil_host in str(r.headers):
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'type': 'Basic Host Header Injection',
                        'payload': evil_host,
                        'description': f'Injected host "{evil_host}" reflected in response',
                        'status_code': r.status_code,
                        'found_in': 'body' if evil_host in r.text else 'headers'
                    })
                
                # Check for redirects to injected host
                location = r.headers.get('Location', '')
                if evil_host in location:
                    self.vulnerabilities.append({
                        'severity': 'CRITICAL',
                        'type': 'Host Header Redirect',
                        'payload': evil_host,
                        'description': f'Server redirects to injected host',
                        'redirect_location': location,
                        'status_code': r.status_code
                    })
            except Exception as e:
                pass
    
    def test_absolute_url_injection(self):
        """Test injection via absolute URL in GET request"""
        evil_url = f"http://evil.com{self.parsed_url.path}"
        try:
            r = requests.get(evil_url, headers={'Host': self.original_host}, timeout=5)
            if 'evil.com' in r.text or 'evil.com' in str(r.headers):
                self.vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'type': 'Absolute URL Injection',
                    'payload': evil_url,
                    'description': 'Injected URL reflected in response'
                })
        except Exception as e:
            pass
    
    def test_duplicate_host_headers(self):
        """Test duplicate Host headers"""
        try:
            # Craft raw request with duplicate headers
            import socket
            
            request = f"GET {self.parsed_url.path or '/'} HTTP/1.1\r\n"
            request += f"Host: {self.original_host}\r\n"
            request += f"Host: evil.com\r\n"
            request += "Connection: close\r\n\r\n"
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.original_host, 443 if self.parsed_url.scheme == 'https' else 80))
            
            if self.parsed_url.scheme == 'https':
                import ssl
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.original_host)
            
            sock.sendall(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            if 'evil.com' in response:
                self.vulnerabilities.append({
                    'severity': 'HIGH',
                    'type': 'Duplicate Host Header',
                    'payload': 'Host: evil.com (duplicate)',
                    'description': 'Server accepts duplicate Host headers'
                })
        except Exception as e:
            pass
    
    def test_host_override_headers(self):
        """Test X-Forwarded-Host and similar headers"""
        override_headers = [
            'X-Forwarded-Host',
            'X-Host',
            'X-Forwarded-Server',
            'X-HTTP-Host-Override',
            'Forwarded'
        ]
        
        for header_name in override_headers:
            try:
                headers = {header_name: 'evil.com'}
                r = requests.get(self.target_url, headers=headers, timeout=5, allow_redirects=False)
                
                if 'evil.com' in r.text or 'evil.com' in str(r.headers):
                    self.vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'type': 'Host Override Header',
                        'header': header_name,
                        'payload': 'evil.com',
                        'description': f'{header_name} header reflected in response',
                        'status_code': r.status_code
                    })
                
                location = r.headers.get('Location', '')
                if 'evil.com' in location:
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'type': 'Host Override Redirect',
                        'header': header_name,
                        'payload': 'evil.com',
                        'description': f'{header_name} causes redirect to injected host',
                        'redirect_location': location
                    })
            except Exception as e:
                pass
    
    def test_port_manipulation(self):
        """Test host header with port manipulation"""
        test_payloads = [
            f'{self.original_host}:1337',
            f'{self.original_host}:evil.com',
            f'{self.original_host}@evil.com',
            f'evil.com:{self.original_host}'
        ]
        
        for payload in test_payloads:
            try:
                headers = {'Host': payload}
                r = requests.get(self.target_url, headers=headers, timeout=5, allow_redirects=False)
                
                if 'evil.com' in r.text or 'evil.com' in str(r.headers):
                    self.vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'type': 'Port Manipulation Injection',
                        'payload': payload,
                        'description': 'Host header with port manipulation reflected'
                    })
            except Exception as e:
                pass
    
    def test_password_reset_poisoning(self):
        """Test for password reset poisoning potential"""
        try:
            headers = {'Host': 'evil.com'}
            r = requests.get(self.target_url, headers=headers, timeout=5)
            
            # Look for password reset indicators
            reset_indicators = [
                'password', 'reset', 'forgot', 'recovery',
                'email', 'link', 'token', 'verify'
            ]
            
            content_lower = r.text.lower()
            if any(indicator in content_lower for indicator in reset_indicators):
                if 'evil.com' in r.text:
                    self.vulnerabilities.append({
                        'severity': 'CRITICAL',
                        'type': 'Password Reset Poisoning',
                        'payload': 'evil.com',
                        'description': 'Potential password reset poisoning vulnerability',
                        'note': 'Injected host appears in password reset functionality'
                    })
        except Exception as e:
            pass
    
    def test_cache_poisoning(self):
        """Test for cache poisoning via Host header"""
        try:
            # First request with evil host
            headers = {'Host': 'evil.com'}
            r1 = requests.get(self.target_url, headers=headers, timeout=5)
            
            # Check cache headers
            cache_headers = ['X-Cache', 'CF-Cache-Status', 'Age', 'Cache-Control']
            cached = any(h in r1.headers for h in cache_headers)
            
            if cached and 'evil.com' in r1.text:
                self.vulnerabilities.append({
                    'severity': 'HIGH',
                    'type': 'Web Cache Poisoning',
                    'payload': 'evil.com',
                    'description': 'Host header injection with caching detected',
                    'cache_headers': {h: r1.headers.get(h) for h in cache_headers if h in r1.headers}
                })
        except Exception as e:
            pass
    
    def test_internal_network_access(self):
        """Test access to internal network resources"""
        internal_hosts = [
            '127.0.0.1',
            'localhost',
            '10.0.0.1',
            '192.168.1.1',
            '172.16.0.1'
        ]
        
        for host in internal_hosts:
            try:
                headers = {'Host': host}
                r = requests.get(self.target_url, headers=headers, timeout=5)
                
                # Look for internal network indicators
                if any(x in r.text.lower() for x in ['internal', 'private', 'admin', 'intranet']):
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'type': 'Internal Network Access',
                        'payload': host,
                        'description': f'Possible access to internal resources via {host}'
                    })
            except Exception as e:
                pass
    
    def validate_all(self):
        """Run all Host Header injection tests"""
        print(f"\n[*] Testing Host Header Injection for: {self.target_url}\n")
        
        self.test_basic_injection()
        self.test_host_override_headers()
        self.test_port_manipulation()
        self.test_duplicate_host_headers()
        self.test_password_reset_poisoning()
        self.test_cache_poisoning()
        self.test_internal_network_access()
        
        return self.vulnerabilities
    
    def print_report(self):
        """Print formatted vulnerability report"""
        if not self.vulnerabilities:
            print("[+] No Host Header injection vulnerabilities detected!")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} Host Header vulnerability(ies):\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{i}] {vuln['type']} [{vuln['severity']}]")
            print(f"    Description: {vuln['description']}")
            for key, value in vuln.items():
                if key not in ['type', 'description', 'severity']:
                    print(f"    {key}: {value}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python host_header_detector.py <target_url>")
        print("Example: python host_header_detector.py https://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate URL format
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    detector = HostHeaderInjectionDetector(target)
    detector.validate_all()
    detector.print_report()

if __name__ == "__main__":
    main()