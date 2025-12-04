#!/usr/bin/env python3
"""
CORS Misconfiguration Validator
Tests for common CORS security misconfigurations
"""

import requests
import sys
from urllib.parse import urlparse

class CORSValidator:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        
    def test_null_origin(self):
        """Test if null origin is allowed"""
        headers = {'Origin': 'null'}
        try:
            r = requests.get(self.target_url, headers=headers, timeout=5)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == 'null':
                self.vulnerabilities.append({
                    'severity': 'HIGH',
                    'issue': 'Null Origin Allowed',
                    'description': 'Server reflects null origin',
                    'acao': acao,
                    'credentials': acac
                })
        except Exception as e:
            pass
    
    def test_arbitrary_origin(self):
        """Test if arbitrary origins are reflected"""
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'http://localhost'
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            try:
                r = requests.get(self.target_url, headers=headers, timeout=5)
                acao = r.headers.get('Access-Control-Allow-Origin', '')
                acac = r.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin and acac.lower() == 'true':
                    self.vulnerabilities.append({
                        'severity': 'CRITICAL',
                        'issue': 'Arbitrary Origin Reflection with Credentials',
                        'description': f'Server reflects {origin} with credentials enabled',
                        'origin': origin,
                        'acao': acao,
                        'credentials': acac
                    })
                elif acao == origin:
                    self.vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'issue': 'Arbitrary Origin Reflection',
                        'description': f'Server reflects {origin}',
                        'origin': origin,
                        'acao': acao
                    })
            except Exception as e:
                pass
    
    def test_wildcard_with_credentials(self):
        """Test for wildcard origin with credentials"""
        try:
            r = requests.get(self.target_url, timeout=5)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and acac.lower() == 'true':
                self.vulnerabilities.append({
                    'severity': 'HIGH',
                    'issue': 'Wildcard with Credentials',
                    'description': 'Wildcard origin (*) combined with credentials',
                    'acao': acao,
                    'credentials': acac
                })
            elif acao == '*':
                self.vulnerabilities.append({
                    'severity': 'LOW',
                    'issue': 'Wildcard Origin',
                    'description': 'Server uses wildcard origin (*)',
                    'acao': acao
                })
        except Exception as e:
            pass
    
    def test_subdomain_bypass(self):
        """Test if subdomain variations are accepted"""
        parsed = urlparse(self.target_url)
        domain = parsed.netloc
        
        test_subdomains = [
            f"https://evil.{domain}",
            f"https://{domain}.evil.com",
            f"https://evilprefix{domain}"
        ]
        
        for origin in test_subdomains:
            headers = {'Origin': origin}
            try:
                r = requests.get(self.target_url, headers=headers, timeout=5)
                acao = r.headers.get('Access-Control-Allow-Origin', '')
                
                if acao == origin:
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'issue': 'Subdomain Bypass',
                        'description': f'Malicious subdomain accepted: {origin}',
                        'origin': origin,
                        'acao': acao
                    })
            except Exception as e:
                pass
    
    def test_pre_domain_bypass(self):
        """Test pre-domain bypass techniques"""
        parsed = urlparse(self.target_url)
        domain = parsed.netloc
        
        test_origins = [
            f"https://{domain}.evil.com",
            f"https://evil{domain}",
            f"https://not{domain}"
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            try:
                r = requests.get(self.target_url, headers=headers, timeout=5)
                acao = r.headers.get('Access-Control-Allow-Origin', '')
                
                if acao == origin:
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'issue': 'Pre-domain Bypass',
                        'description': f'Pre-domain manipulation accepted: {origin}',
                        'origin': origin,
                        'acao': acao
                    })
            except Exception as e:
                pass
    
    def test_insecure_protocol(self):
        """Test if HTTP origin is accepted for HTTPS site"""
        parsed = urlparse(self.target_url)
        if parsed.scheme == 'https':
            http_origin = f"http://{parsed.netloc}"
            headers = {'Origin': http_origin}
            try:
                r = requests.get(self.target_url, headers=headers, timeout=5)
                acao = r.headers.get('Access-Control-Allow-Origin', '')
                
                if acao == http_origin:
                    self.vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'issue': 'Insecure Protocol Accepted',
                        'description': 'HTTP origin accepted for HTTPS endpoint',
                        'origin': http_origin,
                        'acao': acao
                    })
            except Exception as e:
                pass
    
    def validate_all(self):
        """Run all CORS validation tests"""
        print(f"\n[*] Testing CORS Configuration for: {self.target_url}\n")
        
        self.test_wildcard_with_credentials()
        self.test_null_origin()
        self.test_arbitrary_origin()
        self.test_subdomain_bypass()
        self.test_pre_domain_bypass()
        self.test_insecure_protocol()
        
        return self.vulnerabilities
    
    def print_report(self):
        """Print formatted vulnerability report"""
        if not self.vulnerabilities:
            print("[+] No CORS misconfigurations detected!")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} CORS misconfiguration(s):\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{i}] {vuln['issue']} [{vuln['severity']}]")
            print(f"    Description: {vuln['description']}")
            for key, value in vuln.items():
                if key not in ['issue', 'description', 'severity']:
                    print(f"    {key}: {value}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python cors_validator.py <target_url>")
        print("Example: python cors_validator.py https://example.com/api/data")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate URL format
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    validator = CORSValidator(target)
    validator.validate_all()
    validator.print_report()

if __name__ == "__main__":
    main()