#!/usr/bin/env python3
"""
Parameter Pollution Discovery Tool
Tests for HTTP Parameter Pollution (HPP) vulnerabilities
"""

import requests
import sys
from urllib.parse import urlparse, parse_qs

class ParameterPollutionDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
    
    def test_pollution(self):
        print(f"[*] Testing Parameter Pollution on: {self.target_url}\n")
        
        # Extract existing parameters or use common ones
        parsed = urlparse(self.target_url)
        existing_params = list(parse_qs(parsed.query).keys())
        
        test_params = existing_params if existing_params else [
            'id', 'user', 'email', 'action', 'redirect', 'filter',
            'sort', 'order', 'page', 'limit', 'category', 'search'
        ]
        
        for param in test_params:
            self._test_duplicate_params(param)
            self._test_array_syntax(param)
            self._test_delimiter_confusion(param)
    
    def _test_duplicate_params(self, param):
        """Test duplicate parameter handling"""
        sep = '&' if '?' in self.target_url else '?'
        
        try:
            # Test with duplicate parameters
            url1 = f"{self.target_url}{sep}{param}=value1&{param}=value2"
            url2 = f"{self.target_url}{sep}{param}=value2&{param}=value1"
            url3 = f"{self.target_url}{sep}{param}=value1"
            
            r1 = requests.get(url1, timeout=5)
            r2 = requests.get(url2, timeout=5)
            r3 = requests.get(url3, timeout=5)
            
            # Check if order matters
            if r1.text != r2.text:
                self.vulnerabilities.append({
                    'type': 'Parameter Order Pollution',
                    'severity': 'MEDIUM',
                    'parameter': param,
                    'description': 'Server processes duplicate parameters differently based on order',
                    'test_url': url1
                })
            
            # Check if last value is used
            if r1.text == r3.text and 'value2' in r1.text:
                self.vulnerabilities.append({
                    'type': 'Last Parameter Wins',
                    'severity': 'LOW',
                    'parameter': param,
                    'description': 'Server uses last parameter value'
                })
            
            # Check if first value is used
            if r1.text == r3.text and 'value1' in r1.text:
                self.vulnerabilities.append({
                    'type': 'First Parameter Wins',
                    'severity': 'LOW',
                    'parameter': param,
                    'description': 'Server uses first parameter value'
                })
            
            # Check if values are concatenated
            if 'value1' in r1.text and 'value2' in r1.text:
                self.vulnerabilities.append({
                    'type': 'Parameter Concatenation',
                    'severity': 'MEDIUM',
                    'parameter': param,
                    'description': 'Server concatenates duplicate parameter values'
                })
        except:
            pass
    
    def _test_array_syntax(self, param):
        """Test array parameter syntax"""
        sep = '&' if '?' in self.target_url else '?'
        
        array_syntaxes = [
            f"{param}[]=value1&{param}[]=value2",
            f"{param}[0]=value1&{param}[1]=value2",
            f"{param}.0=value1&{param}.1=value2"
        ]
        
        for syntax in array_syntaxes:
            try:
                test_url = f"{self.target_url}{sep}{syntax}"
                r = requests.get(test_url, timeout=5)
                
                if r.status_code == 200 and ('value1' in r.text or 'value2' in r.text):
                    self.vulnerabilities.append({
                        'type': 'Array Syntax Support',
                        'severity': 'INFO',
                        'parameter': param,
                        'syntax': syntax.split('&')[0],
                        'description': 'Server accepts array parameter syntax'
                    })
            except:
                pass
    
    def _test_delimiter_confusion(self, param):
        """Test delimiter confusion"""
        sep = '&' if '?' in self.target_url else '?'
        
        delimiter_tests = [
            f"{param}=value1;{param}=value2",  # Semicolon delimiter
            f"{param}=value1%26{param}=value2",  # Encoded ampersand
            f"{param}=value1%3B{param}=value2",  # Encoded semicolon
        ]
        
        for test in delimiter_tests:
            try:
                test_url = f"{self.target_url}{sep}{test}"
                r = requests.get(test_url, timeout=5)
                
                if 'value2' in r.text:
                    self.vulnerabilities.append({
                        'type': 'Delimiter Confusion',
                        'severity': 'MEDIUM',
                        'parameter': param,
                        'description': 'Server accepts alternative parameter delimiters',
                        'test_url': test_url
                    })
            except:
                pass
    
    def print_report(self):
        if not self.vulnerabilities:
            print("[+] No parameter pollution vulnerabilities found!")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} parameter pollution issues:\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{i}] {vuln['type']} [{vuln['severity']}]")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    print(f"    {key}: {value}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python param_pollution_detector.py <target_url>")
        print("Example: python param_pollution_detector.py https://example.com/search?q=test")
        sys.exit(1)
    
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    detector = ParameterPollutionDetector(target)
    detector.test_pollution()
    detector.print_report()

if __name__ == "__main__":
    main()