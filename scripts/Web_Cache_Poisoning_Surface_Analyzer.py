#!/usr/bin/env python3
"""
Web Cache Poisoning Surface Analyzer
Tests for web cache poisoning vulnerabilities

Installation:
    pip install requests

Usage:
    python cache_poisoning_analyzer.py <target_url>
    
Example:
    python cache_poisoning_analyzer.py https://example.com
    python cache_poisoning_analyzer.py https://example.com/api/data
    
Description:
    Tests for cache poisoning via:
    - Unkeyed headers (X-Forwarded-Host, X-Forwarded-Scheme, etc.)
    - HTTP header injection
    - Cache key manipulation
    - Response splitting
    - Cache deception
"""

import requests
import sys
import time
import hashlib
from urllib.parse import urlparse
from collections import defaultdict

class CachePoisoningAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.cache_headers = []
        self.parsed_url = urlparse(target_url)
        self.cache_buster = int(time.time())
        
    def analyze_all(self):
        print(f"[*] Analyzing Cache Poisoning Surface: {self.target_url}\n")
        
        self._detect_cache_system()
        self._test_unkeyed_headers()
        self._test_cache_key_normalization()
        self._test_host_header_poisoning()
        self._test_forwarded_headers()
        self._test_method_override()
        self._test_response_header_injection()
        self._test_cache_deception()
        self._test_fat_get_requests()
        
        return self.vulnerabilities
    
    def _make_request(self, url=None, headers=None, method='GET'):
        """Make HTTP request and return response"""
        url = url or self.target_url
        headers = headers or {}
        
        try:
            if method == 'GET':
                r = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
            elif method == 'POST':
                r = requests.post(url, headers=headers, timeout=10, allow_redirects=False)
            else:
                r = requests.request(method, url, headers=headers, timeout=10, allow_redirects=False)
            
            return r
        except Exception as e:
            return None
    
    def _detect_cache_system(self):
        """Detect caching system and behavior"""
        print("[*] Detecting cache system...")
        
        r = self._make_request()
        if not r:
            print("    [!] Failed to connect")
            return
        
        # Check for cache headers
        cache_indicators = [
            'X-Cache', 'X-Cache-Status', 'CF-Cache-Status', 
            'X-Varnish', 'X-Served-By', 'X-Cache-Hits',
            'Age', 'Cache-Control', 'X-Proxy-Cache',
            'X-CDN', 'X-Edge-Location', 'Server-Timing'
        ]
        
        found_headers = {}
        for header in cache_indicators:
            if header in r.headers:
                found_headers[header] = r.headers[header]
                self.cache_headers.append(header)
        
        if found_headers:
            print(f"    [+] Cache system detected:")
            for header, value in found_headers.items():
                print(f"        {header}: {value}")
            
            # Identify cache system
            if 'CF-Cache-Status' in found_headers:
                print(f"    [*] Cloudflare detected")
            elif 'X-Varnish' in found_headers:
                print(f"    [*] Varnish detected")
            elif 'X-Cache' in found_headers and 'HIT' in found_headers['X-Cache']:
                print(f"    [*] Generic cache (likely CDN)")
        else:
            print(f"    [~] No obvious cache headers found")
            self.vulnerabilities.append({
                'type': 'Unknown Cache Behavior',
                'severity': 'INFO',
                'description': 'No cache headers found - behavior unclear',
                'recommendation': 'Manual verification of caching behavior needed'
            })
        print()
    
    def _test_unkeyed_headers(self):
        """Test for unkeyed headers that affect response"""
        print("[*] Testing unkeyed headers...")
        
        test_headers = {
            'X-Forwarded-Host': 'evil.com',
            'X-Forwarded-Scheme': 'http',
            'X-Forwarded-Proto': 'http',
            'X-Host': 'evil.com',
            'X-Original-URL': '/admin',
            'X-Rewrite-URL': '/admin',
            'Forwarded': 'host=evil.com',
            'X-Forwarded-Server': 'evil.com',
            'X-HTTP-Host-Override': 'evil.com',
            'X-Original-Host': 'evil.com',
            'True-Client-IP': '127.0.0.1',
            'X-Custom-IP-Authorization': '127.0.0.1'
        }
        
        # Get baseline response
        cache_buster = f"?cb={self.cache_buster}"
        baseline_url = f"{self.target_url}{cache_buster}"
        baseline = self._make_request(baseline_url)
        
        if not baseline:
            print("    [!] Failed to get baseline")
            return
        
        poisoned_headers = []
        
        for header_name, header_value in test_headers.items():
            # Test with header
            self.cache_buster += 1
            test_url = f"{self.target_url}?cb={self.cache_buster}"
            test_headers_dict = {header_name: header_value}
            
            r1 = self._make_request(test_url, test_headers_dict)
            
            if not r1:
                continue
            
            # Check if header affected response
            if self._response_differs(baseline, r1):
                # Verify it's cacheable
                time.sleep(1)
                r2 = self._make_request(test_url)
                
                if r2 and self._response_differs(baseline, r2):
                    poisoned_headers.append({
                        'header': header_name,
                        'test_value': header_value,
                        'evidence': self._get_evidence(baseline, r1, header_value)
                    })
                    print(f"    [!] HIGH: {header_name} is unkeyed and affects response")
        
        if poisoned_headers:
            self.vulnerabilities.append({
                'type': 'Unkeyed Header Cache Poisoning',
                'severity': 'HIGH',
                'description': 'Headers affect response but are not part of cache key',
                'poisoned_headers': poisoned_headers,
                'impact': 'Attacker can poison cache with malicious values',
                'recommendation': 'Include headers in cache key or validate/sanitize them'
            })
        else:
            print(f"    [+] No unkeyed headers found")
        print()
    
    def _response_differs(self, r1, r2):
        """Check if two responses differ significantly"""
        if r1.status_code != r2.status_code:
            return True
        
        # Check content length difference
        if abs(len(r1.content) - len(r2.content)) > 10:
            return True
        
        # Check for different redirects
        if r1.headers.get('Location') != r2.headers.get('Location'):
            return True
        
        return False
    
    def _get_evidence(self, baseline, poisoned, test_value):
        """Extract evidence of poisoning"""
        evidence = []
        
        # Check if test value appears in response
        if test_value.encode() in poisoned.content:
            evidence.append(f"Test value '{test_value}' appears in response")
        
        # Check status code change
        if baseline.status_code != poisoned.status_code:
            evidence.append(f"Status changed: {baseline.status_code} -> {poisoned.status_code}")
        
        # Check redirect change
        if baseline.headers.get('Location') != poisoned.headers.get('Location'):
            evidence.append(f"Redirect changed to: {poisoned.headers.get('Location')}")
        
        return evidence[:3]
    
    def _test_cache_key_normalization(self):
        """Test cache key normalization issues"""
        print("[*] Testing cache key normalization...")
        
        variations = [
            (f"{self.target_url}", "baseline"),
            (f"{self.target_url}/", "trailing slash"),
            (f"{self.target_url}?", "empty query"),
            (f"{self.target_url}?a=1&b=2", "params order 1"),
            (f"{self.target_url}?b=2&a=1", "params order 2"),
            (f"{self.target_url}#fragment", "fragment"),
        ]
        
        cache_values = {}
        
        for url, description in variations:
            r = self._make_request(url)
            if r:
                cache_status = r.headers.get('X-Cache') or r.headers.get('CF-Cache-Status') or 'UNKNOWN'
                cache_values[description] = cache_status
        
        # Check for normalization issues
        if len(set(cache_values.values())) > 1:
            print(f"    [!] MEDIUM: Inconsistent caching across URL variations")
            for desc, status in cache_values.items():
                print(f"        {desc}: {status}")
            
            self.vulnerabilities.append({
                'type': 'Cache Key Normalization Issues',
                'severity': 'MEDIUM',
                'description': 'URL variations cached differently',
                'variations': cache_values,
                'impact': 'May enable cache deception attacks',
                'recommendation': 'Normalize URLs before caching'
            })
        else:
            print(f"    [+] Consistent cache behavior across variations")
        print()
    
    def _test_host_header_poisoning(self):
        """Test Host header cache poisoning"""
        print("[*] Testing Host header poisoning...")
        
        # Test with malicious host
        test_url = f"{self.target_url}?cb={self.cache_buster}"
        self.cache_buster += 1
        
        malicious_headers = {
            'Host': 'evil.com'
        }
        
        r1 = self._make_request(test_url, malicious_headers)
        
        if not r1:
            print("    [!] Request failed")
            return
        
        # Check if evil.com appears in response
        if b'evil.com' in r1.content:
            # Try to retrieve cached version
            time.sleep(1)
            r2 = self._make_request(test_url)
            
            if r2 and b'evil.com' in r2.content:
                self.vulnerabilities.append({
                    'type': 'Host Header Cache Poisoning',
                    'severity': 'CRITICAL',
                    'description': 'Host header reflected and cached',
                    'test_host': 'evil.com',
                    'impact': 'Attacker can poison cache with malicious host',
                    'recommendation': 'Do not reflect Host header in response'
                })
                print(f"    [!] CRITICAL: Host header poisoning successful")
            else:
                print(f"    [~] Host reflected but not cached")
        else:
            print(f"    [+] Host header not reflected")
        print()
    
    def _test_forwarded_headers(self):
        """Test X-Forwarded-* header poisoning"""
        print("[*] Testing X-Forwarded-* headers...")
        
        forwarded_tests = [
            ('X-Forwarded-Host', 'evil.com'),
            ('X-Forwarded-Scheme', 'http'),
            ('X-Forwarded-Proto', 'http'),
            ('Forwarded', 'host=evil.com;proto=http')
        ]
        
        vulnerable_headers = []
        
        for header_name, header_value in forwarded_tests:
            test_url = f"{self.target_url}?cb={self.cache_buster}"
            self.cache_buster += 1
            
            test_headers = {header_name: header_value}
            r1 = self._make_request(test_url, test_headers)
            
            if not r1:
                continue
            
            # Check for reflection
            if header_value.encode() in r1.content or 'evil.com' in r1.text:
                # Check if cached
                time.sleep(1)
                r2 = self._make_request(test_url)
                
                if r2 and (header_value.encode() in r2.content or 'evil.com' in r2.text):
                    vulnerable_headers.append({
                        'header': header_name,
                        'value': header_value
                    })
                    print(f"    [!] HIGH: {header_name} poisoning successful")
        
        if vulnerable_headers:
            self.vulnerabilities.append({
                'type': 'Forwarded Header Cache Poisoning',
                'severity': 'HIGH',
                'description': 'X-Forwarded-* headers reflected and cached',
                'vulnerable_headers': vulnerable_headers,
                'impact': 'Attacker can inject malicious values via proxy headers',
                'recommendation': 'Validate and sanitize proxy headers'
            })
        else:
            print(f"    [+] No X-Forwarded-* poisoning found")
        print()
    
    def _test_method_override(self):
        """Test HTTP method override poisoning"""
        print("[*] Testing HTTP method override...")
        
        override_headers = [
            'X-HTTP-Method-Override',
            'X-HTTP-Method',
            'X-Method-Override'
        ]
        
        test_url = f"{self.target_url}?cb={self.cache_buster}"
        self.cache_buster += 1
        
        for header in override_headers:
            test_headers = {header: 'POST'}
            
            r1 = self._make_request(test_url, test_headers, method='GET')
            
            if not r1:
                continue
            
            # Check if method was overridden (different response than normal GET)
            r_normal = self._make_request(f"{self.target_url}?cb={self.cache_buster + 1}")
            
            if r_normal and self._response_differs(r_normal, r1):
                self.vulnerabilities.append({
                    'type': 'Method Override Cache Poisoning',
                    'severity': 'MEDIUM',
                    'description': f'{header} affects response',
                    'header': header,
                    'impact': 'GET request behavior can be altered',
                    'recommendation': 'Disable method override or include in cache key'
                })
                print(f"    [!] MEDIUM: {header} affects response")
                break
        else:
            print(f"    [+] No method override issues")
        print()
    
    def _test_response_header_injection(self):
        """Test for response header injection via cache"""
        print("[*] Testing response header injection...")
        
        # Try to inject headers via various vectors
        injection_tests = [
            ('X-Custom-Header', 'test\r\nX-Injected: true'),
            ('X-Forwarded-Host', 'example.com\r\nX-Injected: true'),
            ('Referer', 'http://example.com\r\nX-Injected: true')
        ]
        
        for header_name, header_value in injection_tests:
            test_url = f"{self.target_url}?cb={self.cache_buster}"
            self.cache_buster += 1
            
            test_headers = {header_name: header_value}
            r1 = self._make_request(test_url, test_headers)
            
            if not r1:
                continue
            
            # Check if injection worked
            if 'X-Injected' in r1.headers:
                self.vulnerabilities.append({
                    'type': 'Response Header Injection via Cache',
                    'severity': 'HIGH',
                    'description': 'Can inject response headers via cached content',
                    'injection_header': header_name,
                    'injected_header': 'X-Injected',
                    'impact': 'Can manipulate response headers for other users',
                    'recommendation': 'Sanitize all headers before caching'
                })
                print(f"    [!] HIGH: Header injection via {header_name}")
                return
        
        print(f"    [+] No header injection detected")
        print()
    
    def _test_cache_deception(self):
        """Test for cache deception vulnerabilities"""
        print("[*] Testing cache deception...")
        
        # Test path confusion
        deception_paths = [
            f"{self.parsed_url.path}/test.css",
            f"{self.parsed_url.path}/test.js",
            f"{self.parsed_url.path}/test.jpg",
            f"{self.parsed_url.path}/..%2ftest.css",
            f"{self.parsed_url.path}%2ftest.css",
        ]
        
        base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        vulnerable_paths = []
        
        for path in deception_paths:
            test_url = f"{base_url}{path}?cb={self.cache_buster}"
            self.cache_buster += 1
            
            r = self._make_request(test_url)
            
            if not r:
                continue
            
            # Check if static extension is cached
            cache_header = r.headers.get('X-Cache') or r.headers.get('CF-Cache-Status')
            
            if cache_header and ('HIT' in cache_header.upper() or 'MISS' in cache_header.upper()):
                if r.status_code == 200 and len(r.content) > 100:
                    vulnerable_paths.append({
                        'path': path,
                        'cache_status': cache_header,
                        'content_length': len(r.content)
                    })
                    print(f"    [!] MEDIUM: Static extension cached: {path}")
        
        if vulnerable_paths:
            self.vulnerabilities.append({
                'type': 'Cache Deception',
                'severity': 'MEDIUM',
                'description': 'Static file extensions cached with dynamic content',
                'vulnerable_paths': vulnerable_paths,
                'impact': 'Attacker can trick users into caching sensitive data',
                'recommendation': 'Only cache actual static files, verify content type'
            })
        else:
            print(f"    [+] No cache deception vectors found")
        print()
    
    def _test_fat_get_requests(self):
        """Test if GET requests with body are cached"""
        print("[*] Testing fat GET requests...")
        
        test_url = f"{self.target_url}?cb={self.cache_buster}"
        self.cache_buster += 1
        
        # Try GET with body
        headers = {'Content-Type': 'application/json'}
        body = '{"poisoned": "true"}'
        
        try:
            r1 = requests.request('GET', test_url, data=body, headers=headers, timeout=10)
            
            if r1.status_code == 200:
                # Check if cached
                time.sleep(1)
                r2 = self._make_request(test_url)
                
                if r2 and b'poisoned' in r2.content:
                    self.vulnerabilities.append({
                        'type': 'Fat GET Cache Poisoning',
                        'severity': 'HIGH',
                        'description': 'GET requests with body are cached',
                        'impact': 'Attacker can poison cache via GET body',
                        'recommendation': 'Reject GET requests with body or include body in cache key'
                    })
                    print(f"    [!] HIGH: Fat GET requests are cached")
                else:
                    print(f"    [+] Fat GET requests not cached")
            else:
                print(f"    [+] Fat GET requests rejected")
        except:
            print(f"    [+] Fat GET requests not supported")
        print()
    
    def print_report(self):
        print("\n" + "="*70)
        print("WEB CACHE POISONING SURFACE ANALYSIS REPORT")
        print("="*70 + "\n")
        
        if not self.vulnerabilities:
            print("[+] No cache poisoning vulnerabilities detected!")
            print("[+] Cache configuration appears secure.")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} cache poisoning issues:\n")
        
        # Group by severity
        critical = [v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v.get('severity') == 'HIGH']
        medium = [v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v.get('severity') == 'LOW']
        info = [v for v in self.vulnerabilities if v.get('severity') == 'INFO']
        
        for severity, vulns in [('CRITICAL', critical), ('HIGH', high), ('MEDIUM', medium), ('LOW', low), ('INFO', info)]:
            if vulns:
                print(f"\n{severity} Severity ({len(vulns)}):")
                print("-" * 50)
                for i, vuln in enumerate(vulns, 1):
                    print(f"\n  [{i}] {vuln['type']}")
                    for key, value in vuln.items():
                        if key not in ['type', 'severity']:
                            if isinstance(value, list):
                                if len(value) <= 5:
                                    print(f"      {key}:")
                                    for item in value:
                                        if isinstance(item, dict):
                                            for k, v in item.items():
                                                print(f"        {k}: {v}")
                                        else:
                                            print(f"        - {item}")
                                else:
                                    print(f"      {key}: {len(value)} items")
                            else:
                                print(f"      {key}: {value}")
        
        print("\n" + "="*70)
        print("CACHE POISONING PREVENTION BEST PRACTICES")
        print("="*70)
        print("""
1. Cache Key Design:
   - Include all headers that affect response in cache key
   - Normalize URLs (trailing slashes, parameter order)
   - Don't trust client-supplied headers (X-Forwarded-*)

2. Header Validation:
   - Validate and sanitize all headers before use
   - Don't reflect untrusted headers in responses
   - Use allowlists for acceptable header values

3. Static Resource Handling:
   - Only cache based on file content, not extension
   - Verify Content-Type matches file extension
   - Set explicit cache headers for static resources

4. Method Restrictions:
   - Only cache GET and HEAD requests
   - Reject GET requests with bodies
   - Disable HTTP method override headers

5. Cache Control Headers:
   - Use Cache-Control: private for user-specific content
   - Use Cache-Control: no-cache for dynamic content
   - Set appropriate max-age values
   - Use Vary header for content negotiation

6. Origin Server Configuration:
   - Don't trust proxy headers (X-Forwarded-Host, etc.)
   - Validate Host header against allowed domains
   - Use HTTPS to prevent MITM cache poisoning

7. CDN/Cache Configuration:
   - Configure cache key properly
   - Disable caching of sensitive endpoints
   - Use cache purging after updates
   - Monitor cache hit/miss ratios

8. Testing:
   - Regularly audit cache behavior
   - Test with various header combinations
   - Monitor for anomalous cache keys
   - Use cache-busting for testing

9. Monitoring:
   - Log cache poisoning attempts
   - Alert on unusual header patterns
   - Track cache performance metrics

10. Response Headers:
    - Use X-Frame-Options or frame-ancestors
    - Set X-Content-Type-Options: nosniff
    - Implement Content-Security-Policy
        """)

def main():
    if len(sys.argv) < 2:
        print("Web Cache Poisoning Surface Analyzer")
        print("=" * 50)
        print("\nUsage: python cache_poisoning_analyzer.py <target_url>")
        print("\nExamples:")
        print("  python cache_poisoning_analyzer.py https://example.com")
        print("  python cache_poisoning_analyzer.py https://example.com/api/data")
        print("\nDescription:")
        print("  Tests for web cache poisoning vulnerabilities:")
        print("  - Unkeyed headers (X-Forwarded-Host, etc.)")
        print("  - Host header poisoning")
        print("  - Cache key normalization issues")
        print("  - Response header injection")
        print("  - Cache deception")
        print("\nWARNING:")
        print("  This tool may poison shared caches")
        print("  Only use on systems you have permission to test!")
        sys.exit(1)
    
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print("\n" + "="*70)
    print("WEB CACHE POISONING SURFACE ANALYZER")
    print("="*70 + "\n")
    
    print("[!] WARNING: This tool may poison shared caches")
    print("[!] Only use on systems you have permission to test!\n")
    
    analyzer = CachePoisoningAnalyzer(target)
    analyzer.analyze_all()
    analyzer.print_report()
    
    print("\n" + "="*70)
    print("Analysis Complete")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()





    