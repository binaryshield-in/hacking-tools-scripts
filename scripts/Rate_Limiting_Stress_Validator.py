#!/usr/bin/env python3
"""
Rate Limiting Stress Validator
Tests API rate limiting implementation and bypass techniques

Installation:
    pip install requests

Usage:
    python rate_limiting_validator.py <target_url> [requests_count]
    
Example:
    python rate_limiting_validator.py https://api.example.com/endpoint
    python rate_limiting_validator.py https://api.example.com/login 100
    python rate_limiting_validator.py https://api.example.com/api --auth "Bearer token123"
    
Description:
    Tests rate limiting effectiveness by:
    - Sending multiple rapid requests
    - Testing IP-based rate limits
    - Testing user/session-based limits
    - Testing bypass techniques (headers, case changes)
"""

import requests
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime
import concurrent.futures

class RateLimitingValidator:
    def __init__(self, target_url, auth_header=None):
        self.target_url = target_url
        self.auth_header = auth_header
        self.results = []
        self.vulnerabilities = []
        self.lock = threading.Lock()
    
    def validate_all(self, request_count=100):
        print(f"[*] Rate Limiting Stress Test on: {self.target_url}\n")
        
        self._test_basic_rate_limit(request_count)
        self._test_distributed_requests()
        self._analyze_rate_limit_headers()
        self._test_bypass_techniques()
        self._test_429_handling()
        self._test_per_endpoint_limits()
        
        return self.vulnerabilities
    
    def _test_basic_rate_limit(self, request_count):
        """Test basic rate limiting with rapid requests"""
        print(f"[*] Testing basic rate limiting ({request_count} requests)...")
        
        status_codes = defaultdict(int)
        response_times = []
        start_time = time.time()
        
        headers = {}
        if self.auth_header:
            headers['Authorization'] = self.auth_header
        
        # Send rapid requests
        for i in range(request_count):
            try:
                req_start = time.time()
                r = requests.get(self.target_url, headers=headers, timeout=10)
                req_time = time.time() - req_start
                
                status_codes[r.status_code] += 1
                response_times.append(req_time)
                
                # Print progress
                if (i + 1) % 10 == 0:
                    print(f"    [{i+1}/{request_count}] Status codes so far: {dict(status_codes)}")
                
                # Check for rate limit response
                if r.status_code == 429:
                    print(f"    [+] Rate limit triggered at request {i+1}")
                    break
                
                # Small delay to prevent connection issues
                time.sleep(0.01)
            except Exception as e:
                status_codes['error'] += 1
        
        total_time = time.time() - start_time
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        print(f"\n[*] Test Results:")
        print(f"    Total requests: {sum(status_codes.values())}")
        print(f"    Total time: {total_time:.2f}s")
        print(f"    Avg response time: {avg_response_time:.3f}s")
        print(f"    Status codes: {dict(status_codes)}\n")
        
        # Analyze results
        if 429 not in status_codes and status_codes[200] >= request_count * 0.9:
            self.vulnerabilities.append({
                'type': 'No Rate Limiting',
                'severity': 'HIGH',
                'description': f'Server accepted {status_codes[200]} requests without rate limiting',
                'requests_sent': request_count,
                'rate_limit_triggered': False,
                'impact': 'API vulnerable to abuse and DoS attacks'
            })
            print(f"    [!] HIGH: No rate limiting detected\n")
        elif 429 in status_codes:
            trigger_point = sum(status_codes.values()) - status_codes[429]
            self.vulnerabilities.append({
                'type': 'Rate Limiting Present',
                'severity': 'INFO',
                'description': f'Rate limit triggered after ~{trigger_point} requests',
                'trigger_point': trigger_point,
                'total_429_responses': status_codes[429]
            })
            print(f"    [+] Rate limiting active (triggered after ~{trigger_point} requests)\n")
    
    def _test_distributed_requests(self):
        """Test if rate limit can be bypassed with distributed timing"""
        print("[*] Testing distributed request pattern...")
        
        intervals = [0.5, 1.0, 2.0]  # seconds between requests
        
        for interval in intervals:
            status_codes = []
            
            for i in range(20):
                try:
                    headers = {}
                    if self.auth_header:
                        headers['Authorization'] = self.auth_header
                    
                    r = requests.get(self.target_url, headers=headers, timeout=10)
                    status_codes.append(r.status_code)
                    time.sleep(interval)
                except:
                    pass
            
            if 429 not in status_codes and status_codes.count(200) == 20:
                self.vulnerabilities.append({
                    'type': 'Rate Limit Bypass - Timing',
                    'severity': 'MEDIUM',
                    'description': f'Rate limit bypassed with {interval}s interval',
                    'interval': f'{interval}s',
                    'requests_succeeded': 20,
                    'impact': 'Slow-rate attacks possible'
                })
                print(f"    [!] MEDIUM: Rate limit bypassed with {interval}s intervals\n")
                return
        
        print(f"    [+] Distributed requests still rate limited\n")
    
    def _analyze_rate_limit_headers(self):
        """Check for rate limit information in headers"""
        print("[*] Analyzing rate limit headers...")
        
        try:
            headers = {}
            if self.auth_header:
                headers['Authorization'] = self.auth_header
            
            r = requests.get(self.target_url, headers=headers, timeout=10)
            
            rate_limit_headers = {}
            header_patterns = [
                'X-RateLimit', 'RateLimit', 'X-Rate-Limit',
                'Retry-After', 'X-Retry-After'
            ]
            
            for header, value in r.headers.items():
                if any(pattern.lower() in header.lower() for pattern in header_patterns):
                    rate_limit_headers[header] = value
            
            if rate_limit_headers:
                print(f"    [+] Rate limit headers found:")
                for header, value in rate_limit_headers.items():
                    print(f"        {header}: {value}")
                print()
            else:
                self.vulnerabilities.append({
                    'type': 'Missing Rate Limit Headers',
                    'severity': 'LOW',
                    'description': 'No rate limit headers exposed',
                    'impact': 'Clients cannot programmatically detect limits'
                })
                print(f"    [!] LOW: No rate limit headers found\n")
        except Exception as e:
            print(f"    [!] Error: {e}\n")
    
    def _test_bypass_techniques(self):
        """Test various rate limit bypass techniques"""
        print("[*] Testing rate limit bypass techniques...")
        
        bypass_tests = [
            ('X-Forwarded-For', '127.0.0.1', 'IP spoofing'),
            ('X-Forwarded-For', '1.2.3.4', 'Different IP'),
            ('X-Real-IP', '127.0.0.1', 'Real-IP header'),
            ('X-Originating-IP', '127.0.0.1', 'Originating-IP'),
            ('X-Remote-IP', '127.0.0.1', 'Remote-IP'),
            ('X-Client-IP', '127.0.0.1', 'Client-IP'),
            ('True-Client-IP', '127.0.0.1', 'True-Client-IP'),
            ('Forwarded', 'for=127.0.0.1', 'Forwarded header'),
        ]
        
        base_headers = {}
        if self.auth_header:
            base_headers['Authorization'] = self.auth_header
        
        # First, trigger rate limit
        for i in range(50):
            try:
                r = requests.get(self.target_url, headers=base_headers, timeout=5)
                if r.status_code == 429:
                    print(f"    [*] Rate limit triggered, testing bypasses...")
                    break
            except:
                pass
        
        # Test bypass techniques
        bypasses_found = []
        
        for header_name, header_value, description in bypass_tests:
            test_headers = base_headers.copy()
            test_headers[header_name] = header_value
            
            try:
                r = requests.get(self.target_url, headers=test_headers, timeout=5)
                
                if r.status_code != 429:
                    bypasses_found.append({
                        'technique': description,
                        'header': header_name,
                        'value': header_value,
                        'status': r.status_code
                    })
                    print(f"    [!] Bypass found: {description} ({header_name})")
            except:
                pass
        
        if bypasses_found:
            self.vulnerabilities.append({
                'type': 'Rate Limit Bypass - Headers',
                'severity': 'HIGH',
                'description': 'Rate limit can be bypassed using headers',
                'bypasses': bypasses_found,
                'impact': 'Attacker can bypass rate limiting'
            })
            print(f"    [!] HIGH: {len(bypasses_found)} bypass technique(s) found\n")
        else:
            print(f"    [+] No header-based bypasses found\n")
    
    def _test_429_handling(self):
        """Test how server handles rate limit errors"""
        print("[*] Testing 429 response handling...")
        
        # Trigger rate limit
        headers = {}
        if self.auth_header:
            headers['Authorization'] = self.auth_header
        
        for i in range(100):
            try:
                r = requests.get(self.target_url, headers=headers, timeout=5)
                
                if r.status_code == 429:
                    print(f"    [*] 429 response received")
                    print(f"        Status: {r.status_code}")
                    print(f"        Content-Type: {r.headers.get('Content-Type', 'N/A')}")
                    
                    retry_after = r.headers.get('Retry-After')
                    if retry_after:
                        print(f"        Retry-After: {retry_after}")
                    else:
                        self.vulnerabilities.append({
                            'type': 'Missing Retry-After Header',
                            'severity': 'LOW',
                            'description': '429 response missing Retry-After header',
                            'impact': 'Clients cannot determine when to retry'
                        })
                        print(f"    [!] LOW: Missing Retry-After header")
                    
                    if len(r.content) > 0:
                        print(f"        Response body: {r.text[:200]}")
                    
                    print()
                    break
            except:
                pass
    
    def _test_per_endpoint_limits(self):
        """Test if rate limits are per-endpoint or global"""
        print("[*] Testing per-endpoint vs global limits...")
        
        # This would require multiple endpoints
        # For now, just document the finding
        self.vulnerabilities.append({
            'type': 'Rate Limit Scope',
            'severity': 'INFO',
            'description': 'Manual testing recommended to verify per-endpoint limits',
            'recommendation': 'Test multiple endpoints to verify limit scope'
        })
        print(f"    [~] Manual verification recommended\n")
    
    def _test_concurrent_requests(self, request_count=50):
        """Test rate limiting with concurrent requests"""
        print(f"[*] Testing concurrent requests ({request_count} parallel)...")
        
        def make_request(req_num):
            headers = {}
            if self.auth_header:
                headers['Authorization'] = self.auth_header
            
            try:
                r = requests.get(self.target_url, headers=headers, timeout=10)
                return (req_num, r.status_code)
            except Exception as e:
                return (req_num, 'error')
        
        status_codes = defaultdict(int)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(request_count)]
            
            for future in concurrent.futures.as_completed(futures):
                req_num, status = future.result()
                status_codes[status] += 1
        
        print(f"    Results: {dict(status_codes)}")
        
        if 429 not in status_codes:
            self.vulnerabilities.append({
                'type': 'Concurrent Request Bypass',
                'severity': 'MEDIUM',
                'description': 'Rate limit not enforced for concurrent requests',
                'concurrent_requests': request_count,
                'impact': 'Parallel requests bypass rate limiting'
            })
            print(f"    [!] MEDIUM: Concurrent requests bypass rate limit\n")
        else:
            print(f"    [+] Rate limit enforced for concurrent requests\n")
    
    def _test_case_sensitivity(self):
        """Test if endpoint is case-sensitive for rate limiting"""
        print("[*] Testing case sensitivity bypass...")
        
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        
        # Create variations
        variations = [
            self.target_url,
            self.target_url.upper(),
            self.target_url.lower(),
        ]
        
        headers = {}
        if self.auth_header:
            headers['Authorization'] = self.auth_header
        
        results = {}
        for url in set(variations):
            status_codes = []
            for i in range(20):
                try:
                    r = requests.get(url, headers=headers, timeout=5)
                    status_codes.append(r.status_code)
                except:
                    pass
            results[url] = status_codes.count(200)
        
        # Check if any variation bypasses
        if len(set(results.values())) > 1:
            self.vulnerabilities.append({
                'type': 'Case Sensitivity Bypass',
                'severity': 'MEDIUM',
                'description': 'Rate limit can be bypassed with case variations',
                'results': results,
                'impact': 'URL case changes bypass rate limiting'
            })
            print(f"    [!] MEDIUM: Case sensitivity bypass found\n")
        else:
            print(f"    [+] No case sensitivity bypass\n")
    
    def print_report(self):
        print("\n" + "="*70)
        print("RATE LIMITING STRESS VALIDATION REPORT")
        print("="*70 + "\n")
        
        if not self.vulnerabilities:
            print("[+] No rate limiting issues detected!")
            print("[+] Rate limiting appears properly implemented.")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} rate limiting issues:\n")
        
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
                                print(f"      {key}:")
                                for item in value:
                                    if isinstance(item, dict):
                                        for k, v in item.items():
                                            print(f"        {k}: {v}")
                                    else:
                                        print(f"        - {item}")
                            else:
                                print(f"      {key}: {value}")
        
        print("\n" + "="*70)
        print("REMEDIATION RECOMMENDATIONS")
        print("="*70)
        print("""
1. Implement rate limiting at multiple levels:
   - IP-based limits (prevent single IP abuse)
   - User/session-based limits (prevent account abuse)
   - Global limits (protect overall capacity)

2. Use proper HTTP 429 responses with:
   - Retry-After header
   - Clear error messages
   - Appropriate reset times

3. Don't trust client-supplied IP headers:
   - X-Forwarded-For can be spoofed
   - Use actual connection IP when possible

4. Implement rate limits consistently:
   - All endpoints should have limits
   - Case-insensitive URL matching
   - Protection against concurrent requests

5. Consider additional protections:
   - CAPTCHA for repeated failures
   - Account lockout after threshold
   - Progressive delays (exponential backoff)
   - Web Application Firewall (WAF)
        """)

def main():
    if len(sys.argv) < 2:
        print("Rate Limiting Stress Validator")
        print("=" * 50)
        print("\nUsage: python rate_limiting_validator.py <target_url> [requests_count] [--auth <token>]")
        print("\nExamples:")
        print("  python rate_limiting_validator.py https://api.example.com/endpoint")
        print("  python rate_limiting_validator.py https://api.example.com/login 100")
        print("  python rate_limiting_validator.py https://api.example.com/api --auth 'Bearer token123'")
        print("\nDescription:")
        print("  Tests rate limiting effectiveness and bypass techniques:")
        print("  - Basic rate limit testing")
        print("  - Distributed request patterns")
        print("  - Header-based bypasses")
        print("  - Concurrent request handling")
        print("  - 429 response analysis")
        print("\nWARNING:")
        print("  This tool sends many rapid requests")
        print("  May trigger security alerts or temporary blocks")
        print("  Only use on systems you have permission to test!")
        sys.exit(1)
    
    target = sys.argv[1]
    request_count = 100
    auth_header = None
    
    # Parse arguments
    if len(sys.argv) > 2:
        if '--auth' in sys.argv:
            auth_index = sys.argv.index('--auth')
            if len(sys.argv) > auth_index + 1:
                auth_header = sys.argv[auth_index + 1]
        else:
            try:
                request_count = int(sys.argv[2])
            except:
                pass
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print("\n" + "="*70)
    print("RATE LIMITING STRESS VALIDATOR")
    print("="*70 + "\n")
    
    print("[!] WARNING: This tool sends many rapid requests")
    print("[!] Only use on systems you have permission to test!\n")
    
    validator = RateLimitingValidator(target, auth_header)
    validator.validate_all(request_count)
    validator.print_report()
    
    print("\n" + "="*70)
    print("Validation Complete")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()