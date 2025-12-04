#!/usr/bin/env python3
"""
CSP (Content Security Policy) Configuration Gap Scanner
Analyzes CSP headers for security weaknesses and misconfigurations

Installation:
    pip install requests

Usage:
    python csp_scanner.py <target_url>
    
Example:
    python csp_scanner.py https://example.com
    python csp_scanner.py https://app.example.com/dashboard
    
Description:
    Analyzes Content-Security-Policy headers for:
    - Missing or weak directives
    - Unsafe configurations (unsafe-inline, unsafe-eval)
    - Wildcard sources
    - Deprecated directives
    - CSP bypasses
"""

import requests
import sys
import re
from urllib.parse import urlparse
from collections import defaultdict

class CSPScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.csp_header = None
        self.csp_directives = {}
        
    def scan(self):
        print(f"[*] Scanning CSP Configuration for: {self.target_url}\n")
        
        # Fetch and parse CSP
        if not self._fetch_csp():
            return self.vulnerabilities
        
        self._parse_csp()
        self._print_csp()
        
        # Run all checks
        self._check_missing_directives()
        self._check_unsafe_keywords()
        self._check_wildcard_sources()
        self._check_http_sources()
        self._check_deprecated_directives()
        self._check_nonce_hash_usage()
        self._check_frame_options()
        self._check_base_uri()
        self._check_form_action()
        self._check_object_src()
        self._check_script_src_bypasses()
        self._check_csp_report()
        
        return self.vulnerabilities
    
    def _fetch_csp(self):
        """Fetch CSP header from target"""
        try:
            r = requests.get(self.target_url, timeout=10)
            
            # Check for CSP header
            csp_headers = [
                'Content-Security-Policy',
                'Content-Security-Policy-Report-Only',
                'X-Content-Security-Policy',
                'X-WebKit-CSP'
            ]
            
            for header in csp_headers:
                if header in r.headers:
                    self.csp_header = r.headers[header]
                    print(f"[+] Found CSP header: {header}\n")
                    return True
            
            # Check for CSP in meta tag
            if '<meta' in r.text.lower() and 'content-security-policy' in r.text.lower():
                match = re.search(r'<meta[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*content=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
                if match:
                    self.csp_header = match.group(1)
                    print(f"[+] Found CSP in meta tag\n")
                    return True
            
            self.vulnerabilities.append({
                'type': 'Missing CSP',
                'severity': 'HIGH',
                'description': 'No Content-Security-Policy header found',
                'impact': 'Site vulnerable to XSS and injection attacks',
                'recommendation': 'Implement a strict Content-Security-Policy'
            })
            print(f"[!] HIGH: No CSP header found\n")
            return False
            
        except Exception as e:
            print(f"[!] Error fetching CSP: {e}")
            return False
    
    def _parse_csp(self):
        """Parse CSP header into directives"""
        directives = self.csp_header.split(';')
        
        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue
            
            parts = directive.split(None, 1)
            if len(parts) == 1:
                self.csp_directives[parts[0]] = []
            else:
                self.csp_directives[parts[0]] = parts[1].split()
    
    def _print_csp(self):
        """Print parsed CSP directives"""
        print("="*70)
        print("CSP DIRECTIVES")
        print("="*70)
        for directive, values in self.csp_directives.items():
            values_str = ' '.join(values) if values else '(empty)'
            print(f"  {directive}: {values_str}")
        print("="*70 + "\n")
    
    def _check_missing_directives(self):
        """Check for missing important directives"""
        print("[*] Checking for missing critical directives...")
        
        critical_directives = {
            'default-src': 'Fallback for all fetch directives',
            'script-src': 'Controls JavaScript sources',
            'object-src': 'Controls plugin sources',
            'base-uri': 'Controls <base> element URLs',
        }
        
        missing = []
        for directive, description in critical_directives.items():
            if directive not in self.csp_directives:
                missing.append((directive, description))
        
        if missing:
            self.vulnerabilities.append({
                'type': 'Missing Critical Directives',
                'severity': 'HIGH',
                'missing_directives': [f"{d}: {desc}" for d, desc in missing],
                'description': f'{len(missing)} critical directive(s) missing',
                'impact': 'Incomplete XSS protection'
            })
            print(f"    [!] HIGH: {len(missing)} critical directives missing")
            for directive, desc in missing:
                print(f"        - {directive}: {desc}")
        else:
            print(f"    [+] All critical directives present")
        print()
    
    def _check_unsafe_keywords(self):
        """Check for unsafe-inline and unsafe-eval"""
        print("[*] Checking for unsafe keywords...")
        
        unsafe_found = []
        
        for directive, values in self.csp_directives.items():
            if "'unsafe-inline'" in values:
                unsafe_found.append({
                    'directive': directive,
                    'keyword': 'unsafe-inline',
                    'severity': 'HIGH',
                    'impact': 'Allows inline scripts/styles, defeats CSP purpose'
                })
                print(f"    [!] HIGH: 'unsafe-inline' in {directive}")
            
            if "'unsafe-eval'" in values:
                unsafe_found.append({
                    'directive': directive,
                    'keyword': 'unsafe-eval',
                    'severity': 'MEDIUM',
                    'impact': 'Allows eval() and similar dangerous functions'
                })
                print(f"    [!] MEDIUM: 'unsafe-eval' in {directive}")
        
        if unsafe_found:
            self.vulnerabilities.append({
                'type': 'Unsafe Keywords',
                'severity': 'HIGH',
                'unsafe_directives': unsafe_found,
                'description': 'CSP contains unsafe keywords',
                'recommendation': 'Use nonces or hashes instead of unsafe-inline'
            })
        else:
            print(f"    [+] No unsafe keywords found")
        print()
    
    def _check_wildcard_sources(self):
        """Check for wildcard sources"""
        print("[*] Checking for wildcard sources...")
        
        wildcards = []
        
        for directive, values in self.csp_directives.items():
            for value in values:
                if value == '*':
                    wildcards.append({
                        'directive': directive,
                        'value': '*',
                        'severity': 'HIGH',
                        'impact': 'Allows resources from any origin'
                    })
                    print(f"    [!] HIGH: Wildcard '*' in {directive}")
                
                elif value.startswith('*.'):
                    wildcards.append({
                        'directive': directive,
                        'value': value,
                        'severity': 'MEDIUM',
                        'impact': f'Allows all subdomains of {value}'
                    })
                    print(f"    [!] MEDIUM: Subdomain wildcard '{value}' in {directive}")
                
                elif value.startswith('*://'):
                    wildcards.append({
                        'directive': directive,
                        'value': value,
                        'severity': 'MEDIUM',
                        'impact': 'Allows both HTTP and HTTPS'
                    })
                    print(f"    [!] MEDIUM: Protocol wildcard '{value}' in {directive}")
        
        if wildcards:
            self.vulnerabilities.append({
                'type': 'Wildcard Sources',
                'severity': 'HIGH',
                'wildcards': wildcards,
                'description': 'CSP contains wildcard sources',
                'recommendation': 'Use specific hostnames instead of wildcards'
            })
        else:
            print(f"    [+] No wildcard sources found")
        print()
    
    def _check_http_sources(self):
        """Check for HTTP (non-HTTPS) sources"""
        print("[*] Checking for insecure HTTP sources...")
        
        http_sources = []
        
        for directive, values in self.csp_directives.items():
            for value in values:
                if value.startswith('http://') or value.startswith('http:'):
                    http_sources.append({
                        'directive': directive,
                        'source': value
                    })
                    print(f"    [!] MEDIUM: HTTP source '{value}' in {directive}")
        
        if http_sources:
            self.vulnerabilities.append({
                'type': 'Insecure HTTP Sources',
                'severity': 'MEDIUM',
                'http_sources': http_sources,
                'description': 'CSP allows HTTP sources',
                'impact': 'Resources can be loaded over insecure connections',
                'recommendation': 'Use HTTPS-only sources or upgrade-insecure-requests'
            })
        else:
            print(f"    [+] No HTTP sources found")
        print()
    
    def _check_deprecated_directives(self):
        """Check for deprecated directives"""
        print("[*] Checking for deprecated directives...")
        
        deprecated = {
            'reflected-xss': 'Deprecated, use X-XSS-Protection header',
            'referrer': 'Deprecated, use Referrer-Policy header',
            'plugin-types': 'Deprecated in CSP Level 3'
        }
        
        found_deprecated = []
        for directive in self.csp_directives.keys():
            if directive in deprecated:
                found_deprecated.append({
                    'directive': directive,
                    'reason': deprecated[directive]
                })
                print(f"    [!] LOW: Deprecated directive '{directive}'")
        
        if found_deprecated:
            self.vulnerabilities.append({
                'type': 'Deprecated Directives',
                'severity': 'LOW',
                'deprecated': found_deprecated,
                'description': 'CSP uses deprecated directives'
            })
        else:
            print(f"    [+] No deprecated directives")
        print()
    
    def _check_nonce_hash_usage(self):
        """Check for proper nonce or hash usage"""
        print("[*] Checking nonce/hash implementation...")
        
        has_nonce = False
        has_hash = False
        has_unsafe_inline = False
        
        for directive, values in self.csp_directives.items():
            if directive in ['script-src', 'style-src']:
                for value in values:
                    if value.startswith("'nonce-"):
                        has_nonce = True
                        print(f"    [+] Nonce found in {directive}")
                    elif value.startswith("'sha"):
                        has_hash = True
                        print(f"    [+] Hash found in {directive}")
                    elif value == "'unsafe-inline'":
                        has_unsafe_inline = True
        
        if has_unsafe_inline and not has_nonce and not has_hash:
            self.vulnerabilities.append({
                'type': 'Unsafe Inline Without Nonce/Hash',
                'severity': 'HIGH',
                'description': 'Using unsafe-inline without nonces or hashes',
                'recommendation': 'Replace unsafe-inline with nonces or hashes'
            })
            print(f"    [!] HIGH: unsafe-inline without nonce/hash fallback")
        elif not has_unsafe_inline and (has_nonce or has_hash):
            print(f"    [+] Proper nonce/hash usage (no unsafe-inline)")
        print()
    
    def _check_frame_options(self):
        """Check frame-ancestors directive"""
        print("[*] Checking frame-ancestors...")
        
        if 'frame-ancestors' not in self.csp_directives:
            self.vulnerabilities.append({
                'type': 'Missing frame-ancestors',
                'severity': 'MEDIUM',
                'description': 'No frame-ancestors directive',
                'impact': 'Site may be vulnerable to clickjacking',
                'recommendation': "Add frame-ancestors 'none' or specific origins"
            })
            print(f"    [!] MEDIUM: Missing frame-ancestors directive")
        else:
            values = self.csp_directives['frame-ancestors']
            if '*' in values:
                print(f"    [!] HIGH: frame-ancestors allows all origins")
                self.vulnerabilities.append({
                    'type': 'Permissive frame-ancestors',
                    'severity': 'HIGH',
                    'description': 'frame-ancestors allows all origins',
                    'impact': 'Site can be framed by any domain'
                })
            else:
                print(f"    [+] frame-ancestors configured: {' '.join(values)}")
        print()
    
    def _check_base_uri(self):
        """Check base-uri directive"""
        print("[*] Checking base-uri...")
        
        if 'base-uri' not in self.csp_directives:
            self.vulnerabilities.append({
                'type': 'Missing base-uri',
                'severity': 'MEDIUM',
                'description': 'No base-uri directive',
                'impact': 'Attacker can inject <base> tag to hijack relative URLs',
                'recommendation': "Add base-uri 'self' or 'none'"
            })
            print(f"    [!] MEDIUM: Missing base-uri directive")
        else:
            values = self.csp_directives['base-uri']
            if '*' in values:
                print(f"    [!] HIGH: base-uri allows all origins")
            else:
                print(f"    [+] base-uri configured: {' '.join(values)}")
        print()
    
    def _check_form_action(self):
        """Check form-action directive"""
        print("[*] Checking form-action...")
        
        if 'form-action' not in self.csp_directives:
            self.vulnerabilities.append({
                'type': 'Missing form-action',
                'severity': 'LOW',
                'description': 'No form-action directive',
                'impact': 'Forms can submit to any destination',
                'recommendation': "Add form-action 'self' or specific origins"
            })
            print(f"    [!] LOW: Missing form-action directive")
        else:
            values = self.csp_directives['form-action']
            if '*' in values:
                print(f"    [!] MEDIUM: form-action allows all destinations")
            else:
                print(f"    [+] form-action configured: {' '.join(values)}")
        print()
    
    def _check_object_src(self):
        """Check object-src directive"""
        print("[*] Checking object-src...")
        
        if 'object-src' not in self.csp_directives:
            self.vulnerabilities.append({
                'type': 'Missing object-src',
                'severity': 'HIGH',
                'description': 'No object-src directive',
                'impact': 'Plugins like Flash can be loaded from anywhere',
                'recommendation': "Add object-src 'none' to block plugins"
            })
            print(f"    [!] HIGH: Missing object-src directive")
        else:
            values = self.csp_directives['object-src']
            if "'none'" in values:
                print(f"    [+] object-src set to 'none' (recommended)")
            else:
                print(f"    [~] object-src configured: {' '.join(values)}")
        print()
    
    def _check_script_src_bypasses(self):
        """Check for common CSP bypasses in script-src"""
        print("[*] Checking for CSP bypass vectors...")
        
        bypasses = []
        
        if 'script-src' in self.csp_directives:
            values = ' '.join(self.csp_directives['script-src'])
            
            # JSONP endpoints that can be used for CSP bypass
            jsonp_endpoints = [
                'googleapis.com', 'google.com/recaptcha',
                'gstatic.com', 'google-analytics.com',
                'youtube.com', 'facebook.com', 'twitter.com'
            ]
            
            for endpoint in jsonp_endpoints:
                if endpoint in values:
                    bypasses.append({
                        'source': endpoint,
                        'risk': 'May have JSONP endpoints usable for bypass'
                    })
                    print(f"    [!] MEDIUM: {endpoint} may enable JSONP bypass")
            
            # Angular bypass
            if "'unsafe-eval'" in values or 'angular' in values.lower():
                bypasses.append({
                    'source': 'Angular/unsafe-eval',
                    'risk': 'Angular templates with unsafe-eval can be exploited'
                })
                print(f"    [!] HIGH: Angular with unsafe-eval is bypassable")
        
        if bypasses:
            self.vulnerabilities.append({
                'type': 'Potential CSP Bypasses',
                'severity': 'HIGH',
                'bypasses': bypasses,
                'description': 'CSP may be bypassable via allowed sources',
                'recommendation': 'Review whitelisted domains for JSONP endpoints'
            })
        else:
            print(f"    [+] No obvious bypass vectors detected")
        print()
    
    def _check_csp_report(self):
        """Check for CSP reporting configuration"""
        print("[*] Checking CSP reporting...")
        
        reporting_directives = ['report-uri', 'report-to']
        has_reporting = any(d in self.csp_directives for d in reporting_directives)
        
        if has_reporting:
            for directive in reporting_directives:
                if directive in self.csp_directives:
                    print(f"    [+] {directive} configured: {' '.join(self.csp_directives[directive])}")
        else:
            self.vulnerabilities.append({
                'type': 'No CSP Reporting',
                'severity': 'LOW',
                'description': 'No report-uri or report-to directive',
                'impact': 'CSP violations are not logged',
                'recommendation': 'Add reporting to monitor violations'
            })
            print(f"    [!] LOW: No CSP reporting configured")
        print()
    
    def print_report(self):
        print("\n" + "="*70)
        print("CSP CONFIGURATION GAP ANALYSIS REPORT")
        print("="*70 + "\n")
        
        if not self.vulnerabilities:
            print("[+] No CSP configuration issues found!")
            print("[+] CSP appears to be well-configured.")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} CSP configuration issues:\n")
        
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
                                    if isinstance(item, dict):
                                        for k, v in item.items():
                                            print(f"        {k}: {v}")
                                    else:
                                        print(f"        - {item}")
                            else:
                                print(f"      {key}: {value}")
        
        print("\n" + "="*70)
        print("BEST PRACTICES")
        print("="*70)
        print("""
1. Start with a strict policy:
   Content-Security-Policy: default-src 'none'; script-src 'self'; 
   style-src 'self'; img-src 'self'; font-src 'self'; 
   connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; 
   form-action 'self'; object-src 'none'

2. Use nonces or hashes instead of 'unsafe-inline':
   script-src 'nonce-{random}' or 'sha256-{hash}'

3. Avoid wildcards - be specific with allowed sources

4. Use HTTPS-only sources

5. Enable CSP reporting to monitor violations:
   report-uri https://your-domain.com/csp-report

6. Test in report-only mode first:
   Content-Security-Policy-Report-Only

7. Use frame-ancestors instead of X-Frame-Options

8. Set object-src to 'none' to block plugins

9. Use upgrade-insecure-requests for mixed content

10. Review and update CSP regularly
        """)

def main():
    if len(sys.argv) < 2:
        print("CSP Configuration Gap Scanner")
        print("=" * 50)
        print("\nUsage: python csp_scanner.py <target_url>")
        print("\nExamples:")
        print("  python csp_scanner.py https://example.com")
        print("  python csp_scanner.py https://app.example.com/dashboard")
        print("\nDescription:")
        print("  Analyzes Content-Security-Policy headers for:")
        print("  - Missing critical directives")
        print("  - Unsafe keywords (unsafe-inline, unsafe-eval)")
        print("  - Wildcard sources")
        print("  - HTTP (non-HTTPS) sources")
        print("  - Potential CSP bypasses")
        print("  - Deprecated directives")
        sys.exit(1)
    
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print("\n" + "="*70)
    print("CSP CONFIGURATION GAP SCANNER")
    print("="*70 + "\n")
    
    scanner = CSPScanner(target)
    scanner.scan()
    scanner.print_report()
    
    print("\n" + "="*70)
    print("Scan Complete")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()