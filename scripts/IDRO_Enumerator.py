#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) Enumeration Toolkit
Tests for IDOR vulnerabilities by fuzzing object references
"""

import requests
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import concurrent.futures

class IDOREnumerator:
    def __init__(self, target_url, auth_header=None):
        self.target_url = target_url
        self.auth_header = auth_header
        self.vulnerabilities = []
        self.baseline_response = None
    
    def enumerate(self, param_name=None, start=1, end=100):
        print(f"[*] Testing IDOR on: {self.target_url}\n")
        
        # Get baseline response
        self._get_baseline()
        
        # Identify parameters to test
        if param_name:
            self._test_parameter(param_name, start, end)
        else:
            self._identify_and_test_params(start, end)
    
    def _get_baseline(self):
        """Get baseline response for comparison"""
        try:
            headers = {}
            if self.auth_header:
                headers['Authorization'] = self.auth_header
            
            r = requests.get(self.target_url, headers=headers, timeout=5)
            self.baseline_response = r
            print(f"[*] Baseline status: {r.status_code}, Length: {len(r.content)}\n")
        except Exception as e:
            print(f"[!] Error getting baseline: {e}")
            sys.exit(1)
    
    def _identify_and_test_params(self, start, end):
        """Identify and test potential IDOR parameters"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        # Common IDOR parameter names
        common_params = ['id', 'user', 'userid', 'uid', 'account', 'doc', 
                        'document', 'file', 'resource', 'object', 'ref']
        
        # Test existing numeric parameters
        for param, values in params.items():
            if param.lower() in [p.lower() for p in common_params]:
                print(f"[*] Testing parameter: {param}")
                self._test_parameter(param, start, end)
        
        # Test path-based IDs
        if re.search(r'/\d+/?', parsed.path):
            print(f"[*] Testing path-based IDs")
            self._test_path_id(start, end)
    
    def _test_parameter(self, param_name, start, end):
        """Test a specific parameter for IDOR"""
        print(f"[*] Testing {param_name} from {start} to {end}...")
        
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        accessible_ids = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for test_id in range(start, end + 1):
                future = executor.submit(self._test_id_value, param_name, test_id, params, parsed)
                futures.append(future)
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    accessible_ids.append(result)
        
        if len(accessible_ids) > 1:
            self.vulnerabilities.append({
                'type': 'IDOR - Parameter Enumeration',
                'severity': 'HIGH',
                'parameter': param_name,
                'accessible_ids': accessible_ids[:10],  # First 10
                'total_found': len(accessible_ids),
                'description': f'Multiple object IDs accessible via {param_name}'
            })
    
    def _test_id_value(self, param_name, test_id, params, parsed):
        """Test a single ID value"""
        try:
            test_params = params.copy()
            test_params[param_name] = [str(test_id)]
            
            query_string = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, query_string, parsed.fragment
            ))
            
            headers = {}
            if self.auth_header:
                headers['Authorization'] = self.auth_header
            
            r = requests.get(test_url, headers=headers, timeout=5)
            
            # Check if response indicates success
            if self._is_successful_response(r):
                print(f"    [+] ID {test_id}: Status {r.status_code}, Length {len(r.content)}")
                return {
                    'id': test_id,
                    'status': r.status_code,
                    'length': len(r.content)
                }
        except:
            pass
        
        return None
    
    def _test_path_id(self, start, end):
        """Test path-based ID enumeration"""
        parsed = urlparse(self.target_url)
        
        # Extract current ID from path
        id_match = re.search(r'/(\d+)/?', parsed.path)
        if not id_match:
            return
        
        current_id = id_match.group(1)
        base_path = parsed.path.replace(f'/{current_id}', '')
        
        accessible_ids = []
        
        for test_id in range(start, end + 1):
            try:
                test_path = f"{base_path}/{test_id}"
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, test_path,
                    parsed.params, parsed.query, parsed.fragment
                ))
                
                headers = {}
                if self.auth_header:
                    headers['Authorization'] = self.auth_header
                
                r = requests.get(test_url, headers=headers, timeout=5)
                
                if self._is_successful_response(r):
                    print(f"    [+] Path ID {test_id}: Status {r.status_code}")
                    accessible_ids.append(test_id)
            except:
                pass
        
        if len(accessible_ids) > 1:
            self.vulnerabilities.append({
                'type': 'IDOR - Path Enumeration',
                'severity': 'HIGH',
                'accessible_ids': accessible_ids[:10],
                'total_found': len(accessible_ids),
                'description': 'Multiple object IDs accessible via path'
            })
    
    def _is_successful_response(self, response):
        """Determine if response indicates successful access"""
        # Success indicators
        if response.status_code == 200:
            # Check if significantly different from baseline
            if self.baseline_response:
                length_diff = abs(len(response.content) - len(self.baseline_response.content))
                
                # Different content length suggests different resource
                if length_diff > 100:
                    return True
                
                # Check for success indicators in content
                success_patterns = [
                    r'"success":\s*true',
                    r'"error":\s*false',
                    r'"status":\s*"ok"',
                    r'<title>.*</title>'
                ]
                
                for pattern in success_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return True
            else:
                return True
        
        return False
    
    def test_uuid_enumeration(self):
        """Test UUID-based IDOR"""
        print("[*] Testing UUID enumeration...")
        
        # Extract UUID pattern from URL
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        uuid_match = re.search(uuid_pattern, self.target_url, re.IGNORECASE)
        
        if uuid_match:
            current_uuid = uuid_match.group(0)
            
            # Test UUID manipulation
            test_uuids = [
                current_uuid.replace(current_uuid[0], '0'),
                current_uuid.replace(current_uuid[-1], '0'),
                '00000000-0000-0000-0000-000000000001',
                '00000000-0000-0000-0000-000000000002'
            ]
            
            for test_uuid in test_uuids:
                try:
                    test_url = self.target_url.replace(current_uuid, test_uuid)
                    
                    headers = {}
                    if self.auth_header:
                        headers['Authorization'] = self.auth_header
                    
                    r = requests.get(test_url, headers=headers, timeout=5)
                    
                    if r.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'IDOR - UUID Enumeration',
                            'severity': 'MEDIUM',
                            'original_uuid': current_uuid,
                            'accessible_uuid': test_uuid,
                            'description': 'Predictable UUID allows enumeration'
                        })
                except:
                    pass
    
    def print_report(self):
        if not self.vulnerabilities:
            print("\n[+] No IDOR vulnerabilities found!")
            return
        
        print(f"\n[!] Found {len(self.vulnerabilities)} IDOR vulnerabilities:\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"[{i}] {vuln['type']} [{vuln['severity']}]")
            for key, value in vuln.items():
                if key not in ['type', 'severity']:
                    if isinstance(value, list) and len(value) > 5:
                        print(f"    {key}: {value[:5]} ... (showing first 5)")
                    else:
                        print(f"    {key}: {value}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python idor_toolkit.py <target_url> [auth_header] [start] [end]")
        print("Example: python idor_toolkit.py https://api.example.com/user?id=5")
        print("         python idor_toolkit.py https://api.example.com/user/5 'Bearer token123' 1 200")
        sys.exit(1)
    
    target = sys.argv[1]
    auth = sys.argv[2] if len(sys.argv) > 2 else None
    start = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    end = int(sys.argv[4]) if len(sys.argv) > 4 else 100
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    enumerator = IDOREnumerator(target, auth)
    enumerator.enumerate(start=start, end=end)
    enumerator.test_uuid_enumeration()
    enumerator.print_report()

if __name__ == "__main__":
    main()