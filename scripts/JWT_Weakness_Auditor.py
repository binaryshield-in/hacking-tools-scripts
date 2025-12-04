#!/usr/bin/env python3
"""
JWT Weakness Auditor
Tests JSON Web Tokens for common security vulnerabilities

Installation:
    pip install requests pyjwt cryptography

Usage:
    python jwt_auditor.py <jwt_token> [target_url]
    
Example:
    python jwt_auditor.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    python jwt_auditor.py eyJhbGc... https://api.example.com/user
"""

import requests
import sys
import json
import base64
import hashlib
import hmac
import time

class JWTAuditor:
    def __init__(self, jwt_token, target_url=None):
        self.jwt_token = jwt_token
        self.target_url = target_url
        self.vulnerabilities = []
        self.header = {}
        self.payload = {}
        self.signature = ""
        
        self._parse_jwt()
    
    def _parse_jwt(self):
        """Parse JWT token into header, payload, and signature"""
        try:
            parts = self.jwt_token.split('.')
            if len(parts) != 3:
                print("[!] Invalid JWT format (expected 3 parts)")
                sys.exit(1)
            
            # Decode header
            header_data = parts[0] + '=' * (4 - len(parts[0]) % 4)
            self.header = json.loads(base64.urlsafe_b64decode(header_data))
            
            # Decode payload
            payload_data = parts[1] + '=' * (4 - len(parts[1]) % 4)
            self.payload = json.loads(base64.urlsafe_b64decode(payload_data))
            
            # Store signature
            self.signature = parts[2]
            
            print("[*] JWT Successfully Parsed:")
            print(f"\n[*] Header: {json.dumps(self.header, indent=2)}")
            print(f"\n[*] Payload: {json.dumps(self.payload, indent=2)}\n")
        except Exception as e:
            print(f"[!] Error parsing JWT: {e}")
            sys.exit(1)
    
    def audit_all(self):
        print("="*70)
        print("JWT SECURITY AUDIT")
        print("="*70 + "\n")
        
        self._check_algorithm_none()
        self._check_algorithm_confusion()
        self._check_weak_secret()
        self._check_sensitive_data()
        self._check_expiration()
        self._check_kid_injection()
        self._check_jku_jwe_headers()
        self._test_signature_stripping()
        self._check_claims()
        
        return self.vulnerabilities
    
    def _check_algorithm_none(self):
        """Test algorithm=none bypass"""
        print("[*] Testing algorithm='none' attack...")
        
        parts = self.jwt_token.split('.')
        
        # Create header with alg=none
        none_header = self.header.copy()
        none_header['alg'] = 'none'
        
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(none_header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        # Create tokens with empty signature
        none_tokens = [
            f"{encoded_header}.{parts[1]}.",
            f"{encoded_header}.{parts[1]}",
        ]
        
        for none_token in none_tokens:
            if self.target_url:
                try:
                    headers = {'Authorization': f'Bearer {none_token}'}
                    r = requests.get(self.target_url, headers=headers, timeout=5)
                    
                    if r.status_code == 200 and 'error' not in r.text.lower():
                        self.vulnerabilities.append({
                            'type': 'Algorithm None Attack',
                            'severity': 'CRITICAL',
                            'description': 'Server accepts JWT with alg=none (no signature verification)',
                            'exploit_token': none_token[:50] + '...'
                        })
                        print(f"    [!] CRITICAL: Server accepts alg=none")
                        return
                except:
                    pass
        
        print(f"    [+] alg=none attack blocked")
    
    def _check_algorithm_confusion(self):
        """Test RS256 to HS256 algorithm confusion"""
        print("[*] Testing algorithm confusion...")
        
        current_alg = self.header.get('alg', '').upper()
        
        if current_alg == 'RS256':
            self.vulnerabilities.append({
                'type': 'Potential Algorithm Confusion',
                'severity': 'HIGH',
                'description': 'Token uses RS256. May be vulnerable to HS256 confusion if public key is known',
                'current_alg': 'RS256',
                'attack_alg': 'HS256',
                'impact': 'Attacker can sign tokens using public key as HMAC secret'
            })
            print(f"    [!] HIGH: RS256 detected (vulnerable to alg confusion)")
        elif current_alg.startswith('HS'):
            print(f"    [+] Uses {current_alg} (symmetric)")
        else:
            print(f"    [+] Algorithm: {current_alg}")
    
    def _check_weak_secret(self):
        """Test for weak HMAC secrets"""
        print("[*] Testing for weak HMAC secrets...")
        
        if not self.header.get('alg', '').startswith('HS'):
            print(f"    [~] Not an HMAC algorithm, skipping")
            return
        
        weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key',
            'secretkey', 'mykey', 'jwt', 'token', 'hello', 'world',
            '', 'null', 'undefined', '12345', 'qwerty', 'abc123',
            'password123', 'admin123', 'secret123', 'jwt_secret'
        ]
        
        parts = self.jwt_token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        original_sig = parts[2]
        
        algorithms = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        
        for secret in weak_secrets:
            for alg_name, hash_func in algorithms.items():
                try:
                    signature = hmac.new(
                        secret.encode(),
                        message.encode(),
                        hash_func
                    ).digest()
                    
                    encoded_sig = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                    
                    if encoded_sig == original_sig:
                        self.vulnerabilities.append({
                            'type': 'Weak HMAC Secret',
                            'severity': 'CRITICAL',
                            'secret': secret,
                            'algorithm': alg_name,
                            'description': f'JWT signed with weak/common secret: "{secret}"',
                            'impact': 'Attacker can forge valid tokens'
                        })
                        print(f"    [!] CRITICAL: Weak secret found: '{secret}' with {alg_name}")
                        return
                except:
                    pass
        
        print(f"    [+] No weak secrets found in common list")
    
    def _check_sensitive_data(self):
        """Check for sensitive data in payload"""
        print("[*] Checking for sensitive data exposure...")
        
        sensitive_patterns = {
            'password': ['password', 'passwd', 'pwd'],
            'secrets': ['secret', 'api_key', 'apikey', 'token', 'private_key'],
            'financial': ['credit_card', 'cc', 'cvv', 'ssn', 'account_number'],
            'personal': ['phone', 'address', 'dob', 'birth']
        }
        
        found_sensitive = []
        payload_str = json.dumps(self.payload).lower()
        payload_keys = [k.lower() for k in self.payload.keys()]
        
        for category, patterns in sensitive_patterns.items():
            for pattern in patterns:
                if any(pattern in key for key in payload_keys) or pattern in payload_str:
                    found_sensitive.append(f"{pattern} ({category})")
        
        if found_sensitive:
            self.vulnerabilities.append({
                'type': 'Sensitive Data Exposure',
                'severity': 'HIGH',
                'description': 'JWT payload contains potentially sensitive data',
                'sensitive_fields': list(set(found_sensitive)),
                'impact': 'JWT payloads are only base64 encoded, not encrypted'
            })
            print(f"    [!] HIGH: Sensitive data found: {', '.join(set(found_sensitive))}")
        else:
            print(f"    [+] No obvious sensitive data in payload")
    
    def _check_expiration(self):
        """Check token expiration and timing claims"""
        print("[*] Checking expiration and timing...")
        
        current_time = int(time.time())
        issues = []
        
        # Check exp (expiration)
        if 'exp' not in self.payload:
            self.vulnerabilities.append({
                'type': 'Missing Expiration',
                'severity': 'MEDIUM',
                'description': 'JWT does not have expiration claim (exp)',
                'impact': 'Token never expires, increasing attack window'
            })
            issues.append("No expiration")
        else:
            exp_time = self.payload['exp']
            time_diff = exp_time - current_time
            
            if exp_time < current_time:
                issues.append(f"Expired {-time_diff} seconds ago")
            elif time_diff > (365 * 24 * 3600):
                self.vulnerabilities.append({
                    'type': 'Long Expiration Time',
                    'severity': 'MEDIUM',
                    'description': f'JWT expires more than 1 year in the future',
                    'exp_timestamp': exp_time,
                    'days_until_exp': time_diff // (24 * 3600)
                })
                issues.append(f"Expires in {time_diff // (24 * 3600)} days")
            else:
                issues.append(f"Expires in {time_diff // 60} minutes")
        
        # Check nbf (not before)
        if 'nbf' not in self.payload:
            issues.append("No 'not before' claim")
        
        # Check iat (issued at)
        if 'iat' not in self.payload:
            issues.append("No 'issued at' claim")
        
        if len(issues) > 0:
            print(f"    [~] Timing issues: {', '.join(issues)}")
        else:
            print(f"    [+] Proper timing claims present")
    
    def _check_kid_injection(self):
        """Check for key ID injection vulnerabilities"""
        print("[*] Checking 'kid' (Key ID) parameter...")
        
        if 'kid' not in self.header:
            print(f"    [~] No 'kid' parameter present")
            return
        
        kid = self.header['kid']
        issues = []
        
        # Check for path traversal
        if '../' in kid or '..' in kid or '\\' in kid:
            issues.append('path traversal')
            self.vulnerabilities.append({
                'type': 'KID Path Traversal',
                'severity': 'HIGH',
                'description': 'Key ID contains path traversal sequences',
                'kid': kid,
                'impact': 'May allow reading arbitrary files as signing keys'
            })
        
        # Check for SQL injection patterns
        sql_patterns = ["'", '"', '--', ';', ' OR ', ' AND ', 'UNION']
        if any(pattern in kid.upper() for pattern in sql_patterns):
            issues.append('SQL injection patterns')
            self.vulnerabilities.append({
                'type': 'Potential KID SQL Injection',
                'severity': 'HIGH',
                'description': 'Key ID contains SQL injection patterns',
                'kid': kid
            })
        
        # Check for command injection
        if any(char in kid for char in ['|', ';', '&', '$', '`', '\n']):
            issues.append('command injection chars')
            self.vulnerabilities.append({
                'type': 'Potential KID Command Injection',
                'severity': 'HIGH',
                'description': 'Key ID contains command injection characters',
                'kid': kid
            })
        
        if issues:
            print(f"    [!] HIGH: kid vulnerable to {', '.join(issues)}")
        else:
            print(f"    [+] kid parameter looks safe: {kid}")
    
    def _check_jku_jwe_headers(self):
        """Check for JKU/JWE header injection"""
        print("[*] Checking for risky header parameters...")
        
        risky_headers = {
            'jku': 'JWK Set URL',
            'jwk': 'JSON Web Key',
            'x5u': 'X.509 URL',
            'x5c': 'X.509 Certificate Chain'
        }
        
        found = []
        for header, description in risky_headers.items():
            if header in self.header:
                self.vulnerabilities.append({
                    'type': f'{header.upper()} Header Present',
                    'severity': 'HIGH',
                    'description': f'JWT uses {description} ({header}) header',
                    'value': str(self.header[header])[:100],
                    'impact': 'Attacker may be able to specify their own signing key'
                })
                found.append(header)
        
        if found:
            print(f"    [!] HIGH: Risky headers present: {', '.join(found)}")
        else:
            print(f"    [+] No risky headers found")
    
    def _test_signature_stripping(self):
        """Test signature stripping"""
        print("[*] Testing signature stripping...")
        
        if not self.target_url:
            print(f"    [~] No target URL provided, skipping")
            return
        
        parts = self.jwt_token.split('.')
        stripped_tokens = [
            f"{parts[0]}.{parts[1]}.",
            f"{parts[0]}.{parts[1]}"
        ]
        
        for stripped_token in stripped_tokens:
            try:
                headers = {'Authorization': f'Bearer {stripped_token}'}
                r = requests.get(self.target_url, headers=headers, timeout=5)
                
                if r.status_code == 200 and 'error' not in r.text.lower():
                    self.vulnerabilities.append({
                        'type': 'Signature Stripping',
                        'severity': 'CRITICAL',
                        'description': 'Server accepts JWT without signature verification',
                        'exploit_token': stripped_token[:50] + '...'
                    })
                    print(f"    [!] CRITICAL: Server accepts tokens without signature")
                    return
            except:
                pass
        
        print(f"    [+] Signature stripping blocked")
    
    def _check_claims(self):
        """Check for standard JWT claims"""
        print("[*] Checking JWT claims...")
        
        standard_claims = {
            'iss': 'Issuer',
            'sub': 'Subject',
            'aud': 'Audience',
            'exp': 'Expiration',
            'nbf': 'Not Before',
            'iat': 'Issued At',
            'jti': 'JWT ID'
        }
        
        missing = []
        present = []
        
        for claim, description in standard_claims.items():
            if claim in self.payload:
                present.append(f"{claim}={self.payload[claim]}")
            else:
                missing.append(claim)
        
        if missing:
            print(f"    [~] Missing claims: {', '.join(missing)}")
        if present:
            print(f"    [+] Present claims: {', '.join(present[:3])}...")
    
    def print_report(self):
        print("\n" + "="*70)
        print("JWT SECURITY AUDIT REPORT")
        print("="*70 + "\n")
        
        if not self.vulnerabilities:
            print("[+] No critical JWT vulnerabilities found!")
            print("[+] Token appears to follow security best practices.")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} JWT security issues:\n")
        
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

def main():
    if len(sys.argv) < 2:
        print("JWT Weakness Auditor")
        print("=" * 50)
        print("\nUsage: python jwt_auditor.py <jwt_token> [target_url]")
        print("\nExamples:")
        print("  python jwt_auditor.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        print("  python jwt_auditor.py eyJhbGc... https://api.example.com/user")
        print("\nDescription:")
        print("  Audits JWT tokens for common security vulnerabilities:")
        print("  - Algorithm confusion attacks")
        print("  - Weak HMAC secrets")
        print("  - Sensitive data exposure")
        print("  - Missing expiration")
        print("  - Key injection vulnerabilities")
        sys.exit(1)
    
    jwt_token = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else None
    
    print("\n" + "="*70)
    print("JWT WEAKNESS AUDITOR")
    print("="*70 + "\n")
    
    auditor = JWTAuditor(jwt_token, target_url)
    auditor.audit_all()
    auditor.print_report()
    
    print("\n" + "="*70)
    print("Audit Complete")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()