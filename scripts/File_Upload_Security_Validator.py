#!/usr/bin/env python3
"""
File Upload Security Validator
Tests file upload functionality for security vulnerabilities

Installation:
    pip install requests

Usage:
    python file_upload_validator.py <upload_endpoint> [field_name]
    
Example:
    python file_upload_validator.py https://example.com/upload
    python file_upload_validator.py https://example.com/api/files file
"""

import requests
import sys
from io import BytesIO

class FileUploadValidator:
    def __init__(self, target_url, field_name='file'):
        self.target_url = target_url
        self.field_name = field_name
        self.vulnerabilities = []
    
    def test_uploads(self):
        print(f"[*] Testing File Upload Security on: {self.target_url}")
        print(f"[*] Using field name: {self.field_name}\n")
        
        self._test_executable_extensions()
        self._test_mime_type_bypass()
        self._test_double_extensions()
        self._test_null_byte_injection()
        self._test_content_type_validation()
        self._test_path_traversal()
        self._test_polyglot_files()
        self._test_file_size_limits()
    
    def _test_executable_extensions(self):
        """Test if dangerous extensions are allowed"""
        print("[*] Testing executable extensions...")
        
        dangerous_extensions = [
            ('.php', '<?php echo "test"; ?>', 'PHP script'),
            ('.php3', '<?php echo "test"; ?>', 'PHP3 script'),
            ('.php4', '<?php echo "test"; ?>', 'PHP4 script'),
            ('.php5', '<?php echo "test"; ?>', 'PHP5 script'),
            ('.phtml', '<?php echo "test"; ?>', 'PHTML script'),
            ('.asp', '<% Response.Write("test") %>', 'ASP script'),
            ('.aspx', '<% Response.Write("test") %>', 'ASPX script'),
            ('.jsp', '<% out.print("test"); %>', 'JSP script'),
            ('.py', 'print("test")', 'Python script'),
            ('.pl', 'print "test";', 'Perl script'),
            ('.cgi', '#!/bin/bash\necho test', 'CGI script'),
            ('.sh', '#!/bin/bash\necho test', 'Shell script'),
            ('.exe', 'MZ', 'Executable')
        ]
        
        for ext, content, description in dangerous_extensions:
            filename = f"test{ext}"
            
            if self._upload_file(filename, content.encode()):
                self.vulnerabilities.append({
                    'type': 'Dangerous Extension Allowed',
                    'severity': 'CRITICAL',
                    'extension': ext,
                    'filename': filename,
                    'file_type': description,
                    'description': f'Server accepts {description} files'
                })
                print(f"    [!] CRITICAL: {ext} allowed ({description})")
            else:
                print(f"    [+] {ext} blocked")
    
    def _test_mime_type_bypass(self):
        """Test MIME type validation bypass"""
        print("\n[*] Testing MIME type bypass...")
        
        bypass_tests = [
            ('shell.php', 'image/jpeg', b'<?php phpinfo(); ?>', 'PHP as JPEG'),
            ('shell.php', 'image/png', b'<?php phpinfo(); ?>', 'PHP as PNG'),
            ('shell.php', 'image/gif', b'<?php phpinfo(); ?>', 'PHP as GIF'),
            ('shell.php', 'text/plain', b'<?php phpinfo(); ?>', 'PHP as text'),
            ('test.jpg.php', 'image/jpeg', b'<?php phpinfo(); ?>', 'Double ext with JPEG type'),
        ]
        
        for filename, mime_type, content, description in bypass_tests:
            if self._upload_file(filename, content, mime_type):
                self.vulnerabilities.append({
                    'type': 'MIME Type Bypass',
                    'severity': 'HIGH',
                    'filename': filename,
                    'mime_type': mime_type,
                    'description': f'{description} - Server trusts client MIME type'
                })
                print(f"    [!] HIGH: {description} successful")
    
    def _test_double_extensions(self):
        """Test double extension bypass"""
        print("\n[*] Testing double extensions...")
        
        double_ext_tests = [
            ('shell.php.jpg', 'Double extension'),
            ('shell.jpg.php', 'Reverse double extension'),
            ('shell.php.png', 'PHP.PNG'),
            ('shell.php.gif', 'PHP.GIF'),
            ('shell.php;.jpg', 'Semicolon separator'),
            ('shell.php .jpg', 'Space separator'),
            ('shell.php%00.jpg', 'Null byte (URL encoded)'),
        ]
        
        for filename, description in double_ext_tests:
            content = b'<?php phpinfo(); ?>'
            
            if self._upload_file(filename, content, 'image/jpeg'):
                self.vulnerabilities.append({
                    'type': 'Double Extension Bypass',
                    'severity': 'HIGH',
                    'filename': filename,
                    'technique': description,
                    'description': f'{description} bypass successful'
                })
                print(f"    [!] HIGH: {description} allowed")
    
    def _test_null_byte_injection(self):
        """Test null byte injection"""
        print("\n[*] Testing null byte injection...")
        
        # Null byte in different encodings
        null_byte_tests = [
            ('shell.php\x00.jpg', 'Null byte'),
            ('shell.php%00.jpg', 'URL encoded null'),
            ('shell.php%2500.jpg', 'Double encoded null'),
        ]
        
        for filename, description in null_byte_tests:
            content = b'<?php phpinfo(); ?>'
            
            if self._upload_file(filename, content):
                self.vulnerabilities.append({
                    'type': 'Null Byte Injection',
                    'severity': 'HIGH',
                    'filename': filename,
                    'technique': description,
                    'description': f'{description} vulnerability detected'
                })
                print(f"    [!] HIGH: {description} successful")
    
    def _test_content_type_validation(self):
        """Test if server validates actual file content"""
        print("\n[*] Testing content validation...")
        
        # Malicious content with valid image headers
        fake_images = [
            ('fake.jpg', b'\xFF\xD8\xFF\xE0<?php phpinfo(); ?>', 'image/jpeg', 'JPEG header + PHP'),
            ('fake.png', b'\x89PNG\r\n\x1a\n<?php phpinfo(); ?>', 'image/png', 'PNG header + PHP'),
            ('fake.gif', b'GIF89a<?php phpinfo(); ?>', 'image/gif', 'GIF header + PHP'),
            ('fake.pdf', b'%PDF-1.5<?php phpinfo(); ?>', 'application/pdf', 'PDF header + PHP'),
        ]
        
        for filename, content, mime_type, description in fake_images:
            if self._upload_file(filename, content, mime_type):
                self.vulnerabilities.append({
                    'type': 'Weak Content Validation',
                    'severity': 'MEDIUM',
                    'filename': filename,
                    'mime_type': mime_type,
                    'description': f'{description} - Server only checks file header'
                })
                print(f"    [!] MEDIUM: {description} allowed")
    
    def _test_path_traversal(self):
        """Test path traversal in filename"""
        print("\n[*] Testing path traversal...")
        
        traversal_filenames = [
            ('../test.txt', 'Parent directory'),
            ('..\\test.txt', 'Windows parent directory'),
            ('../../test.txt', 'Two levels up'),
            ('....//test.txt', 'Encoded traversal'),
            ('..;/test.txt', 'Semicolon traversal'),
            ('%2e%2e/test.txt', 'URL encoded'),
            ('%252e%252e/test.txt', 'Double encoded'),
            ('/etc/passwd', 'Absolute path'),
            ('C:\\Windows\\test.txt', 'Windows absolute path'),
        ]
        
        for filename, description in traversal_filenames:
            content = b'test content'
            
            if self._upload_file(filename, content, 'text/plain'):
                self.vulnerabilities.append({
                    'type': 'Path Traversal in Filename',
                    'severity': 'HIGH',
                    'filename': filename,
                    'technique': description,
                    'description': f'{description} - Server accepts path manipulation'
                })
                print(f"    [!] HIGH: {description} allowed")
    
    def _test_polyglot_files(self):
        """Test polyglot files (valid as multiple types)"""
        print("\n[*] Testing polyglot files...")
        
        # GIF + PHP polyglot
        gif_php_polyglot = b'GIF89a;\n<?php phpinfo(); ?>\n//'
        
        if self._upload_file('polyglot.gif', gif_php_polyglot, 'image/gif'):
            self.vulnerabilities.append({
                'type': 'Polyglot File Upload',
                'severity': 'HIGH',
                'filename': 'polyglot.gif',
                'description': 'Server accepts GIF/PHP polyglot file'
            })
            print(f"    [!] HIGH: GIF/PHP polyglot allowed")
    
    def _test_file_size_limits(self):
        """Test file size limitations"""
        print("\n[*] Testing file size limits...")
        
        sizes = [
            (1024, '1 KB'),
            (1024*1024, '1 MB'),
            (10*1024*1024, '10 MB'),
            (100*1024*1024, '100 MB'),
        ]
        
        max_allowed = 0
        for size, description in sizes:
            try:
                content = b'A' * size
                
                if self._upload_file('test.txt', content, 'text/plain', timeout=30):
                    max_allowed = size
                    print(f"    [+] {description} allowed")
                else:
                    break
            except:
                break
        
        if max_allowed > 50*1024*1024:
            self.vulnerabilities.append({
                'type': 'No Proper File Size Limit',
                'severity': 'MEDIUM',
                'max_tested': f"{max_allowed/(1024*1024):.1f} MB",
                'description': 'Server accepts very large files (DoS risk)'
            })
            print(f"    [!] MEDIUM: Files up to {max_allowed/(1024*1024):.1f} MB allowed")
    
    def _upload_file(self, filename, content, mime_type='application/octet-stream', timeout=10):
        """Helper function to upload a file"""
        try:
            files = {self.field_name: (filename, BytesIO(content), mime_type)}
            r = requests.post(self.target_url, files=files, timeout=timeout, verify=False)
            
            # Consider upload successful if:
            # - Status is 200/201
            # - No error messages in response
            # - Response indicates success
            if r.status_code in [200, 201]:
                error_keywords = ['error', 'invalid', 'not allowed', 'forbidden', 'denied']
                if not any(keyword in r.text.lower() for keyword in error_keywords):
                    return True
            
            return False
        except Exception as e:
            return False
    
    def print_report(self):
        print("\n" + "="*70)
        print("FILE UPLOAD SECURITY VALIDATION REPORT")
        print("="*70 + "\n")
        
        if not self.vulnerabilities:
            print("[+] No file upload vulnerabilities found!")
            print("[+] Upload endpoint appears to be properly secured.")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} file upload vulnerabilities:\n")
        
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
                            print(f"      {key}: {value}")
        
        print("\n" + "="*70)
        print("RECOMMENDATIONS")
        print("="*70)
        print("""
1. Validate file extensions against a whitelist
2. Verify actual file content, not just MIME type
3. Store uploaded files outside web root
4. Rename files upon upload (use UUIDs)
5. Implement file size limits
6. Scan files for malware
7. Set proper file permissions
8. Use Content-Security-Policy headers
        """)

def main():
    if len(sys.argv) < 2:
        print("File Upload Security Validator")
        print("=" * 50)
        print("\nUsage: python file_upload_validator.py <upload_endpoint> [field_name]")
        print("\nExamples:")
        print("  python file_upload_validator.py https://example.com/upload")
        print("  python file_upload_validator.py https://example.com/api/files file")
        print("\nDescription:")
        print("  Tests file upload endpoints for common security")
        print("  vulnerabilities including:")
        print("  - Executable file uploads")
        print("  - MIME type bypasses")
        print("  - Path traversal")
        print("  - Content validation weaknesses")
        sys.exit(1)
    
    target = sys.argv[1]
    field_name = sys.argv[2] if len(sys.argv) > 2 else 'file'
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print("\n" + "="*70)
    print("FILE UPLOAD SECURITY VALIDATOR")
    print("="*70 + "\n")
    
    # Disable SSL warnings for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    validator = FileUploadValidator(target, field_name)
    validator.test_uploads()
    validator.print_report()
    
    print("\n" + "="*70)
    print("Scan Complete")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()