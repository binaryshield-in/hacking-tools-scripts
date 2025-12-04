#!/usr/bin/env python3
"""
GraphQL Weakness Mapping Utility
Maps and tests GraphQL endpoints for security vulnerabilities

Installation:
    pip install requests

Usage:
    python graphql_mapper.py <graphql_endpoint>
    
Example:
    python graphql_mapper.py https://api.example.com/graphql
    python graphql_mapper.py https://example.com/api --auth "Bearer token123"
    
Description:
    Tests GraphQL endpoints for:
    - Introspection enabled/disabled
    - Query depth/complexity limits
    - Batch query vulnerabilities
    - Field suggestion attacks
    - Rate limiting
    - Information disclosure
"""

import requests
import sys
import json
import time
from collections import defaultdict

class GraphQLMapper:
    def __init__(self, endpoint_url, auth_header=None):
        self.endpoint_url = endpoint_url
        self.auth_header = auth_header
        self.vulnerabilities = []
        self.schema = None
        self.queries = []
        self.mutations = []
        self.types = []
        
    def map_all(self):
        print(f"[*] Mapping GraphQL Endpoint: {self.endpoint_url}\n")
        
        self._test_introspection()
        self._test_query_depth()
        self._test_batch_queries()
        self._test_field_suggestions()
        self._test_directives()
        self._test_query_complexity()
        self._test_rate_limiting()
        self._test_error_messages()
        self._test_dos_vectors()
        self._test_authentication()
        
        return self.vulnerabilities
    
    def _send_query(self, query, variables=None):
        """Send GraphQL query"""
        headers = {'Content-Type': 'application/json'}
        if self.auth_header:
            headers['Authorization'] = self.auth_header
        
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        try:
            r = requests.post(self.endpoint_url, json=payload, headers=headers, timeout=10)
            return r.json() if r.status_code == 200 else {'errors': [{'message': f'HTTP {r.status_code}'}]}
        except Exception as e:
            return {'errors': [{'message': str(e)}]}
    
    def _test_introspection(self):
        """Test if introspection is enabled"""
        print("[*] Testing introspection...")
        
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    name
                    kind
                    description
                    fields {
                        name
                        description
                        args {
                            name
                            description
                            type { name kind ofType { name kind } }
                        }
                        type { name kind ofType { name kind } }
                    }
                }
            }
        }
        """
        
        result = self._send_query(introspection_query)
        
        if 'data' in result and '__schema' in result.get('data', {}):
            self.schema = result['data']['__schema']
            
            # Extract information
            types = self.schema.get('types', [])
            self.types = [t for t in types if not t['name'].startswith('__')]
            
            print(f"    [!] HIGH: Introspection is ENABLED")
            print(f"    [*] Found {len(self.types)} types")
            
            # Identify queries and mutations
            query_type = self.schema.get('queryType', {}).get('name')
            mutation_type = self.schema.get('mutationType', {}).get('name')
            
            for t in types:
                if t['name'] == query_type:
                    self.queries = [f['name'] for f in t.get('fields', [])]
                    print(f"    [*] Found {len(self.queries)} queries")
                elif t['name'] == mutation_type:
                    self.mutations = [f['name'] for f in t.get('fields', [])]
                    print(f"    [*] Found {len(self.mutations)} mutations")
            
            self.vulnerabilities.append({
                'type': 'Introspection Enabled',
                'severity': 'HIGH',
                'description': 'GraphQL introspection is enabled in production',
                'impact': 'Attacker can discover entire API schema',
                'queries_found': len(self.queries),
                'mutations_found': len(self.mutations),
                'types_found': len(self.types),
                'recommendation': 'Disable introspection in production environments'
            })
            
            # Check for sensitive field names
            self._analyze_schema_for_sensitive_fields()
            
        else:
            print(f"    [+] Introspection is DISABLED")
            # Try alternative introspection
            self._test_partial_introspection()
        
        print()
    
    def _analyze_schema_for_sensitive_fields(self):
        """Analyze schema for sensitive field names"""
        print("[*] Analyzing schema for sensitive fields...")
        
        sensitive_keywords = [
            'password', 'token', 'secret', 'api_key', 'apikey',
            'credit_card', 'ssn', 'private', 'internal', 'admin',
            'debug', 'test', 'dev'
        ]
        
        sensitive_fields = []
        
        for t in self.types:
            for field in t.get('fields', []) or []:
                field_name = field['name'].lower()
                for keyword in sensitive_keywords:
                    if keyword in field_name:
                        sensitive_fields.append({
                            'type': t['name'],
                            'field': field['name'],
                            'keyword': keyword
                        })
                        print(f"    [!] Sensitive field: {t['name']}.{field['name']}")
        
        if sensitive_fields:
            self.vulnerabilities.append({
                'type': 'Sensitive Field Exposure',
                'severity': 'MEDIUM',
                'description': 'Schema exposes sensitive field names',
                'sensitive_fields': sensitive_fields[:10],
                'total_found': len(sensitive_fields),
                'impact': 'Field names reveal sensitive data structures'
            })
    
    def _test_partial_introspection(self):
        """Test for partial introspection queries"""
        print("[*] Testing partial introspection...")
        
        partial_queries = [
            "{ __schema { types { name } } }",
            "{ __type(name: \"Query\") { name fields { name } } }",
            "{ __type(name: \"Mutation\") { name fields { name } } }",
        ]
        
        for query in partial_queries:
            result = self._send_query(query)
            if 'data' in result:
                self.vulnerabilities.append({
                    'type': 'Partial Introspection',
                    'severity': 'MEDIUM',
                    'description': 'Partial introspection queries work',
                    'query': query,
                    'impact': 'Some schema information still accessible'
                })
                print(f"    [!] MEDIUM: Partial introspection works")
                return
    
    def _test_query_depth(self):
        """Test query depth limits"""
        print("[*] Testing query depth limits...")
        
        # Build deeply nested query
        depths = [5, 10, 20, 50]
        
        for depth in depths:
            nested_query = self._build_nested_query(depth)
            start_time = time.time()
            result = self._send_query(nested_query)
            elapsed = time.time() - start_time
            
            if 'errors' in result:
                error_msg = result['errors'][0].get('message', '').lower()
                if 'depth' in error_msg or 'complex' in error_msg:
                    print(f"    [+] Query depth limit at ~{depth} (blocked)")
                    return
            elif 'data' in result:
                print(f"    [!] Depth {depth} allowed (took {elapsed:.2f}s)")
                if depth >= 20:
                    self.vulnerabilities.append({
                        'type': 'No Query Depth Limit',
                        'severity': 'HIGH',
                        'description': f'Queries with depth {depth}+ are allowed',
                        'max_tested_depth': depth,
                        'impact': 'Deep nested queries can cause DoS',
                        'recommendation': 'Implement query depth limiting (max 10-15)'
                    })
        print()
    
    def _build_nested_query(self, depth):
        """Build a deeply nested query"""
        if not self.queries:
            # Generic nested query
            query = "{ "
            for i in range(depth):
                query += "__schema { "
            query += "queryType { name }"
            query += " }" * depth
            query += " }"
            return query
        
        # Use actual schema if available
        query_name = self.queries[0] if self.queries else "__schema"
        query = f"{{ {query_name} {{"
        for i in range(depth - 1):
            query += "__typename "
        query += "} }"
        return query
    
    def _test_batch_queries(self):
        """Test batch query vulnerabilities"""
        print("[*] Testing batch query support...")
        
        # Test batching multiple queries
        batch_sizes = [5, 10, 50, 100]
        
        for size in batch_sizes:
            queries = []
            for i in range(size):
                queries.append({
                    'query': '{ __typename }'
                })
            
            headers = {'Content-Type': 'application/json'}
            if self.auth_header:
                headers['Authorization'] = self.auth_header
            
            try:
                start_time = time.time()
                r = requests.post(self.endpoint_url, json=queries, headers=headers, timeout=30)
                elapsed = time.time() - start_time
                
                if r.status_code == 200:
                    print(f"    [!] Batch of {size} queries accepted (took {elapsed:.2f}s)")
                    
                    if size >= 50:
                        self.vulnerabilities.append({
                            'type': 'Batch Query DoS',
                            'severity': 'HIGH',
                            'description': f'Server accepts batch queries of {size}+',
                            'max_tested_batch': size,
                            'impact': 'Attacker can amplify requests for DoS',
                            'recommendation': 'Limit batch query size to 5-10'
                        })
                else:
                    print(f"    [+] Batch size {size} blocked")
                    break
            except:
                print(f"    [+] Batch queries appear limited")
                break
        print()
    
    def _test_field_suggestions(self):
        """Test field suggestion attacks"""
        print("[*] Testing field suggestions...")
        
        # Query with typo to trigger suggestions
        typo_query = "{ userr { id } }"
        result = self._send_query(typo_query)
        
        if 'errors' in result:
            error_msg = str(result['errors'][0].get('message', ''))
            
            # Check if error reveals field names
            if 'did you mean' in error_msg.lower() or 'similar' in error_msg.lower():
                print(f"    [!] MEDIUM: Field suggestions enabled")
                print(f"        Error: {error_msg[:100]}")
                
                self.vulnerabilities.append({
                    'type': 'Field Suggestion Information Disclosure',
                    'severity': 'MEDIUM',
                    'description': 'Error messages suggest valid field names',
                    'example_error': error_msg[:200],
                    'impact': 'Helps attacker discover valid fields without introspection',
                    'recommendation': 'Disable field suggestions in production'
                })
            else:
                print(f"    [+] No field suggestions in errors")
        print()
    
    def _test_directives(self):
        """Test GraphQL directives"""
        print("[*] Testing directives...")
        
        # Test @skip and @include
        directive_query = """
        {
            __typename @skip(if: true)
            __schema @include(if: false) { queryType { name } }
        }
        """
        
        result = self._send_query(directive_query)
        if 'data' in result:
            print(f"    [+] Directives (@skip, @include) supported")
        
        # Test custom directives
        if self.schema:
            directives = self.schema.get('directives', [])
            if directives:
                print(f"    [*] Found {len(directives)} directives")
        print()
    
    def _test_query_complexity(self):
        """Test query complexity limits"""
        print("[*] Testing query complexity...")
        
        # Build complex query with many fields
        complex_query = "{ __schema { "
        for i in range(100):
            complex_query += f"queryType {{ name }} "
        complex_query += "} }"
        
        result = self._send_query(complex_query)
        
        if 'errors' in result:
            error_msg = result['errors'][0].get('message', '').lower()
            if 'complex' in error_msg or 'limit' in error_msg:
                print(f"    [+] Query complexity limiting detected")
            else:
                print(f"    [~] Query rejected (reason unclear)")
        elif 'data' in result:
            self.vulnerabilities.append({
                'type': 'No Complexity Limiting',
                'severity': 'MEDIUM',
                'description': 'Complex queries with 100+ fields accepted',
                'impact': 'Resource-intensive queries possible',
                'recommendation': 'Implement query complexity analysis'
            })
            print(f"    [!] MEDIUM: No complexity limiting detected")
        print()
    
    def _test_rate_limiting(self):
        """Test rate limiting on GraphQL endpoint"""
        print("[*] Testing rate limiting...")
        
        query = "{ __typename }"
        status_codes = []
        
        for i in range(50):
            result = self._send_query(query)
            if 'errors' in result:
                error_msg = result['errors'][0].get('message', '').lower()
                if 'rate' in error_msg or 'limit' in error_msg or 'too many' in error_msg:
                    print(f"    [+] Rate limiting triggered at request {i+1}")
                    return
            time.sleep(0.05)
        
        self.vulnerabilities.append({
            'type': 'No Rate Limiting',
            'severity': 'MEDIUM',
            'description': 'No rate limiting detected on GraphQL endpoint',
            'requests_tested': 50,
            'impact': 'Endpoint vulnerable to abuse',
            'recommendation': 'Implement rate limiting'
        })
        print(f"    [!] MEDIUM: No rate limiting detected (50 requests)")
        print()
    
    def _test_error_messages(self):
        """Test error message verbosity"""
        print("[*] Testing error message verbosity...")
        
        # Send invalid query
        invalid_query = "{ invalid_field_12345 { id } }"
        result = self._send_query(invalid_query)
        
        if 'errors' in result:
            error = result['errors'][0]
            error_msg = error.get('message', '')
            
            verbose_indicators = [
                'stack', 'trace', 'line', 'column', 'path',
                'internal', 'exception', 'debug'
            ]
            
            error_str = str(error).lower()
            found_verbose = [ind for ind in verbose_indicators if ind in error_str]
            
            if found_verbose:
                self.vulnerabilities.append({
                    'type': 'Verbose Error Messages',
                    'severity': 'LOW',
                    'description': 'Error messages contain detailed information',
                    'verbose_elements': found_verbose,
                    'example_error': str(error)[:200],
                    'impact': 'Internal details exposed in errors',
                    'recommendation': 'Use generic error messages in production'
                })
                print(f"    [!] LOW: Verbose errors detected: {', '.join(found_verbose)}")
            else:
                print(f"    [+] Error messages appear minimal")
        print()
    
    def _test_dos_vectors(self):
        """Test potential DoS vectors"""
        print("[*] Testing DoS vectors...")
        
        # Circular reference query
        if self.queries:
            circular_query = f"""
            {{
                {self.queries[0]} {{
                    __typename
                }}
            }}
            """ * 50
            
            start_time = time.time()
            result = self._send_query(circular_query)
            elapsed = time.time() - start_time
            
            if elapsed > 5:
                self.vulnerabilities.append({
                    'type': 'Slow Query DoS',
                    'severity': 'MEDIUM',
                    'description': f'Query took {elapsed:.2f} seconds',
                    'impact': 'Slow queries can cause resource exhaustion',
                    'recommendation': 'Implement query timeouts'
                })
                print(f"    [!] MEDIUM: Slow query detected ({elapsed:.2f}s)")
            else:
                print(f"    [+] Query performance acceptable")
        print()
    
    def _test_authentication(self):
        """Test authentication handling"""
        print("[*] Testing authentication...")
        
        # Try query without auth
        headers = {'Content-Type': 'application/json'}
        query = "{ __typename }"
        
        try:
            r = requests.post(self.endpoint_url, json={'query': query}, headers=headers, timeout=10)
            
            if r.status_code == 200:
                result = r.json()
                if 'data' in result:
                    self.vulnerabilities.append({
                        'type': 'No Authentication Required',
                        'severity': 'HIGH',
                        'description': 'GraphQL endpoint accessible without authentication',
                        'impact': 'Anyone can query the API',
                        'recommendation': 'Require authentication for all queries'
                    })
                    print(f"    [!] HIGH: No authentication required")
                else:
                    print(f"    [+] Authentication appears required")
            elif r.status_code == 401:
                print(f"    [+] Authentication required (401)")
            else:
                print(f"    [~] Unexpected response: {r.status_code}")
        except:
            print(f"    [!] Error testing authentication")
        print()
    
    def print_report(self):
        print("\n" + "="*70)
        print("GRAPHQL WEAKNESS MAPPING REPORT")
        print("="*70 + "\n")
        
        if not self.vulnerabilities:
            print("[+] No GraphQL vulnerabilities detected!")
            print("[+] Endpoint appears well-configured.")
            return
        
        print(f"[!] Found {len(self.vulnerabilities)} GraphQL security issues:\n")
        
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
                                if len(value) <= 5:
                                    print(f"      {key}:")
                                    for item in value:
                                        if isinstance(item, dict):
                                            for k, v in item.items():
                                                print(f"        {k}: {v}")
                                        else:
                                            print(f"        - {item}")
                                else:
                                    print(f"      {key}: {len(value)} items (showing first 5)")
                                    for item in value[:5]:
                                        if isinstance(item, dict):
                                            print(f"        {dict(list(item.items())[:2])}")
                                        else:
                                            print(f"        - {item}")
                            else:
                                print(f"      {key}: {value}")
        
        print("\n" + "="*70)
        print("GRAPHQL SECURITY BEST PRACTICES")
        print("="*70)
        print("""
1. Disable Introspection in Production:
   - Prevents attackers from discovering schema
   - Use environment variables to control

2. Implement Query Limits:
   - Query depth: Maximum 10-15 levels
   - Query complexity: Assign costs to fields
   - Batch queries: Limit to 5-10 per request

3. Rate Limiting:
   - Per IP: 100 requests/minute
   - Per user: 1000 requests/hour
   - Consider query cost in limits

4. Authentication & Authorization:
   - Require authentication for all queries
   - Field-level authorization checks
   - Use DataLoader for N+1 prevention

5. Error Handling:
   - Generic error messages in production
   - No stack traces or internal details
   - Log detailed errors server-side

6. Query Timeouts:
   - Set maximum execution time (5-10 seconds)
   - Cancel long-running queries

7. Disable Field Suggestions:
   - Don't suggest similar field names
   - Prevents schema enumeration

8. Input Validation:
   - Validate all user inputs
   - Sanitize string inputs
   - Use allowlists for enum values

9. Monitoring:
   - Log all queries
   - Alert on suspicious patterns
   - Track query performance

10. Security Headers:
    - Implement CORS properly
    - Use Content-Security-Policy
    - Set X-Content-Type-Options
        """)

def main():
    if len(sys.argv) < 2:
        print("GraphQL Weakness Mapping Utility")
        print("=" * 50)
        print("\nUsage: python graphql_mapper.py <graphql_endpoint> [--auth <token>]")
        print("\nExamples:")
        print("  python graphql_mapper.py https://api.example.com/graphql")
        print("  python graphql_mapper.py https://example.com/api --auth 'Bearer token123'")
        print("\nDescription:")
        print("  Maps and tests GraphQL endpoints for security issues:")
        print("  - Introspection enabled/disabled")
        print("  - Query depth and complexity limits")
        print("  - Batch query vulnerabilities")
        print("  - Field suggestion attacks")
        print("  - Rate limiting")
        print("  - Information disclosure")
        sys.exit(1)
    
    endpoint = sys.argv[1]
    auth_header = None
    
    # Parse auth header
    if '--auth' in sys.argv:
        auth_index = sys.argv.index('--auth')
        if len(sys.argv) > auth_index + 1:
            auth_header = sys.argv[auth_index + 1]
    
    if not endpoint.startswith(('http://', 'https://')):
        endpoint = 'https://' + endpoint
    
    print("\n" + "="*70)
    print("GRAPHQL WEAKNESS MAPPING UTILITY")
    print("="*70 + "\n")
    
    mapper = GraphQLMapper(endpoint, auth_header)
    mapper.map_all()
    mapper.print_report()
    
    print("\n" + "="*70)
    print("Mapping Complete")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()