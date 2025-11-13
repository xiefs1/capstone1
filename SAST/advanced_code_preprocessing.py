"""
Advanced Code Preprocessing for Security Vulnerability Detection
Handles code normalization, obfuscation detection, and semantic preservation
"""

import re
import ast
import hashlib
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Any, Optional
from collections import Counter
import warnings
warnings.filterwarnings("ignore")

class AdvancedCodePreprocessor:
    """
    Advanced code preprocessor that normalizes code while preserving security semantics
    """
    
    def __init__(self):
        # Common obfuscation patterns
        self.obfuscation_patterns = {
            'hex_encoding': r'\\x[0-9a-fA-F]{2}',
            'unicode_encoding': r'\\u[0-9a-fA-F]{4}',
            'base64_encoding': r'[A-Za-z0-9+/]{4,}={0,2}',
            'rot13': r'[a-zA-Z]{10,}',
            'variable_obfuscation': r'[a-zA-Z_][a-zA-Z0-9_]{10,}',
            'string_concatenation': r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']',
            'eval_obfuscation': r'eval\s*\(\s*["\'][^"\']*["\']',
            'char_code_obfuscation': r'String\.fromCharCode\s*\(',
            'function_obfuscation': r'function\s+[a-zA-Z_][a-zA-Z0-9_]{10,}'
        }
        
        # Security-critical patterns that should NOT be normalized
        self.security_critical_patterns = [
            r'SELECT.*FROM', r'INSERT.*INTO', r'UPDATE.*SET', r'DELETE.*FROM',
            r'<script', r'javascript:', r'onclick=', r'onload=',
            r'exec\s*\(', r'system\s*\(', r'eval\s*\(',
            r'innerHTML', r'outerHTML', r'document\.write',
            r'request\.', r'$_GET', r'$_POST', r'$_COOKIE',
            r'prepareStatement', r'bindParam', r'escape\s*\('
        ]
        
        # Common variable names that should be normalized
        self.common_variables = {
            'user_input': ['input', 'userInput', 'user_input', 'userData', 'data'],
            'query': ['query', 'sql', 'sqlQuery', 'statement'],
            'connection': ['conn', 'connection', 'db', 'database'],
            'result': ['result', 'rs', 'resultSet', 'response'],
            'username': ['username', 'user', 'login', 'name'],
            'password': ['password', 'pass', 'pwd', 'secret']
        }

    def preprocess_code(self, code: str, preserve_security: bool = True) -> Dict[str, Any]:
        """
        Preprocess code with advanced normalization while preserving security semantics
        """
        result = {
            'original_code': code,
            'normalized_code': code,
            'obfuscation_score': 0.0,
            'complexity_score': 0.0,
            'security_patterns_preserved': [],
            'preprocessing_applied': []
        }
        
        # 1. Detect obfuscation
        obfuscation_score = self._detect_obfuscation(code)
        result['obfuscation_score'] = obfuscation_score
        
        # 2. Normalize code
        if preserve_security:
            normalized_code = self._normalize_preserving_security(code)
        else:
            normalized_code = self._normalize_aggressive(code)
        
        result['normalized_code'] = normalized_code
        
        # 3. Calculate complexity
        complexity_score = self._calculate_complexity(normalized_code)
        result['complexity_score'] = complexity_score
        
        # 4. Detect security patterns
        security_patterns = self._detect_security_patterns(normalized_code)
        result['security_patterns_preserved'] = security_patterns
        
        return result

    def _detect_obfuscation(self, code: str) -> float:
        """Detect and score code obfuscation level"""
        obfuscation_indicators = 0
        total_checks = 0
        
        for pattern_name, pattern in self.obfuscation_patterns.items():
            matches = len(re.findall(pattern, code))
            if matches > 0:
                obfuscation_indicators += min(matches, 5)  # Cap at 5 per pattern
            total_checks += 1
        
        # Additional obfuscation checks
        # 1. High ratio of special characters
        special_chars = len(re.findall(r'[^\w\s]', code))
        char_ratio = special_chars / max(len(code), 1)
        if char_ratio > 0.3:
            obfuscation_indicators += 3
        
        # 2. Very long variable names
        long_vars = len(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{15,}', code))
        if long_vars > 0:
            obfuscation_indicators += long_vars
        
        # 3. Excessive string concatenation
        concat_count = len(re.findall(r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']', code))
        if concat_count > 3:
            obfuscation_indicators += concat_count
        
        # 4. Nested function calls
        nested_calls = len(re.findall(r'\w+\s*\([^)]*\w+\s*\([^)]*\)[^)]*\)', code))
        if nested_calls > 2:
            obfuscation_indicators += nested_calls
        
        return min(obfuscation_indicators / max(total_checks + 10, 1), 1.0)

    def _normalize_preserving_security(self, code: str) -> str:
        """Normalize code while preserving security-critical patterns"""
        normalized = code
        
        # 1. Normalize whitespace but preserve structure
        normalized = re.sub(r'\n\s*\n', '\n', normalized)  # Remove empty lines
        normalized = re.sub(r'[ \t]+', ' ', normalized)  # Normalize spaces/tabs
        normalized = re.sub(r'\n[ \t]+', '\n', normalized)  # Remove leading whitespace
        
        # 2. Normalize variable names (but preserve security context)
        normalized = self._normalize_variable_names(normalized)
        
        # 3. Normalize string literals (but preserve SQL/HTML patterns)
        normalized = self._normalize_string_literals(normalized)
        
        # 4. Normalize function calls (but preserve security functions)
        normalized = self._normalize_function_calls(normalized)
        
        # 5. Normalize comments
        normalized = self._normalize_comments(normalized)
        
        return normalized

    def _normalize_aggressive(self, code: str) -> str:
        """Aggressive normalization for general pattern matching"""
        normalized = code
        
        # Remove all comments
        normalized = re.sub(r'//.*$', '', normalized, flags=re.MULTILINE)
        normalized = re.sub(r'/\*.*?\*/', '', normalized, flags=re.DOTALL)
        normalized = re.sub(r'#.*$', '', normalized, flags=re.MULTILINE)
        
        # Normalize all whitespace
        normalized = re.sub(r'\s+', ' ', normalized)
        
        # Normalize quotes
        normalized = re.sub(r'"([^"]*)"', r'"STRING"', normalized)
        normalized = re.sub(r"'([^']*)'", r'"STRING"', normalized)
        
        # Normalize numbers
        normalized = re.sub(r'\b\d+\b', 'NUMBER', normalized)
        
        return normalized.strip()

    def _normalize_variable_names(self, code: str) -> str:
        """Normalize variable names while preserving security context"""
        normalized = code
        
        # Map common variable patterns to standard names
        for standard_name, variants in self.common_variables.items():
            for variant in variants:
                # Only replace if it's a variable assignment or usage
                pattern = r'\b' + re.escape(variant) + r'\b'
                if re.search(pattern, normalized, re.IGNORECASE):
                    # Check if it's in a security context
                    if self._is_security_context(normalized, variant):
                        normalized = re.sub(pattern, standard_name, normalized, flags=re.IGNORECASE)
        
        return normalized

    def _normalize_string_literals(self, code: str) -> str:
        """Normalize string literals while preserving security patterns"""
        normalized = code
        
        # Find all string literals
        string_pattern = r'["\']([^"\']*)["\']'
        strings = re.findall(string_pattern, code)
        
        for string in strings:
            if self._is_security_string(string):
                # Keep security strings as-is
                continue
            else:
                # Normalize non-security strings
                normalized = normalized.replace(f'"{string}"', '"STRING"')
                normalized = normalized.replace(f"'{string}'", '"STRING"')
        
        return normalized

    def _normalize_function_calls(self, code: str) -> str:
        """Normalize function calls while preserving security functions"""
        normalized = code
        
        # List of security functions that should be preserved
        security_functions = [
            'execute', 'executeQuery', 'executeUpdate', 'prepareStatement',
            'innerHTML', 'outerHTML', 'document.write', 'Response.Write',
            'system', 'exec', 'eval', 'shell_exec', 'passthru',
            'escape', 'htmlspecialchars', 'htmlentities', 'strip_tags'
        ]
        
        # Normalize non-security function calls
        func_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        functions = re.findall(func_pattern, code)
        
        for func in functions:
            if func.lower() not in [f.lower() for f in security_functions]:
                # Normalize function name
                normalized = re.sub(r'\b' + re.escape(func) + r'\s*\(', 'FUNCTION(', normalized)
        
        return normalized

    def _normalize_comments(self, code: str) -> str:
        """Normalize comments while preserving security-related comments"""
        normalized = code
        
        # Remove empty comments
        normalized = re.sub(r'//\s*$', '', normalized, flags=re.MULTILINE)
        normalized = re.sub(r'#\s*$', '', normalized, flags=re.MULTILINE)
        
        # Normalize comment content (but preserve security warnings)
        comment_pattern = r'(//|#)\s*(.*)'
        def replace_comment(match):
            prefix = match.group(1)
            content = match.group(2).strip()
            
            if any(keyword in content.lower() for keyword in 
                   ['vulnerable', 'security', 'injection', 'xss', 'sql', 'dangerous']):
                return f"{prefix} {content}"  # Keep security comments
            else:
                return f"{prefix} COMMENT"  # Normalize other comments
        
        normalized = re.sub(comment_pattern, replace_comment, normalized)
        
        return normalized

    def _is_security_context(self, code: str, variable: str) -> bool:
        """Check if a variable is used in a security context"""
        # Look for security patterns around the variable
        security_contexts = [
            r'SELECT.*' + re.escape(variable),
            r'INSERT.*' + re.escape(variable),
            r'UPDATE.*' + re.escape(variable),
            r'DELETE.*' + re.escape(variable),
            r'innerHTML.*' + re.escape(variable),
            r'outerHTML.*' + re.escape(variable),
            r'document\.write.*' + re.escape(variable),
            r'execute.*' + re.escape(variable),
            r'system.*' + re.escape(variable),
            r'exec.*' + re.escape(variable)
        ]
        
        return any(re.search(pattern, code, re.IGNORECASE) for pattern in security_contexts)

    def _is_security_string(self, string: str) -> bool:
        """Check if a string contains security-relevant content"""
        security_keywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
            '<script', 'javascript:', 'onclick', 'onload', 'onerror',
            'exec', 'system', 'eval', 'shell_exec', 'passthru',
            'innerHTML', 'outerHTML', 'document.write', 'Response.Write',
            'request.', '$_GET', '$_POST', '$_COOKIE', '$_REQUEST',
            'prepareStatement', 'bindParam', 'escape', 'htmlspecialchars'
        ]
        
        return any(keyword.lower() in string.lower() for keyword in security_keywords)

    def _calculate_complexity(self, code: str) -> float:
        """Calculate code complexity score"""
        complexity = 0.0
        
        # 1. Cyclomatic complexity (simplified)
        control_structures = len(re.findall(r'\b(if|for|while|switch|case|catch|try)\b', code))
        complexity += control_structures * 0.1
        
        # 2. Nesting depth
        lines = code.split('\n')
        max_depth = 0
        current_depth = 0
        
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith(('//', '#', '/*')):
                if stripped.endswith('{') or stripped.endswith(':'):
                    current_depth += 1
                    max_depth = max(max_depth, current_depth)
                elif stripped.startswith('}') or stripped.startswith('except') or stripped.startswith('finally'):
                    current_depth = max(0, current_depth - 1)
        
        complexity += max_depth * 0.2
        
        # 3. Function call complexity
        function_calls = len(re.findall(r'\w+\s*\(', code))
        complexity += min(function_calls * 0.05, 1.0)
        
        # 4. String manipulation complexity
        string_ops = len(re.findall(r'["\'].*\+.*["\']', code))
        complexity += min(string_ops * 0.1, 0.5)
        
        return min(complexity, 1.0)

    def _detect_security_patterns(self, code: str) -> List[str]:
        """Detect security patterns in the code"""
        patterns = []
        
        for pattern in self.security_critical_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                patterns.append(pattern)
        
        return patterns

    def preprocess_dataset(self, df: pd.DataFrame, 
                          code_column: str = 'code_snippet',
                          preserve_security: bool = True) -> pd.DataFrame:
        """
        Preprocess entire dataset
        """
        print("🔧 Preprocessing dataset with advanced normalization...")
        
        results = []
        for i, code in enumerate(df[code_column]):
            if i % 1000 == 0:
                print(f"Processing {i+1}/{len(df)} samples...")
            
            try:
                result = self.preprocess_code(code, preserve_security)
                results.append(result)
            except Exception as e:
                print(f"Error preprocessing sample {i}: {e}")
                # Add default result for error cases
                results.append({
                    'original_code': code,
                    'normalized_code': code,
                    'obfuscation_score': 0.0,
                    'complexity_score': 0.0,
                    'security_patterns_preserved': [],
                    'preprocessing_applied': ['error']
                })
        
        # Create new dataframe with preprocessing results
        result_df = df.copy()
        result_df['normalized_code'] = [r['normalized_code'] for r in results]
        result_df['obfuscation_score'] = [r['obfuscation_score'] for r in results]
        result_df['complexity_score'] = [r['complexity_score'] for r in results]
        result_df['security_patterns_count'] = [len(r['security_patterns_preserved']) for r in results]
        
        print(f"✅ Preprocessing complete!")
        print(f"📊 Average obfuscation score: {np.mean([r['obfuscation_score'] for r in results]):.3f}")
        print(f"📊 Average complexity score: {np.mean([r['complexity_score'] for r in results]):.3f}")
        
        return result_df


if __name__ == "__main__":
    # Test the preprocessor
    test_code = """
    // This is a vulnerable SQL injection example
    String userInput = request.getParameter("id");
    String query = "SELECT * FROM users WHERE id = '" + userInput + "'";
    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    """
    
    preprocessor = AdvancedCodePreprocessor()
    result = preprocessor.preprocess_code(test_code)
    
    print("Original code:")
    print(result['original_code'])
    print("\nNormalized code:")
    print(result['normalized_code'])
    print(f"\nObfuscation score: {result['obfuscation_score']}")
    print(f"Complexity score: {result['complexity_score']}")
    print(f"Security patterns: {result['security_patterns_preserved']}")
