"""
Advanced SAST Feature Engineering for Security Vulnerability Detection
This module implements sophisticated features that help ML models understand
the semantic meaning and security implications of code rather than just patterns.
"""

import re
import ast
import hashlib
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Any
from collections import Counter
import warnings
warnings.filterwarnings("ignore")

class AdvancedSASTFeatureExtractor:
    """
    Advanced feature extractor that understands code semantics and security patterns
    """
    
    def __init__(self):
        # Security patterns organized by vulnerability type
        self.security_patterns = {
            'sql_injection': {
                'sources': [
                    r'request\.(GET|POST|COOKIES|headers)',
                    r'input\s*\(', r'raw_input\s*\(', r'gets\s*\(', r'scanf\s*\(',
                    r'$_GET', r'$_POST', r'$_COOKIE', r'$_REQUEST',
                    r'HttpServletRequest\.getParameter',
                    r'request\.getParameter', r'request\.getHeader'
                ],
                'sinks': [
                    r'execute\s*\(', r'executeQuery\s*\(', r'executeUpdate\s*\(',
                    r'prepareStatement\s*\(', r'createStatement\s*\(',
                    r'query\s*\(', r'raw\s*\(', r'extra\s*\(',
                    r'SELECT.*\+', r'INSERT.*\+', r'UPDATE.*\+', r'DELETE.*\+'
                ],
                'sanitizers': [
                    r'escape\s*\(', r'escapeString\s*\(', r'htmlspecialchars\s*\(',
                    r'prepareStatement\s*\(', r'bindParam\s*\(', r'bindValue\s*\(',
                    r'parameterized', r'prepared'
                ]
            },
            'xss': {
                'sources': [
                    r'request\.(GET|POST|COOKIES|headers)',
                    r'input\s*\(', r'raw_input\s*\(', r'gets\s*\(',
                    r'$_GET', r'$_POST', r'$_COOKIE', r'$_REQUEST',
                    r'HttpServletRequest\.getParameter'
                ],
                'sinks': [
                    r'innerHTML\s*=', r'outerHTML\s*=', r'document\.write\s*\(',
                    r'Response\.Write\s*\(', r'echo\s+', r'print\s+',
                    r'<.*>.*\+', r'innerHTML.*\+', r'outerHTML.*\+'
                ],
                'sanitizers': [
                    r'escape\s*\(', r'htmlspecialchars\s*\(', r'htmlentities\s*\(',
                    r'strip_tags\s*\(', r'htmlspecialchars_decode\s*\(',
                    r'encode\s*\(', r'decode\s*\('
                ]
            },
            'command_injection': {
                'sources': [
                    r'request\.(GET|POST|COOKIES|headers)',
                    r'input\s*\(', r'raw_input\s*\(', r'gets\s*\(',
                    r'$_GET', r'$_POST', r'$_COOKIE', r'$_REQUEST'
                ],
                'sinks': [
                    r'os\.system\s*\(', r'subprocess\.(run|call|Popen)\s*\(',
                    r'exec\s*\(', r'eval\s*\(', r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'Process\.Start\s*\(', r'shell_exec\s*\('
                ],
                'sanitizers': [
                    r'escapeshellarg\s*\(', r'escapeshellcmd\s*\(',
                    r'addslashes\s*\(', r'stripslashes\s*\(',
                    r'whitelist', r'blacklist', r'validate'
                ]
            },
            'path_traversal': {
                'sources': [
                    r'request\.(GET|POST|COOKIES|headers)',
                    r'input\s*\(', r'raw_input\s*\(', r'gets\s*\(',
                    r'$_GET', r'$_POST', r'$_COOKIE', r'$_REQUEST'
                ],
                'sinks': [
                    r'open\s*\(', r'file\s*\(', r'fopen\s*\(',
                    r'File\.Open\s*\(', r'FileStream\s*\(',
                    r'include\s*\(', r'require\s*\(', r'include_once\s*\('
                ],
                'sanitizers': [
                    r'basename\s*\(', r'dirname\s*\(', r'realpath\s*\(',
                    r'Path\.GetFileName', r'Path\.GetDirectoryName',
                    r'canonicalize', r'normalize'
                ]
            }
        }
        
        # Dangerous function patterns
        self.dangerous_functions = [
            'eval', 'exec', 'system', 'shell_exec', 'passthru', 'proc_open',
            'popen', 'exec', 'Runtime.getRuntime().exec', 'Process.Start',
            'innerHTML', 'outerHTML', 'document.write', 'Response.Write'
        ]
        
        # Safe/secure patterns
        self.safe_patterns = [
            'prepared', 'parameterized', 'bindParam', 'bindValue',
            'escape', 'htmlspecialchars', 'htmlentities', 'strip_tags',
            'escapeshellarg', 'escapeshellcmd', 'basename', 'dirname'
        ]

    def extract_semantic_features(self, code_snippet: str) -> Dict[str, Any]:
        """
        Extract semantic features that understand code meaning and structure
        """
        features = {}
        
        # 1. Data Flow Analysis
        features.update(self._analyze_data_flow(code_snippet))
        
        # 2. Control Flow Analysis  
        features.update(self._analyze_control_flow(code_snippet))
        
        # 3. Security Pattern Analysis
        features.update(self._analyze_security_patterns(code_snippet))
        
        # 4. Code Structure Analysis
        features.update(self._analyze_code_structure(code_snippet))
        
        # 5. Vulnerability-Specific Analysis
        features.update(self._analyze_vulnerability_patterns(code_snippet))
        
        # 6. Context Awareness
        features.update(self._analyze_context(code_snippet))
        
        return features

    def _analyze_data_flow(self, code: str) -> Dict[str, Any]:
        """Analyze how data flows through the code"""
        features = {}
        
        # Find variable assignments and usages
        var_assignments = re.findall(r'(\w+)\s*=\s*[^=]', code)
        var_usages = re.findall(r'(\w+)\s*[+\-*/=]', code)
        
        # Count direct concatenations (dangerous)
        direct_concat = len(re.findall(r'["\'].*\+.*\w+.*\+.*["\']', code))
        features['direct_string_concat'] = direct_concat
        
        # Count variable interpolations
        var_interpolation = len(re.findall(r'["\'].*\{.*\}.*["\']', code))
        features['variable_interpolation'] = var_interpolation
        
        # Count function calls with variables
        func_with_vars = len(re.findall(r'\w+\([^)]*\w+[^)]*\)', code))
        features['function_calls_with_variables'] = func_with_vars
        
        # Data flow complexity
        features['data_flow_complexity'] = len(set(var_assignments)) + len(set(var_usages))
        
        return features

    def _analyze_control_flow(self, code: str) -> Dict[str, Any]:
        """Analyze control flow structures"""
        features = {}
        
        # Count conditional statements
        features['if_statements'] = len(re.findall(r'\bif\s*\(', code))
        features['else_statements'] = len(re.findall(r'\belse\b', code))
        features['switch_statements'] = len(re.findall(r'\bswitch\s*\(', code))
        
        # Count loops
        features['for_loops'] = len(re.findall(r'\bfor\s*\(', code))
        features['while_loops'] = len(re.findall(r'\bwhile\s*\(', code))
        
        # Count try-catch blocks
        features['try_blocks'] = len(re.findall(r'\btry\s*\{', code))
        features['catch_blocks'] = len(re.findall(r'\bcatch\s*\(', code))
        
        # Control flow complexity
        features['control_flow_complexity'] = (
            features['if_statements'] + features['for_loops'] + 
            features['while_loops'] + features['try_blocks']
        )
        
        return features

    def _analyze_security_patterns(self, code: str) -> Dict[str, Any]:
        """Analyze security-specific patterns"""
        features = {}
        
        # Count dangerous functions
        dangerous_count = sum(1 for func in self.dangerous_functions 
                            if re.search(r'\b' + re.escape(func) + r'\s*\(', code, re.I))
        features['dangerous_functions'] = dangerous_count
        
        # Count safe patterns
        safe_count = sum(1 for pattern in self.safe_patterns 
                        if re.search(r'\b' + re.escape(pattern) + r'\b', code, re.I))
        features['safe_patterns'] = safe_count
        
        # Security ratio
        total_patterns = dangerous_count + safe_count
        features['security_ratio'] = safe_count / max(total_patterns, 1)
        
        # Count input validation
        validation_patterns = [
            r'is_numeric', r'is_string', r'ctype_', r'filter_var',
            r'preg_match', r'match', r'validate', r'check'
        ]
        validation_count = sum(1 for pattern in validation_patterns 
                              if re.search(pattern, code, re.I))
        features['input_validation'] = validation_count
        
        return features

    def _analyze_code_structure(self, code: str) -> Dict[str, Any]:
        """Analyze code structure and complexity"""
        features = {}
        
        # Basic metrics
        features['code_length'] = len(code)
        features['line_count'] = len(code.split('\n'))
        features['char_density'] = len(code.replace(' ', '').replace('\n', '')) / max(len(code), 1)
        
        # Indentation analysis (indicates nesting)
        lines = code.split('\n')
        indentations = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        features['max_indentation'] = max(indentations) if indentations else 0
        features['avg_indentation'] = np.mean(indentations) if indentations else 0
        
        # Comment ratio
        comment_lines = len([line for line in lines if line.strip().startswith(('#', '//', '/*'))])
        features['comment_ratio'] = comment_lines / max(len(lines), 1)
        
        # String literal analysis
        string_literals = re.findall(r'["\']([^"\']*)["\']', code)
        features['string_literal_count'] = len(string_literals)
        features['avg_string_length'] = np.mean([len(s) for s in string_literals]) if string_literals else 0
        
        return features

    def _analyze_vulnerability_patterns(self, code: str) -> Dict[str, Any]:
        """Analyze specific vulnerability patterns"""
        features = {}
        
        for vuln_type, patterns in self.security_patterns.items():
            # Count sources
            source_count = sum(1 for pattern in patterns['sources'] 
                             if re.search(pattern, code, re.I))
            features[f'{vuln_type}_sources'] = source_count
            
            # Count sinks
            sink_count = sum(1 for pattern in patterns['sinks'] 
                           if re.search(pattern, code, re.I))
            features[f'{vuln_type}_sinks'] = sink_count
            
            # Count sanitizers
            sanitizer_count = sum(1 for pattern in patterns['sanitizers'] 
                                if re.search(pattern, code, re.I))
            features[f'{vuln_type}_sanitizers'] = sanitizer_count
            
            # Vulnerability risk score
            if source_count > 0 and sink_count > 0:
                risk_score = sink_count / (source_count + sanitizer_count + 1)
                features[f'{vuln_type}_risk_score'] = risk_score
            else:
                features[f'{vuln_type}_risk_score'] = 0.0
        
        return features

    def _analyze_context(self, code: str) -> Dict[str, Any]:
        """Analyze contextual information"""
        features = {}
        
        # Language detection
        java_indicators = ['import java', 'public class', 'System.out', 'String']
        python_indicators = ['import ', 'def ', 'print(', 'if __name__']
        php_indicators = ['<?php', '$_', 'echo ', 'function ']
        csharp_indicators = ['using System', 'public class', 'Console.WriteLine']
        
        features['is_java'] = sum(1 for indicator in java_indicators if indicator in code)
        features['is_python'] = sum(1 for indicator in python_indicators if indicator in code)
        features['is_php'] = sum(1 for indicator in php_indicators if indicator in code)
        features['is_csharp'] = sum(1 for indicator in csharp_indicators if indicator in code)
        
        # Framework detection
        frameworks = {
            'spring': ['@Controller', '@Service', '@Repository', 'Spring'],
            'django': ['from django', 'models.Model', 'views.py'],
            'rails': ['class ApplicationController', 'def index'],
            'express': ['app.get', 'app.post', 'express()'],
            'laravel': ['Route::', 'Eloquent', 'Artisan']
        }
        
        for framework, indicators in frameworks.items():
            features[f'uses_{framework}'] = sum(1 for indicator in indicators 
                                              if indicator in code)
        
        # Database interaction patterns
        db_patterns = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP']
        features['database_operations'] = sum(1 for pattern in db_patterns 
                                            if re.search(r'\b' + pattern + r'\b', code, re.I))
        
        return features

    def extract_all_features(self, code_snippets: List[str]) -> pd.DataFrame:
        """
        Extract all features for a list of code snippets
        """
        all_features = []
        
        for i, code in enumerate(code_snippets):
            if i % 1000 == 0:
                print(f"Processing snippet {i+1}/{len(code_snippets)}")
            
            try:
                features = self.extract_semantic_features(code)
                all_features.append(features)
            except Exception as e:
                print(f"Error processing snippet {i}: {e}")
                # Add default features for failed cases
                all_features.append(self._get_default_features())
        
        return pd.DataFrame(all_features)

    def _get_default_features(self) -> Dict[str, Any]:
        """Return default features for error cases"""
        return {
            'direct_string_concat': 0,
            'variable_interpolation': 0,
            'function_calls_with_variables': 0,
            'data_flow_complexity': 0,
            'if_statements': 0,
            'else_statements': 0,
            'switch_statements': 0,
            'for_loops': 0,
            'while_loops': 0,
            'try_blocks': 0,
            'catch_blocks': 0,
            'control_flow_complexity': 0,
            'dangerous_functions': 0,
            'safe_patterns': 0,
            'security_ratio': 0.0,
            'input_validation': 0,
            'code_length': 0,
            'line_count': 0,
            'char_density': 0.0,
            'max_indentation': 0,
            'avg_indentation': 0.0,
            'comment_ratio': 0.0,
            'string_literal_count': 0,
            'avg_string_length': 0.0
        }


def create_advanced_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create advanced features for the dataset
    """
    print("🔧 Creating advanced semantic features...")
    
    extractor = AdvancedSASTFeatureExtractor()
    
    # Extract features
    features_df = extractor.extract_all_features(df['code_snippet'].tolist())
    
    # Combine with original data
    result_df = pd.concat([df.reset_index(drop=True), features_df.reset_index(drop=True)], axis=1)
    
    print(f"✅ Created {len(features_df.columns)} advanced features")
    print(f"📊 Feature columns: {list(features_df.columns)}")
    
    return result_df


if __name__ == "__main__":
    # Test the feature extractor
    test_code = """
    import java.sql.*;
    
    public class VulnerableExample {
        public void getUserData(String userId) {
            String query = "SELECT * FROM users WHERE id = '" + userId + "'";
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
        }
    }
    """
    
    extractor = AdvancedSASTFeatureExtractor()
    features = extractor.extract_semantic_features(test_code)
    
    print("Test features extracted:")
    for key, value in features.items():
        print(f"  {key}: {value}")
