#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced SAST Analyzer
Analyzes code with:
- Model A: Binary vulnerability detection
- Model B: Vulnerability type classification
- Line number and context extraction
- Enhanced remediation for each vulnerability type
"""

import os
import sys
import re
import ast
import logging
import joblib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

# Import custom modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vulnerability_remediation import VulnerabilityRemediator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding with full context"""
    is_vulnerable: bool
    vulnerability_type: Optional[str]
    confidence: float
    severity: str
    line_number: int
    vulnerable_line: str
    context_before: str
    context_after: str
    code_snippet: str
    remediation: Optional[Any]
    description: str

def extract_line_number_and_context(code_snippet: str, vulnerable_pattern: str = None) -> Dict[str, Any]:
    """
    Extract line number and context from code snippet
    
    Args:
        code_snippet: Full code snippet
        vulnerable_pattern: Pattern to search for (optional)
    
    Returns:
        Dict with line_number, vulnerable_line, context_before, context_after
    """
    lines = code_snippet.split('\n')
    line_number = None
    vulnerable_line_text = None
    context_before = []
    context_after = []
    
    # Try to find the vulnerable line using pattern
    if vulnerable_pattern:
        for idx, line in enumerate(lines):
            if re.search(vulnerable_pattern, line, re.IGNORECASE):
                line_number = idx + 1  # 1-indexed
                vulnerable_line_text = line.strip()
                context_before = lines[max(0, idx-3):idx]
                context_after = lines[idx+1:min(len(lines), idx+4)]
                break
    
    # If no pattern or pattern not found, use suspicious patterns
    if line_number is None:
        suspicious_patterns = [
            r'SELECT.*\+',  # SQL Injection
            r'execute.*\+',
            r'document\.write',  # XSS
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'os\.system\s*\(',  # Command Injection
            r'subprocess\.(run|call|Popen)',
            r'eval\s*\(',  # Code Injection
            r'open\s*\([^)]*\+',  # Path Traversal
            r'file\s*\([^)]*\+',
            r'fopen\s*\([^)]*\+',
        ]
        
        for idx, line in enumerate(lines):
            for pattern in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    line_number = idx + 1
                    vulnerable_line_text = line.strip()
                    context_before = lines[max(0, idx-3):idx]
                    context_after = lines[idx+1:min(len(lines), idx+4)]
                    break
            if line_number:
                break
    
    # Default to first line if nothing found
    if line_number is None:
        line_number = 1
        vulnerable_line_text = lines[0].strip() if lines else ""
        context_after = lines[1:min(len(lines), 4)] if len(lines) > 1 else []
    
    return {
        'line_number': line_number,
        'vulnerable_line': vulnerable_line_text,
        'context_before': '\n'.join(context_before),
        'context_after': '\n'.join(context_after),
        'full_context': '\n'.join(context_before + [vulnerable_line_text] + context_after)
    }

class EnhancedSASTAnalyzer:
    """
    Enhanced SAST Analyzer with binary and multi-class classification
    """
    
    def __init__(self, model_path: str = "models/enhanced_sast_models.joblib"):
        """Initialize the analyzer with trained models"""
        self.model_path = model_path
        self.model_A = None  # Binary classifier
        self.model_B = None  # Multi-class classifier
        self.label_encoder_B = None
        self.feature_extractor = None
        self.remediator = None
        self.is_loaded = False
        
        self.load_models()
    
    def load_models(self):
        """Load trained models"""
        try:
            if not os.path.exists(self.model_path):
                logger.error(f"Model file not found: {self.model_path}")
                return
            
            bundle = joblib.load(self.model_path)
            
            self.model_A = bundle['model_A']
            self.model_B = bundle['model_B']
            self.label_encoder_B = bundle['label_encoder_B']
            self.feature_extractor = bundle['feature_extractor']
            self.remediator = bundle.get('remediator', VulnerabilityRemediator())
            self.is_loaded = True
            
            logger.info(f"✅ Models loaded successfully from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            raise
    
    def analyze_code(self, code_snippet: str, file_path: str = None) -> VulnerabilityFinding:
        """
        Analyze a code snippet and return detailed vulnerability finding
        
        Args:
            code_snippet: Code to analyze
            file_path: Optional file path for context
        
        Returns:
            VulnerabilityFinding with detailed information
        """
        if not self.is_loaded:
            raise ValueError("Models not loaded. Call load_models() first.")
        
        # Extract features
        features = self.feature_extractor.extract_all_features([code_snippet])
        features = features.fillna(0)
        
        # Model A: Binary prediction
        pred_A = self.model_A.predict(features)[0]
        proba_A = self.model_A.predict_proba(features)[0]
        confidence_A = max(proba_A)
        
        # Initialize finding
        finding = VulnerabilityFinding(
            is_vulnerable=bool(pred_A),
            vulnerability_type=None,
            confidence=confidence_A,
            severity="Low",
            line_number=1,
            vulnerable_line="",
            context_before="",
            context_after="",
            code_snippet=code_snippet,
            remediation=None,
            description=""
        )
        
        # If vulnerable, get type from Model B
        if pred_A == 1:
            # Model B: Type classification
            pred_B_encoded = self.model_B.predict(features)[0]
            proba_B = self.model_B.predict_proba(features)[0]
            confidence_B = max(proba_B)
            
            # Decode type
            vuln_type = self.label_encoder_B.inverse_transform([pred_B_encoded])[0]
            finding.vulnerability_type = vuln_type
            finding.confidence = confidence_B
            
            # Determine severity
            if confidence_B > 0.85:
                finding.severity = "Critical"
            elif confidence_B > 0.7:
                finding.severity = "High"
            elif confidence_B > 0.5:
                finding.severity = "Medium"
            else:
                finding.severity = "Low"
            
            # Extract line number and context
            context_info = extract_line_number_and_context(code_snippet)
            finding.line_number = context_info['line_number']
            finding.vulnerable_line = context_info['vulnerable_line']
            finding.context_before = context_info['context_before']
            finding.context_after = context_info['context_after']
            
            # Generate remediation
            if self.remediator:
                try:
                    # Map vulnerability type to remediation format
                    remediation_type_map = {
                        'SQL Injection': 'sql_injection',
                        'XSS': 'xss',
                        'Cross-Site Scripting (XSS)': 'xss',
                        'Cross-Site Scripting': 'xss',
                        'Command Injection': 'command_injection',
                        'Path Traversal': 'path_traversal',
                        'Insecure Deserialization': 'insecure_deserialization',
                    }
                    
                    remediation_type = remediation_type_map.get(vuln_type, 'generic')
                    remediation = self.remediator.generate_remediation(code_snippet, remediation_type)
                    finding.remediation = remediation
                    
                    if remediation:
                        finding.description = remediation.description
                except Exception as e:
                    logger.warning(f"Failed to generate remediation: {e}")
            
            # Generate description if not set
            if not finding.description:
                finding.description = f"Potential {vuln_type} vulnerability detected with {confidence_B:.1%} confidence."
        
        return finding
    
    def analyze_file(self, file_path: str) -> List[VulnerabilityFinding]:
        """
        Analyze a source code file
        
        Args:
            file_path: Path to source code file
        
        Returns:
            List of VulnerabilityFinding objects
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return []
        
        # Split file into functions or code blocks for analysis
        # For now, analyze the entire file as one snippet
        finding = self.analyze_code(content, file_path)
        
        # Add file path to finding
        finding.code_snippet = f"File: {file_path}\n\n{content}"
        
        return [finding] if finding.is_vulnerable else []
    
    def generate_report(self, finding: VulnerabilityFinding) -> str:
        """Generate a comprehensive report for a finding"""
        report = []
        report.append("=" * 80)
        report.append("VULNERABILITY FINDING")
        report.append("=" * 80)
        report.append(f"\nStatus: {'VULNERABLE' if finding.is_vulnerable else 'SAFE'}")
        
        if finding.is_vulnerable:
            report.append(f"\nVulnerability Type: {finding.vulnerability_type}")
            report.append(f"Severity: {finding.severity}")
            report.append(f"Confidence: {finding.confidence:.1%}")
            report.append(f"\nLocation:")
            report.append(f"  Line Number: {finding.line_number}")
            report.append(f"\nVulnerable Line:")
            report.append(f"  {finding.line_number}: {finding.vulnerable_line}")
            
            if finding.context_before:
                before_lines = finding.context_before.split('\n')
                before_count = len(before_lines)
                start_line = finding.line_number - before_count
                report.append(f"\nContext Before (Lines {start_line} - {finding.line_number - 1}):")
                for idx, line in enumerate(before_lines):
                    report.append(f"  {start_line + idx}: {line}")
            
            if finding.context_after:
                after_lines = finding.context_after.split('\n')
                after_count = len(after_lines)
                report.append(f"\nContext After (Lines {finding.line_number + 1} - {finding.line_number + after_count}):")
                for idx, line in enumerate(after_lines):
                    report.append(f"  {finding.line_number + 1 + idx}: {line}")
            
            report.append(f"\nDescription:")
            report.append(f"  {finding.description}")
            
            if finding.remediation:
                remediation = finding.remediation
                report.append(f"\n" + "=" * 80)
                report.append("REMEDIATION")
                report.append("=" * 80)
                report.append(f"\nVulnerable Code:")
                report.append(f"{remediation.vulnerable_code}")
                report.append(f"\nFixed Code:")
                report.append(f"{remediation.fixed_code}")
                report.append(f"\nExplanation:")
                report.append(f"{remediation.explanation}")
                report.append(f"\nBest Practices:")
                for i, practice in enumerate(remediation.best_practices, 1):
                    report.append(f"  {i}. {practice}")
                report.append(f"\nAdditional Resources:")
                for resource in remediation.additional_resources:
                    report.append(f"  - {resource}")
        
        report.append("\n" + "=" * 80)
        return "\n".join(report)
    
    def analyze_multiple(self, code_snippets: List[str]) -> List[VulnerabilityFinding]:
        """Analyze multiple code snippets"""
        findings = []
        for code in code_snippets:
            finding = self.analyze_code(code)
            if finding.is_vulnerable:
                findings.append(finding)
        return findings

def main():
    """Example usage"""
    # Load models
    analyzer = EnhancedSASTAnalyzer()
    
    # Test cases
    test_cases = [
        "SELECT * FROM users WHERE id = '" + "user_input" + "'",  # SQL Injection
        "document.write('<script>alert(1)</script>')",  # XSS
        "os.system('rm -rf /')",  # Command Injection
        "open('/etc/passwd')",  # Path Traversal
        "SELECT * FROM users WHERE id = ?",  # Safe SQL
    ]
    
    print("Testing Enhanced SAST Analyzer")
    print("=" * 80)
    
    for i, code in enumerate(test_cases, 1):
        print(f"\n\nTest Case {i}")
        print("-" * 80)
        finding = analyzer.analyze_code(code)
        report = analyzer.generate_report(finding)
        print(report)

if __name__ == "__main__":
    main()

