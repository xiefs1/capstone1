"""
ML-Enhanced SCA (Software Composition Analysis)
Uses machine learning to detect vulnerabilities in dependencies
"""

import os
import sys
import json
import re
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

# ML imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

@dataclass
class MLVulnerability:
    """Represents a vulnerability found by ML-enhanced SCA"""
    package_name: str
    package_version: str
    vulnerability_id: str
    severity: str
    description: str
    confidence: float
    ml_prediction: bool
    traditional_detection: bool
    cve_id: Optional[str]
    cvss_score: Optional[float]
    published_date: Optional[str]
    fixed_version: Optional[str]
    affected_versions: List[str]
    remediation: str
    references: List[str]

class MLEnhancedSCA:
    """
    ML-Enhanced SCA that uses machine learning to detect vulnerabilities
    """
    
    def __init__(self):
        # Initialize traditional SCA detector
        from sca_vulnerability_detector import SCAVulnerabilityDetector
        self.traditional_sca = SCAVulnerabilityDetector()
        
        # ML models
        self.vulnerability_model = None
        self.severity_model = None
        self.is_trained = False
        
        # Feature names for ML
        self.feature_names = [
            'package_name_length', 'version_dots', 'version_digits', 'has_hyphen',
            'has_underscore', 'starts_with_number', 'contains_alpha', 'contains_beta',
            'contains_rc', 'contains_snapshot', 'version_major', 'version_minor',
            'version_patch', 'is_semantic_version', 'package_popularity_score',
            'maintenance_score', 'security_score', 'age_score'
        ]
        
        # Language encoding mapping (moved inside extract_ml_features)
        self.language_encoding = {
            'python': 1, 'java': 2, 'javascript': 3, 'php': 4, 
            'ruby': 5, 'go': 6, 'rust': 7, 'csharp': 8, 'cpp': 9
        }
    
    def extract_ml_features(self, package_name: str, package_version: str, language: str = 'python') -> np.ndarray:
        """Extract ML features from package information"""
        features = []
        
        # Basic package name features
        features.append(len(package_name))
        features.append(package_name.count('.'))
        features.append(len(re.findall(r'\d', package_version)))
        features.append(1 if '-' in package_name else 0)
        features.append(1 if '_' in package_name else 0)
        features.append(1 if package_name[0].isdigit() else 0)
        features.append(1 if any(c.isalpha() for c in package_name) else 0)
        features.append(1 if 'beta' in package_name.lower() else 0)
        features.append(1 if 'rc' in package_name.lower() else 0)
        features.append(1 if 'snapshot' in package_name.lower() else 0)
        
        # Version parsing
        version_parts = re.findall(r'\d+', package_version)
        features.append(int(version_parts[0]) if version_parts else 0)  # major
        features.append(int(version_parts[1]) if len(version_parts) > 1 else 0)  # minor
        features.append(int(version_parts[2]) if len(version_parts) > 2 else 0)  # patch
        features.append(1 if len(version_parts) >= 3 else 0)  # is_semantic_version
        
        # Language encoding (moved inside this method)
        language_code = self.language_encoding.get(language.lower(), 0)
        features.append(language_code)
        
        # Simulated scores (in real implementation, these would come from package registries)
        features.append(np.random.uniform(0.1, 1.0))  # popularity_score
        features.append(np.random.uniform(0.1, 1.0))  # maintenance_score
        features.append(np.random.uniform(0.1, 1.0))  # security_score
        features.append(np.random.uniform(0.1, 1.0))  # age_score
        
        return np.array(features)
    
    def create_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Create training data for ML models"""
        # This would normally come from a real vulnerability database
        # For demo purposes, we'll create synthetic data
        
        training_data = []
        labels = []
        
        # Known vulnerable packages (from traditional SCA database)
        vulnerable_packages = [
            ('django', '1.11.0', 'python', 1),
            ('flask', '0.12.0', 'python', 1),
            ('requests', '2.19.0', 'python', 1),
            ('numpy', '1.15.0', 'python', 1),
            ('spring-boot', '2.0.0', 'java', 1),
            ('jackson-databind', '2.9.0', 'java', 1),
            ('lodash', '4.17.0', 'javascript', 1),
            ('express', '4.16.0', 'javascript', 1),
        ]
        
        # Known safe packages
        safe_packages = [
            ('pandas', '1.0.0', 'python', 0),
            ('matplotlib', '3.0.0', 'python', 0),
            ('scikit-learn', '1.0.0', 'python', 0),
            ('tensorflow', '2.0.0', 'python', 0),
            ('react', '16.8.0', 'javascript', 0),
            ('vue', '2.6.0', 'javascript', 0),
            ('angular', '8.0.0', 'javascript', 0),
            ('jquery', '3.4.0', 'javascript', 0),
        ]
        
        # Generate features for all packages
        for package, version, language, label in vulnerable_packages + safe_packages:
            features = self.extract_ml_features(package, version, language)
            training_data.append(features)
            labels.append(label)
        
        return np.array(training_data), np.array(labels)
    
    def train_models(self):
        """Train ML models for vulnerability detection"""
        print("🤖 Training ML models for vulnerability detection...")
        
        # Create training data
        X, y = self.create_training_data()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train vulnerability detection model
        self.vulnerability_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.vulnerability_model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.vulnerability_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        print(f"📊 Model Performance:")
        print(f"  Accuracy: {accuracy:.3f}")
        print(f"  Precision: {precision:.3f}")
        print(f"  Recall: {recall:.3f}")
        print(f"  F1-Score: {f1:.3f}")
        
        # Print feature importances
        print(f"\n🔍 Top Feature Importances:")
        feature_importance = self.vulnerability_model.feature_importances_
        for i, (feature, importance) in enumerate(zip(self.feature_names, feature_importance)):
            if importance > 0.05:  # Only show important features
                print(f"  {feature}: {importance:.3f}")
        
        self.is_trained = True
        return accuracy, precision, recall, f1
    
    def predict_vulnerability(self, package_name: str, package_version: str, language: str = 'python') -> Dict[str, Any]:
        """Predict if a package is vulnerable using ML"""
        if not self.is_trained:
            raise ValueError("Models not trained yet. Call train_models() first.")
        
        # Extract features
        features = self.extract_ml_features(package_name, package_version, language)
        features = features.reshape(1, -1)
        
        # Get prediction and probability
        prediction = self.vulnerability_model.predict(features)[0]
        probability = self.vulnerability_model.predict_proba(features)[0]
        confidence = max(probability)
        
        # Also check traditional SCA
        traditional_result = self._check_traditional_sca(package_name, package_version, language)
        
        return {
            'package_name': package_name,
            'package_version': package_version,
            'is_vulnerable': bool(prediction),
            'confidence': confidence,
            'ml_prediction': bool(prediction),
            'traditional_detection': traditional_result['is_vulnerable'],
            'severity': traditional_result.get('severity', 'unknown'),
            'cve_id': traditional_result.get('cve_id', None)
        }
    
    def _check_traditional_sca(self, package_name: str, package_version: str, language: str) -> Dict[str, Any]:
        """Check using traditional SCA approach"""
        # This would normally use the traditional SCA detector
        # For demo purposes, we'll simulate the check
        
        # Check against known vulnerable packages
        if language in self.traditional_sca.vulnerable_packages:
            for vuln_package, versions in self.traditional_sca.vulnerable_packages[language].items():
                if vuln_package.lower() in package_name.lower():
                    for vuln_version, vuln_info in versions.items():
                        if package_version == vuln_version:
                            return {
                                'is_vulnerable': True,
                                'severity': vuln_info['severity'],
                                'cve_id': vuln_info['cve']
                            }
        
        return {'is_vulnerable': False, 'severity': 'none', 'cve_id': None}
    
    def scan_project_ml_enhanced(self, project_path: str) -> Dict[str, Any]:
        """Scan project using ML-enhanced approach"""
        print(f"🔍 ML-Enhanced SCA scanning: {project_path}")
        
        # First, get traditional SCA results
        traditional_results = self.traditional_sca.scan_project(project_path)
        
        # Add ML predictions
        ml_predictions = 0
        ml_vulnerabilities = []
        
        for file_result in traditional_results['files_scanned']:
            for dep in file_result['dependencies']:
                package_name = dep['package']
                package_version = dep['version']
                language = file_result['language']
                
                # Get ML prediction
                ml_result = self.predict_vulnerability(package_name, package_version, language)
                
                if ml_result['ml_prediction']:
                    ml_predictions += 1
                    
                    # Create ML vulnerability object
                    ml_vuln = MLVulnerability(
                        package_name=package_name,
                        package_version=package_version,
                        vulnerability_id=f"ML_{hash(package_name + package_version)}",
                        severity=ml_result['severity'],
                        description=f"ML-predicted vulnerability in {package_name}",
                        confidence=ml_result['confidence'],
                        ml_prediction=True,
                        traditional_detection=ml_result['traditional_detection'],
                        cve_id=ml_result['cve_id'],
                        cvss_score=self._get_cvss_score(ml_result['severity']),
                        published_date=datetime.now().isoformat(),
                        fixed_version="latest",
                        affected_versions=[package_version],
                        remediation=f"Update {package_name} to latest version",
                        references=[]
                    )
                    ml_vulnerabilities.append(ml_vuln)
        
        # Combine results
        enhanced_results = traditional_results.copy()
        enhanced_results['ml_predictions'] = ml_predictions
        enhanced_results['ml_vulnerabilities'] = ml_vulnerabilities
        enhanced_results['total_vulnerabilities'] += len(ml_vulnerabilities)
        
        return enhanced_results
    
    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score based on severity"""
        scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0
        }
        return scores.get(severity.lower(), 5.0)
    
    def generate_ml_enhanced_report(self, scan_results: Dict[str, Any]):
        """Generate ML-enhanced report"""
        print("\n" + "="*60)
        print("🤖 ML-ENHANCED SCA REPORT")
        print("="*60)
        print(f"Project: {scan_results['project_path']}")
        print(f"Files scanned: {scan_results['total_files_scanned']}")
        print(f"Total dependencies: {scan_results['total_dependencies']}")
        print(f"Traditional vulnerabilities: {scan_results['total_vulnerabilities'] - scan_results['ml_predictions']}")
        print(f"ML-predicted vulnerabilities: {scan_results['ml_predictions']}")
        print(f"Total vulnerabilities: {scan_results['total_vulnerabilities']}")
        
        if scan_results['ml_vulnerabilities']:
            print(f"\n🤖 ML-Predicted Vulnerabilities:")
            for vuln in scan_results['ml_vulnerabilities']:
                print(f"  📦 {vuln.package_name} ({vuln.package_version}) - {vuln.severity.upper()}")
                print(f"      Confidence: {vuln.confidence:.2%}")
                print(f"      Traditional Detection: {'Yes' if vuln.traditional_detection else 'No'}")
                print(f"      Description: {vuln.description}")
                print()
        
        print("="*60)
    
    def save_models(self, model_path: str = "models/ml_enhanced_sca.joblib"):
        """Save trained models"""
        if not self.is_trained:
            raise ValueError("Models not trained yet")
        
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        model_data = {
            'vulnerability_model': self.vulnerability_model,
            'feature_names': self.feature_names,
            'language_encoding': self.language_encoding
        }
        
        joblib.dump(model_data, model_path)
        print(f"🤖 ML models saved to: {model_path}")
    
    def load_models(self, model_path: str = "models/ml_enhanced_sca.joblib"):
        """Load trained models"""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        model_data = joblib.load(model_path)
        self.vulnerability_model = model_data['vulnerability_model']
        self.feature_names = model_data['feature_names']
        self.language_encoding = model_data['language_encoding']
        self.is_trained = True
        
        print(f"🤖 ML models loaded from: {model_path}")

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ML-Enhanced SCA Scanner')
    parser.add_argument('--project', '-p', required=True, help='Project directory to scan')
    parser.add_argument('--train', action='store_true', help='Train models before scanning')
    
    args = parser.parse_args()
    
    # Initialize ML-enhanced SCA
    ml_sca = MLEnhancedSCA()
    
    # Train models if requested
    if args.train:
        ml_sca.train_models()
        ml_sca.save_models()
    
    # Load existing models
    try:
        ml_sca.load_models()
    except FileNotFoundError:
        print("❌ No trained models found. Please run with --train first.")
        sys.exit(1)
    
    # Scan project
    scan_results = ml_sca.scan_project_ml_enhanced(args.project)
    
    # Generate report
    ml_sca.generate_ml_enhanced_report(scan_results)
    
    # Exit with appropriate code
    if scan_results['total_vulnerabilities'] > 0:
        print(f"\n⚠️  Found {scan_results['total_vulnerabilities']} vulnerabilities!")
        sys.exit(1)
    else:
        print("\n✅ No vulnerabilities found!")
        sys.exit(0)

if __name__ == "__main__":
    main()
