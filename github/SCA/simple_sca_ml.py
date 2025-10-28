"""
Simple ML-Enhanced SCA
A simplified version of ML-enhanced SCA with basic features
"""

import os
import sys
import json
import re
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

# ML imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib

class SimpleMLSCA:
    """
    Simple ML-enhanced SCA with basic features
    """
    
    def __init__(self):
        self.model = None
        self.is_trained = False
        
        # Simple feature names
        self.feature_names = [
            'package_name_length', 'version_dots', 'version_digits', 'has_hyphen',
            'has_underscore', 'starts_with_number', 'contains_alpha', 'contains_beta',
            'contains_rc', 'contains_snapshot', 'version_major', 'version_minor',
            'version_patch', 'is_semantic_version', 'language_encoding'
        ]
        
        # Language encoding
        self.language_encoding = {
            'python': 1, 'java': 2, 'javascript': 3, 'php': 4, 
            'ruby': 5, 'go': 6, 'rust': 7, 'csharp': 8, 'cpp': 9
        }
    
    def extract_simple_features(self, package_name: str, package_version: str, language: str = 'python') -> np.ndarray:
        """Extract simple ML features from package information"""
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
        
        # Language encoding
        language_code = self.language_encoding.get(language.lower(), 0)
        features.append(language_code)
        
        return np.array(features)
    
    def create_simple_training_data(self) -> tuple:
        """Create simple training data"""
        training_data = []
        labels = []
        
        # Known vulnerable packages
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
            features = self.extract_simple_features(package, version, language)
            training_data.append(features)
            labels.append(label)
        
        return np.array(training_data), np.array(labels)
    
    def train_simple_model(self):
        """Train simple ML model"""
        print("🤖 Training simple ML model...")
        
        # Create training data
        X, y = self.create_simple_training_data()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=8,
            random_state=42
        )
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        print(f"📊 Simple Model Performance:")
        print(f"  Accuracy: {accuracy:.3f}")
        print(f"  Precision: {precision:.3f}")
        print(f"  Recall: {recall:.3f}")
        print(f"  F1-Score: {f1:.3f}")
        
        # Print feature importances
        print(f"\n🔍 Top Feature Importances:")
        feature_importance = self.model.feature_importances_
        for i, (feature, importance) in enumerate(zip(self.feature_names, feature_importance)):
            if importance > 0.05:  # Only show important features
                print(f"  {feature}: {importance:.3f}")
        
        self.is_trained = True
        return accuracy, precision, recall, f1
    
    def predict_vulnerability(self, package_name: str, package_version: str, language: str = 'python') -> Dict[str, Any]:
        """Predict if a package is vulnerable using simple ML"""
        if not self.is_trained:
            raise ValueError("Model not trained yet. Call train_simple_model() first.")
        
        # Extract features
        features = self.extract_simple_features(package_name, package_version, language)
        features = features.reshape(1, -1)
        
        # Get prediction and probability
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0]
        confidence = max(probability)
        
        return {
            'package_name': package_name,
            'package_version': package_version,
            'is_vulnerable': bool(prediction),
            'confidence': confidence,
            'language': language
        }
    
    def scan_project_simple(self, project_path: str) -> Dict[str, Any]:
        """Scan project using simple ML approach"""
        print(f"🔍 Simple ML SCA scanning: {project_path}")
        
        scan_results = {
            'project_path': project_path,
            'total_files_scanned': 0,
            'total_dependencies': 0,
            'total_vulnerabilities': 0,
            'ml_predictions': 0,
            'vulnerabilities': [],
            'files_scanned': []
        }
        
        # Find package files
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.pytest_cache', 'venv', 'env']]
            
            for file in files:
                if file.endswith(('.txt', '.json', '.xml', '.gradle', '.mod')):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, project_path)
                    
                    # Detect language
                    language = self._detect_language(file)
                    if language:
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            dependencies = self._parse_dependencies(file, content, language)
                            
                            if dependencies:
                                file_vulnerabilities = []
                                for dep in dependencies:
                                    ml_result = self.predict_vulnerability(
                                        dep['package'], dep['version'], language
                                    )
                                    
                                    if ml_result['is_vulnerable']:
                                        scan_results['ml_predictions'] += 1
                                        scan_results['total_vulnerabilities'] += 1
                                        
                                        vulnerability = {
                                            'package_name': dep['package'],
                                            'package_version': dep['version'],
                                            'confidence': ml_result['confidence'],
                                            'language': language,
                                            'file': relative_path
                                        }
                                        file_vulnerabilities.append(vulnerability)
                                        scan_results['vulnerabilities'].append(vulnerability)
                                
                                file_result = {
                                    'file': relative_path,
                                    'language': language,
                                    'dependencies': dependencies,
                                    'vulnerabilities': file_vulnerabilities,
                                    'vulnerability_count': len(file_vulnerabilities)
                                }
                                
                                scan_results['files_scanned'].append(file_result)
                                scan_results['total_files_scanned'] += 1
                                scan_results['total_dependencies'] += len(dependencies)
                        
                        except Exception as e:
                            print(f"  ❌ Error scanning {relative_path}: {e}")
        
        return scan_results
    
    def _detect_language(self, filename: str) -> Optional[str]:
        """Detect programming language from filename"""
        if filename.endswith(('requirements.txt', 'setup.py', 'Pipfile')):
            return 'python'
        elif filename.endswith(('package.json', 'yarn.lock')):
            return 'javascript'
        elif filename.endswith(('pom.xml', 'build.gradle')):
            return 'java'
        elif filename.endswith(('composer.json', 'composer.lock')):
            return 'php'
        return None
    
    def _parse_dependencies(self, filename: str, content: str, language: str) -> List[Dict[str, str]]:
        """Parse dependencies from file content"""
        dependencies = []
        
        if language == 'python' and filename.endswith('.txt'):
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    if '==' in line:
                        package, version = line.split('==', 1)
                        dependencies.append({'package': package.strip(), 'version': version.strip()})
        
        elif language == 'javascript' and filename.endswith('.json'):
            try:
                data = json.loads(content)
                deps = data.get('dependencies', {})
                for package, version in deps.items():
                    dependencies.append({'package': package, 'version': version})
            except:
                pass
        
        return dependencies
    
    def export_scan_results(self, scan_results: Dict[str, Any], output_format: str = 'json') -> str:
        """Export scan results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if output_format.lower() == 'json':
            output_file = f"sca_scan_results_{timestamp}.json"
            with open(output_file, 'w') as f:
                json.dump(scan_results, f, indent=2, default=str)
        
        elif output_format.lower() == 'csv':
            output_file = f"sca_scan_results_{timestamp}.csv"
            # Convert to DataFrame and save
            df_data = []
            for vuln in scan_results['vulnerabilities']:
                df_data.append({
                    'package_name': vuln['package_name'],
                    'package_version': vuln['package_version'],
                    'confidence': vuln['confidence'],
                    'language': vuln['language'],
                    'file': vuln['file']
                })
            
            if df_data:
                df = pd.DataFrame(df_data)
                df.to_csv(output_file, index=False)
            else:
                # Create empty CSV with headers
                df = pd.DataFrame(columns=['package_name', 'package_version', 'confidence', 'language', 'file'])
                df.to_csv(output_file, index=False)
        
        print(f"📊 Scan results exported to: {output_file}")
        return output_file
    
    def save_model(self, model_path: str = "models/simple_ml_sca.joblib"):
        """Save trained model"""
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names,
            'language_encoding': self.language_encoding
        }
        
        joblib.dump(model_data, model_path)
        print(f"🤖 Simple ML model saved to: {model_path}")
    
    def load_model(self, model_path: str = "models/simple_ml_sca.joblib"):
        """Load trained model"""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        self.language_encoding = model_data['language_encoding']
        self.is_trained = True
        
        print(f"🤖 Simple ML model loaded from: {model_path}")

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Simple ML-Enhanced SCA Scanner')
    parser.add_argument('--project', '-p', required=True, help='Project directory to scan')
    parser.add_argument('--train', action='store_true', help='Train model before scanning')
    parser.add_argument('--export', choices=['json', 'csv'], default='json', help='Export format')
    
    args = parser.parse_args()
    
    # Initialize simple ML SCA
    ml_sca = SimpleMLSCA()
    
    # Train model if requested
    if args.train:
        ml_sca.train_simple_model()
        ml_sca.save_model()
    
    # Load existing model
    try:
        ml_sca.load_model()
    except FileNotFoundError:
        print("❌ No trained model found. Please run with --train first.")
        sys.exit(1)
    
    # Scan project
    scan_results = ml_sca.scan_project_simple(args.project)
    
    # Export results
    output_file = ml_sca.export_scan_results(scan_results, args.export)
    
    # Print summary
    print(f"\n📊 Scan Summary:")
    print(f"  Files scanned: {scan_results['total_files_scanned']}")
    print(f"  Dependencies: {scan_results['total_dependencies']}")
    print(f"  Vulnerabilities: {scan_results['total_vulnerabilities']}")
    print(f"  Results exported to: {output_file}")
    
    # Exit with appropriate code
    if scan_results['total_vulnerabilities'] > 0:
        print(f"\n⚠️  Found {scan_results['total_vulnerabilities']} vulnerabilities!")
        sys.exit(1)
    else:
        print("\n✅ No vulnerabilities found!")
        sys.exit(0)

if __name__ == "__main__":
    main()
