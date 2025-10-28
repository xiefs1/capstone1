#!/usr/bin/env python3
"""
SCA Model Test Script
Tests the SCA model against vulnerable package versions
"""

import json
import subprocess
import sys
import os
from datetime import datetime

def create_vulnerable_package_list():
    """Create a list of packages with known vulnerabilities"""
    
    vulnerable_packages = {
        "django": {
            "version": "1.11.29",
            "vulnerabilities": [
                {
                    "cve": "CVE-2019-6975",
                    "severity": "HIGH",
                    "cvss": 8.1,
                    "description": "SQL injection vulnerability in Django admin interface"
                },
                {
                    "cve": "CVE-2018-14574",
                    "severity": "MEDIUM", 
                    "cvss": 6.1,
                    "description": "Cross-site scripting vulnerability in Django admin"
                }
            ]
        },
        "flask": {
            "version": "1.1.1",
            "vulnerabilities": [
                {
                    "cve": "CVE-2018-1000656",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "description": "Server-side template injection vulnerability"
                }
            ]
        },
        "requests": {
            "version": "2.19.0",
            "vulnerabilities": [
                {
                    "cve": "CVE-2018-18074",
                    "severity": "HIGH",
                    "cvss": 7.4,
                    "description": "Certificate verification bypass vulnerability"
                }
            ]
        },
        "urllib3": {
            "version": "1.24.1",
            "vulnerabilities": [
                {
                    "cve": "CVE-2019-11324",
                    "severity": "MEDIUM",
                    "cvss": 5.3,
                    "description": "Certificate verification bypass"
                }
            ]
        },
        "pyyaml": {
            "version": "3.13",
            "vulnerabilities": [
                {
                    "cve": "CVE-2017-18342",
                    "severity": "HIGH",
                    "cvss": 8.5,
                    "description": "Arbitrary code execution vulnerability"
                }
            ]
        },
        "jinja2": {
            "version": "2.10.1",
            "vulnerabilities": [
                {
                    "cve": "CVE-2019-10906",
                    "severity": "MEDIUM",
                    "cvss": 6.1,
                    "description": "Server-side template injection vulnerability"
                }
            ]
        },
        "werkzeug": {
            "version": "0.16.1",
            "vulnerabilities": [
                {
                    "cve": "CVE-2019-14806",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "description": "Path traversal vulnerability"
                }
            ]
        },
        "numpy": {
            "version": "1.16.6",
            "vulnerabilities": [
                {
                    "cve": "CVE-2019-6446",
                    "severity": "MEDIUM",
                    "cvss": 5.3,
                    "description": "Buffer overflow vulnerability"
                }
            ]
        },
        "pandas": {
            "version": "0.24.2",
            "vulnerabilities": [
                {
                    "cve": "CVE-2019-16729",
                    "severity": "MEDIUM",
                    "cvss": 5.3,
                    "description": "Denial of service vulnerability"
                }
            ]
        },
        "scikit-learn": {
            "version": "0.20.4",
            "vulnerabilities": [
                {
                    "cve": "CVE-2019-10192",
                    "severity": "LOW",
                    "cvss": 3.7,
                    "description": "Information disclosure vulnerability"
                }
            ]
        }
    }
    
    return vulnerable_packages

def create_test_environment():
    """Create a test environment with vulnerable packages"""
    
    # Create test directory
    test_dir = "sca_test_environment"
    os.makedirs(test_dir, exist_ok=True)
    
    # Create requirements.txt with vulnerable versions
    requirements_content = """Flask==1.1.1
Django==1.11.29
requests==2.19.0
urllib3==1.24.1
PyYAML==3.13
Jinja2==2.10.1
Werkzeug==0.16.1
MarkupSafe==1.1.1
numpy==1.16.6
pandas==0.24.2
scikit-learn==0.20.4
matplotlib==3.1.1
seaborn==0.9.0
plotly==4.1.1
dash==1.0.2
dash-core-components==1.0.0
dash-html-components==1.0.0
dash-table==4.0.0
dash-renderer==1.0.0
dash-bootstrap-components==0.7.2
dash-daq==0.1.0
dash-cytoscape==0.1.0
dash-sunburst==0.0.1
dash-canvas==0.1.0
dash-bio==0.1.0
dash-ag-grid==0.1.0
dash-mantine-components==0.1.0
dash-extensions==0.0.1
dash-iconify==0.1.0
dash-leaflet==0.1.0
dash-plotly-editor==0.1.0
dash-slicer==0.1.0
dash-snapshots==0.1.0
dash-testing==0.1.0
dash-uploader==0.1.0"""
    
    with open(f"{test_dir}/requirements.txt", "w") as f:
        f.write(requirements_content)
    
    # Create vulnerable package data
    vulnerable_data = create_vulnerable_package_list()
    
    with open(f"{test_dir}/vulnerable_packages.json", "w") as f:
        json.dump(vulnerable_data, f, indent=2)
    
    # Create a simple Python file that uses these packages
    test_code = '''#!/usr/bin/env python3
"""
Test application using vulnerable packages
"""

import flask
import django
import requests
import urllib3
import yaml
import jinja2
import werkzeug
import numpy
import pandas
import sklearn
import matplotlib
import seaborn
import plotly
import dash

def main():
    print("Testing vulnerable packages...")
    
    # Test Flask
    app = flask.Flask(__name__)
    
    # Test requests
    response = requests.get("https://httpbin.org/get")
    
    # Test numpy
    arr = numpy.array([1, 2, 3, 4, 5])
    
    # Test pandas
    df = pandas.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
    
    print("All packages loaded successfully!")

if __name__ == "__main__":
    main()
'''
    
    with open(f"{test_dir}/test_app.py", "w") as f:
        f.write(test_code)
    
    print(f"Test environment created in: {test_dir}")
    return test_dir

def test_sca_model():
    """Test the SCA model against vulnerable packages"""
    
    # Create test environment
    test_dir = create_test_environment()
    
    # Load vulnerable package data
    with open(f"{test_dir}/vulnerable_packages.json", "r") as f:
        vulnerable_packages = json.load(f)
    
    return vulnerable_packages

def generate_sca_report():
    """Generate a comprehensive SCA report"""
    
    vulnerable_packages = create_vulnerable_package_list()
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_packages": len(vulnerable_packages),
        "vulnerable_packages": 0,
        "total_vulnerabilities": 0,
        "severity_counts": {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        },
        "packages": []
    }
    
    for package, data in vulnerable_packages.items():
        package_info = {
            "name": package,
            "version": data["version"],
            "vulnerabilities": data["vulnerabilities"],
            "vulnerability_count": len(data["vulnerabilities"])
        }
        
        report["packages"].append(package_info)
        report["vulnerable_packages"] += 1
        report["total_vulnerabilities"] += len(data["vulnerabilities"])
        
        for vuln in data["vulnerabilities"]:
            report["severity_counts"][vuln["severity"]] += 1
    
    # Save report
    with open("sca_vulnerability_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    return report

def main():
    """Main function"""
    while True:
        print("Choose an option:")
        print("1. Test SCA model with vulnerable packages")
        print("2. Generate SCA vulnerability report")
        print("3. Create test environment")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            test_sca_model()
        elif choice == "2":
            generate_sca_report()
        elif choice == "3":
            create_test_environment()
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please enter 1-4.")

if __name__ == "__main__":
    main()
