import os
import sys
import json
import re
from bs4 import BeautifulSoup

# Ensure local module import
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from SAST.enhanced_sast_analyzer import EnhancedSASTAnalyzer


PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))

# Prefer recommended github model path first (as per docs), then fallback to root
PREFERRED_PATH = os.path.join(PROJECT_ROOT, "github", "SAST", "models", "enhanced_sast_models.joblib")
FALLBACK_PATH = os.path.join(PROJECT_ROOT, "models", "enhanced_sast_models.joblib")
MODEL_PATH = os.getenv("MODEL_PATH")

if not MODEL_PATH:
    MODEL_PATH = PREFERRED_PATH if os.path.exists(PREFERRED_PATH) else FALLBACK_PATH
HTML_FILE_PATH = os.path.join(PROJECT_ROOT, "github", "vulnerable_test_cases.html")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)
REPORT_PATH = os.path.join(OUTPUT_DIR, "sast_enhanced_report.json")


# CWE mapping for vulnerability types
CWE_MAPPING = {
    "SQL Injection": ("CWE-89", "SQL Injection"),
    "sql_injection": ("CWE-89", "SQL Injection"),
    "XSS": ("CWE-79", "Cross-Site Scripting (XSS)"),
    "Cross-Site Scripting (XSS)": ("CWE-79", "Cross-Site Scripting (XSS)"),
    "Cross-Site Scripting": ("CWE-79", "Cross-Site Scripting (XSS)"),
    "xss": ("CWE-79", "Cross-Site Scripting (XSS)"),
    "Command Injection": ("CWE-78", "Command Injection"),
    "command_injection": ("CWE-78", "Command Injection"),
    "Path Traversal": ("CWE-22", "Path Traversal"),
    "path_traversal": ("CWE-22", "Path Traversal"),
    "Insecure Deserialization": ("CWE-502", "Insecure Deserialization"),
    "insecure_deserialization": ("CWE-502", "Insecure Deserialization"),
    "Buffer Overflow": ("CWE-120", "Buffer Overflow"),
    "buffer_overflow": ("CWE-120", "Buffer Overflow"),
    "mixed": ("CWE-79", "Cross-Site Scripting (XSS)"),  # Default to XSS for mixed
    "neutral": ("CWE-20", "Improper Input Validation"),  # Default for neutral
}


def get_cwe_info(vuln_type):
    """Get CWE ID and name for vulnerability type"""
    if not vuln_type:
        return ("CWE-20", "Improper Input Validation")
    return CWE_MAPPING.get(vuln_type, ("CWE-20", "Improper Input Validation"))


def generate_rule_id(vuln_type, line_number, counter):
    """Generate unique rule ID"""
    if vuln_type:
        vuln_short = re.sub(r'[^a-zA-Z0-9]', '', vuln_type.lower())[:10]
        return f"{vuln_short}-{line_number:03d}-{counter:03d}"
    return f"vuln-{line_number:03d}-{counter:03d}"


def get_issue_description(vuln_type, cwe_id, code_snippet):
    """Generate specific issue description based on vulnerability type"""
    issue_map = {
        "CWE-89": f"The code directly concatenates user input into a SQL query string without sanitization or parameterization. The vulnerable code '{code_snippet[:100]}' allows an attacker to inject malicious SQL code that can manipulate the query logic, potentially bypassing authentication or accessing unauthorized data.",
        "CWE-79": f"The code renders user-controlled input without proper encoding or sanitization. The vulnerable code '{code_snippet[:100]}' allows an attacker to inject malicious scripts that execute in the context of other users' browsers, leading to session hijacking or data theft.",
        "CWE-78": f"The code executes system commands using user-controlled input without proper validation. The vulnerable code '{code_snippet[:100]}' allows an attacker to inject arbitrary commands that execute with the application's privileges, potentially leading to complete system compromise.",
        "CWE-22": f"The code constructs file paths using user-controlled input without proper validation. The vulnerable code '{code_snippet[:100]}' allows an attacker to traverse outside the intended directory using '../' sequences, potentially accessing sensitive system files or application source code.",
        "CWE-502": f"The code deserializes untrusted data without proper validation or sanitization. The vulnerable code '{code_snippet[:100]}' allows an attacker to execute arbitrary code during the deserialization process, potentially leading to remote code execution.",
        "CWE-120": f"The code writes data to a buffer without proper bounds checking. The vulnerable code '{code_snippet[:100]}' allows an attacker to write beyond the buffer boundaries, potentially leading to memory corruption and arbitrary code execution.",
        "CWE-20": f"The code processes user input without proper validation or sanitization. The vulnerable code '{code_snippet[:100]}' allows an attacker to provide malicious input that bypasses validation checks, potentially leading to injection attacks or other security issues.",
    }
    return issue_map.get(cwe_id, f"Potential security vulnerability detected in the code. The vulnerable code '{code_snippet[:100]}' may allow an attacker to compromise the application's security.")


def get_impact_description(vuln_type, cwe_id):
    """Generate impact description based on vulnerability type"""
    impact_map = {
        "CWE-89": "An attacker can execute arbitrary SQL commands, potentially leading to: (1) Authentication bypass by injecting ' OR '1'='1' -- or similar payloads, (2) Unauthorized data access or exfiltration of sensitive information, (3) Database schema manipulation and data modification, (4) Complete database compromise including deletion of tables, (5) Potential privilege escalation if the database user has elevated permissions.",
        "CWE-79": "An attacker can inject malicious scripts into web pages viewed by other users, potentially leading to: (1) Session hijacking and account takeover by stealing authentication cookies, (2) Theft of sensitive data including passwords, tokens, and personal information, (3) Defacement of web pages or redirection to malicious sites, (4) Installation of malware or keyloggers on user systems, (5) Phishing attacks by creating fake login forms that steal credentials.",
        "CWE-78": "An attacker can execute arbitrary system commands on the server, potentially leading to: (1) Complete system compromise with full administrative access, (2) Unauthorized file access, modification, or deletion, (3) Data exfiltration from the server or connected systems, (4) Installation of backdoors for persistent access, (5) Lateral movement within the network to compromise other systems.",
        "CWE-22": "An attacker can access files and directories outside the intended directory, potentially leading to: (1) Reading sensitive system files such as /etc/passwd, /etc/shadow, or configuration files, (2) Accessing application source code revealing business logic and potential vulnerabilities, (3) Reading or modifying user data and personal information, (4) Bypassing access controls to view unauthorized content, (5) System information disclosure that aids in further attacks.",
        "CWE-502": "An attacker can execute arbitrary code during deserialization, potentially leading to: (1) Remote code execution with the application's privileges, (2) Complete application compromise and data access, (3) Unauthorized access to system resources and files, (4) System-level attacks including privilege escalation, (5) Denial of service through resource exhaustion or crashes.",
        "CWE-120": "An attacker can write beyond buffer boundaries, potentially leading to: (1) Memory corruption that can crash the application, (2) Arbitrary code execution by overwriting function pointers or return addresses, (3) Application crash resulting in denial of service, (4) Information disclosure through memory dumps, (5) System compromise if the application runs with elevated privileges.",
        "CWE-20": "An attacker can provide malicious input that bypasses validation, potentially leading to: (1) Injection attacks (SQL, command, LDAP, etc.) by providing specially crafted input, (2) Data corruption through malformed input that breaks parsing logic, (3) Application errors that reveal sensitive information, (4) Unauthorized access by bypassing authentication or authorization checks, (5) System compromise through chained vulnerabilities.",
    }
    return impact_map.get(cwe_id, "An attacker can exploit this vulnerability to compromise the application's security, potentially leading to unauthorized access, data theft, or system compromise.")


def get_remediation_for_vulnerability(vuln_type, cwe_id, code_snippet):
    """Generate specific remediation code and explanation based on vulnerability type"""
    remediation_map = {
        "CWE-89": {
            "fixed_code": "# Use parameterized queries (prepared statements)\nquery = \"SELECT * FROM users WHERE username = %s AND password = %s\"\ncursor.execute(query, (username, password))\n\n# OR using ORM (e.g., SQLAlchemy)\n# user = session.query(User).filter(User.username == username, User.password == password).first()",
            "explanation": "Using parameterized queries (prepared statements) ensures that user input is treated as data, not executable code. The database driver handles proper escaping and type checking, preventing SQL injection attacks regardless of the input content. This is the most effective defense against SQL injection.",
            "best_practices": [
                "Always use parameterized queries or prepared statements instead of string concatenation",
                "Use ORM frameworks (SQLAlchemy, Django ORM, Hibernate) that handle SQL injection prevention automatically",
                "Validate and sanitize all user input before processing",
                "Implement principle of least privilege for database accounts",
                "Regularly audit code for dynamic SQL construction patterns",
                "Use stored procedures with parameterized inputs when appropriate"
            ]
        },
        "CWE-79": {
            "fixed_code": "# HTML encode user input before rendering\nfrom html import escape\nsafe_output = escape(user_input)\n\n# OR use framework-specific escaping\n# Django: {{ user_input|escape }}\n# Flask: {{ user_input|e }}\n# React: Use JSX which auto-escapes\n\n# For JavaScript:\n# const safeOutput = document.createTextNode(userInput);\n# element.appendChild(safeOutput);",
            "explanation": "HTML encoding converts special characters to their HTML entity equivalents (e.g., < becomes &lt;), preventing browsers from interpreting user input as executable code. Always encode user input based on the output context (HTML, JavaScript, CSS, URL).",
            "best_practices": [
                "Always HTML-encode user input before rendering in HTML context",
                "Use Content Security Policy (CSP) headers to restrict script execution",
                "Validate and sanitize input on both client and server side",
                "Use framework-provided templating engines that auto-escape by default",
                "Avoid using innerHTML, outerHTML, or document.write() with user input",
                "Implement output encoding based on context (HTML, JavaScript, CSS, URL)"
            ]
        },
        "CWE-78": {
            "fixed_code": "# Use subprocess with explicit command and arguments (no shell)\nimport subprocess\nresult = subprocess.run(['ls', '-la'], capture_output=True, text=True)\n\n# OR use shlex.quote for shell commands when necessary\nimport shlex\nsafe_command = shlex.quote(user_input)\n\n# Avoid: os.system(user_input)\n# Avoid: subprocess.call(user_input, shell=True)",
            "explanation": "Using subprocess.run() with a list of arguments (instead of a shell command string) prevents command injection because the shell is bypassed. Each argument is treated as a separate parameter, preventing injection of additional commands through operators like ;, &&, or |.",
            "best_practices": [
                "Never use os.system() or shell=True with user-controlled input",
                "Use subprocess.run() with explicit command and arguments as a list",
                "Validate and whitelist allowed commands and arguments",
                "Use shlex.quote() if shell execution is absolutely necessary",
                "Implement least privilege principle - run commands with minimal permissions",
                "Log all command executions for security auditing"
            ]
        },
        "CWE-22": {
            "fixed_code": "# Use os.path.join() and validate path\nimport os\nfrom pathlib import Path\n\n# Normalize and validate path\nbase_dir = '/safe/directory'\nuser_path = os.path.normpath(user_input)\nfull_path = os.path.join(base_dir, user_path)\n\n# Ensure path stays within base directory\nif not os.path.abspath(full_path).startswith(os.path.abspath(base_dir)):\n    raise ValueError('Path traversal detected')\n\n# OR use pathlib\nbase = Path('/safe/directory')\nuser_file = Path(user_input)\nfull_path = base / user_file\nif not full_path.resolve().is_relative_to(base.resolve()):\n    raise ValueError('Path traversal detected')",
            "explanation": "Path traversal attacks are prevented by normalizing paths and ensuring they stay within the intended directory. Using os.path.join() and validating that the resolved path starts with the base directory prevents '../' sequences from escaping the allowed directory.",
            "best_practices": [
                "Always validate and sanitize file paths from user input",
                "Use os.path.join() or pathlib.Path for safe path construction",
                "Validate that resolved paths stay within the intended directory",
                "Maintain a whitelist of allowed files or directories",
                "Use chroot jails or containerization to limit file system access",
                "Implement proper access controls and file permissions"
            ]
        },
        "CWE-502": {
            "fixed_code": "# Use safe deserialization libraries\nimport json\n# Safe JSON deserialization\nsafe_data = json.loads(user_input)\n\n# OR use libraries with validation\n# Python: Use json instead of pickle\n# Java: Use Jackson or Gson with type validation\n# .NET: Use System.Text.Json instead of BinaryFormatter\n\n# Avoid: pickle.loads(user_input)\n# Avoid: yaml.load(user_input)  # Use yaml.safe_load() instead",
            "explanation": "Insecure deserialization is prevented by using safe serialization formats (JSON, XML with validation) and avoiding formats that can execute code (pickle, BinaryFormatter). Always validate deserialized data and use libraries that don't allow arbitrary code execution.",
            "best_practices": [
                "Never deserialize untrusted data from unauthenticated sources",
                "Use safe serialization formats (JSON, XML with validation) instead of binary formats",
                "Implement input validation and type checking for deserialized objects",
                "Use signed or encrypted serialization when handling sensitive data",
                "Maintain a whitelist of allowed classes/types for deserialization",
                "Monitor and log deserialization operations for suspicious activity"
            ]
        },
        "CWE-120": {
            "fixed_code": "# Use safe string functions with bounds checking\n# Python: Use string slicing with length checks\nsafe_copy = user_input[:max_length] if len(user_input) <= max_length else user_input[:max_length]\n\n# C/C++: Use strncpy with proper null termination\n# char dest[256];\n# strncpy(dest, src, sizeof(dest) - 1);\n# dest[sizeof(dest) - 1] = '\\0';\n\n# OR use safe libraries\nfrom ctypes import create_string_buffer\nbuffer = create_string_buffer(256)\nbuffer.value = user_input[:255].encode()",
            "explanation": "Buffer overflow vulnerabilities are prevented by always checking buffer bounds before writing data. Use safe string functions that include bounds checking, or manually validate that input length doesn't exceed buffer size before copying.",
            "best_practices": [
                "Always validate input length before copying to buffers",
                "Use safe string functions (strncpy, strncat) with proper bounds checking",
                "Enable compiler security flags (stack canaries, ASLR, DEP)",
                "Use memory-safe languages (Python, Java, C#) when possible",
                "Implement input length limits and validation",
                "Regularly audit code for buffer operations"
            ]
        },
        "CWE-20": {
            "fixed_code": "# Implement comprehensive input validation\nimport re\n\ndef validate_input(user_input, input_type='string', max_length=100):\n    if not user_input or len(user_input) > max_length:\n        raise ValueError('Invalid input length')\n    \n    if input_type == 'email':\n        pattern = r'^[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,}$'\n        if not re.match(pattern, user_input):\n            raise ValueError('Invalid email format')\n    elif input_type == 'numeric':\n        if not user_input.isdigit():\n            raise ValueError('Input must be numeric')\n    \n    return user_input.strip()\n\nvalidated_input = validate_input(user_input, input_type='string')",
            "explanation": "Input validation prevents malicious data from entering the application. Validate input type, length, format, and content against a whitelist of allowed values. Reject any input that doesn't meet strict criteria.",
            "best_practices": [
                "Validate all user input on the server side (client-side validation is not sufficient)",
                "Use whitelist validation (allow only known good values) instead of blacklist",
                "Validate input type, length, format, and range",
                "Sanitize input by removing or encoding dangerous characters",
                "Implement input validation at multiple layers (presentation, business, data)",
                "Log validation failures for security monitoring"
            ]
        }
    }
    
    return remediation_map.get(cwe_id, {
        "fixed_code": "# TODO: Implement secure alternative based on vulnerability type\n# Review security best practices and apply appropriate fixes",
        "explanation": "Review the code and implement appropriate security measures based on the specific vulnerability type detected.",
        "best_practices": [
            "Validate and sanitize all user input",
            "Use secure coding practices",
            "Follow OWASP guidelines",
            "Implement proper error handling",
            "Regular security audits and code reviews"
        ]
    })


def get_references(cwe_id):
    """Generate CWE and OWASP references specific to vulnerability type"""
    cwe_num = cwe_id.replace("CWE-", "")
    
    # Map CWE to specific OWASP Top 10 category
    owasp_map = {
        "CWE-89": "https://owasp.org/Top10/A03_2021-Injection/",  # SQL Injection
        "CWE-79": "https://owasp.org/Top10/A03_2021-Injection/",  # XSS
        "CWE-78": "https://owasp.org/Top10/A03_2021-Injection/",  # Command Injection
        "CWE-22": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",  # Path Traversal
        "CWE-502": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",  # Insecure Deserialization
        "CWE-120": "https://owasp.org/Top10/A03_2021-Injection/",  # Buffer Overflow
        "CWE-20": "https://owasp.org/Top10/A03_2021-Injection/",  # Improper Input Validation
    }
    
    owasp_ref = owasp_map.get(cwe_id, "https://owasp.org/Top10/")
    
    return [
        f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        owasp_ref,
        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
    ]


def extract_code_from_html(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        html = f.read()
    soup = BeautifulSoup(html, "html.parser")
    snippets = []
    for tag in soup.find_all(["script", "code", "pre"]):
        code = tag.get_text().strip()
        if code:
            snippets.append(code)
    # Fallback: analyze whole HTML if no code tags found
    if not snippets:
        snippets = [html]
    return snippets


def main():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Enhanced SAST model not found at {MODEL_PATH}")
    if not os.path.exists(HTML_FILE_PATH):
        raise FileNotFoundError(f"HTML test file not found at {HTML_FILE_PATH}")

    analyzer = EnhancedSASTAnalyzer(MODEL_PATH)

    snippets = extract_code_from_html(HTML_FILE_PATH)
    findings = []
    counter = 0
    
    for code in snippets:
        finding = analyzer.analyze_code(code, file_path=HTML_FILE_PATH)
        
        # Only process vulnerable findings
        if not finding or not finding.is_vulnerable:
            continue
            
        counter += 1
        vuln_type = finding.vulnerability_type or "Unknown"
        
        # Get code snippet for context
        code_snippet = finding.vulnerable_line or code[:200]
        
        # Improve vulnerability type detection based on code content
        code_lower = code_snippet.lower()
        if vuln_type in ["neutral", "mixed", "Unknown"]:
            # Try to detect actual vulnerability type from code
            if any(pattern in code_lower for pattern in ["select", "insert", "update", "delete", "drop table", "union", "or '1'='1"]):
                vuln_type = "SQL Injection"
            elif any(pattern in code_lower for pattern in ["<script", "onerror", "onclick", "innerhtml", "document.write", "javascript:"]):
                vuln_type = "XSS"
            elif any(pattern in code_lower for pattern in ["../", "..\\", "/etc/passwd", "path traversal"]):
                vuln_type = "Path Traversal"
            elif any(pattern in code_lower for pattern in ["os.system", "subprocess", "exec(", "eval(", "shell=True"]):
                vuln_type = "Command Injection"
            elif any(pattern in code_lower for pattern in ["pickle", "deserialize", "unmarshal"]):
                vuln_type = "Insecure Deserialization"
        
        cwe_id, vuln_name = get_cwe_info(vuln_type)
        rule_id = generate_rule_id(vuln_type, finding.line_number, counter)
        
        # Get vulnerability-specific remediation based on CWE ID
        remediation_info = get_remediation_for_vulnerability(vuln_type, cwe_id, code_snippet)
        
        # Always use our CWE-specific remediation (it's more detailed and specific)
        # The analyzer's remediation is often generic, so we prioritize our detailed content
        fixed_code = remediation_info["fixed_code"]
        explanation = remediation_info["explanation"]
        best_practices = remediation_info["best_practices"]
        
        # Generate vulnerability-specific issue description
        issue_description = get_issue_description(vuln_type, cwe_id, code_snippet)
        
        # Generate impact description
        impact = get_impact_description(vuln_type, cwe_id)
        
        # Generate references
        references = get_references(cwe_id)
        
        # Format severity to match prompt (Capitalize first letter)
        severity = finding.severity.capitalize() if finding.severity else "Medium"
        
        # Create finding in prompt format
        finding_dict = {
            "file": os.path.basename(HTML_FILE_PATH),
            "line_number": finding.line_number,
            "rule_id": rule_id,
            "vulnerability": {
                "name": vuln_name,
                "cwe_id": cwe_id,
                "severity": severity,
                "confidence": round(float(finding.confidence), 2)
            },
            "code_snippet": code_snippet,
            "issue_description": issue_description,
            "impact": impact,
            "recommendation": {
                "fixed_code": fixed_code,
                "explanation": explanation,
                "best_practices": best_practices
            },
            "references": references
        }
        
        findings.append(finding_dict)

    # Output as array of findings (one per vulnerability)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        if len(findings) == 1:
            # Single finding - output as object
            json.dump(findings[0], f, indent=2)
        else:
            # Multiple findings - output as array
            json.dump(findings, f, indent=2)
    
    print(f"SAST enhanced scan complete. Found {len(findings)} vulnerabilities. Report saved to {REPORT_PATH}")


if __name__ == "__main__":
    main()


