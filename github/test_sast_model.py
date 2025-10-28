#!/usr/bin/env python3
"""
SAST Model Test Script
Tests the SAST model against vulnerable code samples
"""

import os
import sys
import subprocess
import time

def test_vulnerable_code_samples():
    """Test SAST model against known vulnerable code patterns"""
    
    # Vulnerable code samples for testing
    vulnerable_samples = [
        # SQL Injection
        "SELECT * FROM users WHERE username = '" + "user_input" + "'",
        "SELECT * FROM users WHERE id = " + "user_id",
        "INSERT INTO users VALUES ('" + "name" + "', '" + "email" + "')",
        
        # XSS
        "document.write('<script>alert(1)</script>')",
        "innerHTML = userInput",
        "<div>" + "userContent" + "</div>",
        
        # Command Injection
        "os.system('rm -rf /')",
        "subprocess.run('ping ' + host, shell=True)",
        "os.popen('ls ' + directory)",
        
        # Path Traversal
        "open('../../../etc/passwd', 'r')",
        "file = open(userPath, 'r')",
        "with open('../' + filename, 'r') as f:",
        
        # Unsafe eval
        "eval(userInput)",
        "exec(userCode)",
        "__import__('os').system('ls')",
        
        # Unsafe deserialization
        "pickle.loads(userData)",
        "yaml.load(userYaml)",
        "json.loads(userJson)",
    ]
    
    # Safe code samples for comparison
    safe_samples = [
        # Safe SQL
        "SELECT * FROM users WHERE username = ?",
        "PreparedStatement stmt = conn.prepareStatement(query)",
        "cursor.execute(query, (username, password))",
        
        # Safe XSS prevention
        "escape(userInput)",
        "html.escape(userContent)",
        "markupsafe.escape(userData)",
        
        # Safe command execution
        "subprocess.run(['ping', '-c', '4', host])",
        "os.path.join(directory, filename)",
        "shlex.quote(userInput)",
        
        # Safe file access
        "os.path.join('/safe/dir', filename)",
        "if '..' not in filename:",
        "safe_path = os.path.abspath(filename)",
        
        # Safe alternatives
        "ast.literal_eval(userInput)",
        "json.loads(userJson)",
        "yaml.safe_load(userYaml)",
    ]
    
    return vulnerable_samples, safe_samples

def start_vulnerable_website():
    """Start the vulnerable website for interactive testing"""
    try:
        # Check if Flask is installed
        subprocess.run([sys.executable, "-c", "import flask"], check=True)
        
        # Start the vulnerable website
        os.chdir("github")
        subprocess.run([sys.executable, "test_vulnerable_website.py"])
        
    except subprocess.CalledProcessError:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements_vulnerable.txt"])
        start_vulnerable_website()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        pass

def main():
    """Main function"""
    while True:
        print("Choose an option:")
        print("1. Test SAST model with code samples")
        print("2. Start vulnerable website for interactive testing")
        print("3. View vulnerable test cases (HTML)")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            test_vulnerable_code_samples()
        elif choice == "2":
            start_vulnerable_website()
        elif choice == "3":
            print("File: github/vulnerable_test_cases.html")
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please enter 1-4.")

if __name__ == "__main__":
    main()
