#!/usr/bin/env python3
"""
Vulnerable Website for SAST Testing
Contains various security vulnerabilities for machine learning model testing
"""

from flask import Flask, request, render_template_string, redirect, url_for, flash
import sqlite3
import os
import subprocess
import urllib.parse

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key'

# Database setup
def init_db():
    conn = sqlite3.connect('test_users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        )
    ''')
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password, email) VALUES 
        ('admin', 'admin123', 'admin@test.com'),
        ('user1', 'password123', 'user1@test.com'),
        ('test', 'test123', 'test@test.com')
    ''')
    conn.commit()
    conn.close()

# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test Website</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .vulnerability { background: #ffe6e6; padding: 15px; margin: 10px 0; border-left: 4px solid #ff0000; }
        .safe { background: #e6ffe6; padding: 15px; margin: 10px 0; border-left: 4px solid #00ff00; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        .result { background: #f8f9fa; padding: 10px; margin: 10px 0; border: 1px solid #dee2e6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Vulnerable Test Website</h1>
        <p><strong>Warning:</strong> This website contains intentional security vulnerabilities for testing purposes only!</p>
        
        <h2>1. SQL Injection Vulnerabilities</h2>
        <div class="vulnerability">
            <h3>Login Form (Vulnerable)</h3>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p><strong>Test payload:</strong> admin' OR '1'='1' --</p>
        </div>
        
        <div class="vulnerability">
            <h3>User Search (Vulnerable)</h3>
            <form method="GET" action="/search">
                <input type="text" name="query" placeholder="Search users..." required>
                <button type="submit">Search</button>
            </form>
            <p><strong>Test payload:</strong> ' UNION SELECT username, password, email FROM users --</p>
        </div>
        
        <h2>2. XSS Vulnerabilities</h2>
        <div class="vulnerability">
            <h3>Comment Form (Vulnerable)</h3>
            <form method="POST" action="/comment">
                <textarea name="comment" placeholder="Leave a comment..." required></textarea>
                <button type="submit">Submit Comment</button>
            </form>
            <p><strong>Test payload:</strong> &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
        </div>
        
        <div class="vulnerability">
            <h3>URL Parameter XSS (Vulnerable)</h3>
            <form method="GET" action="/profile">
                <input type="text" name="name" placeholder="Your name" required>
                <button type="submit">View Profile</button>
            </form>
            <p><strong>Test payload:</strong> &lt;img src=x onerror=alert('XSS')&gt;</p>
        </div>
        
        <h2>3. Command Injection Vulnerabilities</h2>
        <div class="vulnerability">
            <h3>Ping Tool (Vulnerable)</h3>
            <form method="POST" action="/ping">
                <input type="text" name="host" placeholder="Host to ping" required>
                <button type="submit">Ping</button>
            </form>
            <p><strong>Test payload:</strong> 127.0.0.1; ls -la</p>
        </div>
        
        <div class="vulnerable">
            <h3>File Upload (Vulnerable)</h3>
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file" required>
                <button type="submit">Upload</button>
            </form>
            <p><strong>Test:</strong> Upload a file with malicious name</p>
        </div>
        
        <h2>4. Path Traversal Vulnerabilities</h2>
        <div class="vulnerability">
            <h3>File Viewer (Vulnerable)</h3>
            <form method="GET" action="/view_file">
                <input type="text" name="filename" placeholder="Filename" required>
                <button type="submit">View File</button>
            </form>
            <p><strong>Test payload:</strong> ../../../etc/passwd</p>
        </div>
        
        <h2>5. Safe Examples (For Comparison)</h2>
        <div class="safe">
            <h3>Safe Login Form</h3>
            <form method="POST" action="/safe_login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Safe Login</button>
            </form>
            <p><strong>Note:</strong> This form uses parameterized queries</p>
        </div>
        
        {% if results %}
        <div class="result">
            <h3>Results:</h3>
            <pre>{{ results }}</pre>
        </div>
        {% endif %}
        
        {% if error %}
        <div class="result" style="background: #ffe6e6;">
            <h3>Error:</h3>
            <pre>{{ error }}</pre>
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

# VULNERABLE ROUTES - SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        conn = sqlite3.connect('test_users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return f"<h2>Login Successful!</h2><p>Welcome {user[1]}!</p><p>Query executed: {query}</p><a href='/'>Back</a>"
        else:
            return f"<h2>Login Failed!</h2><p>Query executed: {query}</p><a href='/'>Back</a>"
    except Exception as e:
        return f"<h2>Error!</h2><p>{str(e)}</p><p>Query executed: {query}</p><a href='/'>Back</a>"

@app.route('/search', methods=['GET'])
def search():
    query_param = request.args.get('query', '')
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT username, email FROM users WHERE username LIKE '%{query_param}%'"
    
    try:
        conn = sqlite3.connect('test_users.db')
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        result_text = f"Query executed: {query}\n\nResults:\n"
        for row in results:
            result_text += f"Username: {row[0]}, Email: {row[1]}\n"
        
        return render_template_string(HTML_TEMPLATE, results=result_text)
    except Exception as e:
        return render_template_string(HTML_TEMPLATE, error=f"Error: {str(e)}\nQuery: {query}")

# VULNERABLE ROUTES - XSS
@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form['comment']
    
    # VULNERABLE: Direct output without escaping
    return f"<h2>Comment Posted!</h2><p>Your comment: {comment}</p><a href='/'>Back</a>"

@app.route('/profile', methods=['GET'])
def profile():
    name = request.args.get('name', '')
    
    # VULNERABLE: Direct output without escaping
    return f"<h2>Profile Page</h2><p>Hello, {name}!</p><a href='/'>Back</a>"

# VULNERABLE ROUTES - Command Injection
@app.route('/ping', methods=['POST'])
def ping():
    host = request.form['host']
    
    # VULNERABLE: Direct command execution
    try:
        result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)
        return f"<h2>Ping Results</h2><pre>Command: ping -c 4 {host}\n\n{result.stdout}</pre><a href='/'>Back</a>"
    except Exception as e:
        return f"<h2>Error!</h2><p>{str(e)}</p><a href='/'>Back</a>"

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file uploaded"
    
    file = request.files['file']
    if file.filename == '':
        return "No file selected"
    
    # VULNERABLE: Unsafe file handling
    filename = file.filename
    file.save(filename)
    
    # VULNERABLE: Command injection in file processing
    result = subprocess.run(f"file {filename}", shell=True, capture_output=True, text=True)
    
    return f"<h2>File Uploaded!</h2><p>Filename: {filename}</p><pre>{result.stdout}</pre><a href='/'>Back</a>"

# VULNERABLE ROUTES - Path Traversal
@app.route('/view_file', methods=['GET'])
def view_file():
    filename = request.args.get('filename', '')
    
    # VULNERABLE: Path traversal
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<h2>File Content</h2><pre>{content}</pre><a href='/'>Back</a>"
    except Exception as e:
        return f"<h2>Error!</h2><p>{str(e)}</p><a href='/'>Back</a>"

# SAFE ROUTES - For comparison
@app.route('/safe_login', methods=['POST'])
def safe_login():
    username = request.form['username']
    password = request.form['password']
    
    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    try:
        conn = sqlite3.connect('test_users.db')
        cursor = conn.cursor()
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return f"<h2>Safe Login Successful!</h2><p>Welcome {user[1]}!</p><a href='/'>Back</a>"
        else:
            return f"<h2>Safe Login Failed!</h2><a href='/'>Back</a>"
    except Exception as e:
        return f"<h2>Error!</h2><p>{str(e)}</p><a href='/'>Back</a>"

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
