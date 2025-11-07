# test_security.py - Test various Python vulnerabilities

# A02 - Cryptographic Failures
import hashlib
import os

def weak_hash(password):
    # ❌ Weak hashing - MD5
    return hashlib.md5(password.encode()).hexdigest()

def hardcoded_password():
    # ❌ Hardcoded password
    password = "supersecret123"
    return password

# A03 - Injection  
import subprocess
import sqlite3

def command_injection(user_input):
    # ❌ Command injection
    subprocess.run(f"ls {user_input}", shell=True)

def sql_injection(user_id):
    # ❌ SQL injection
    conn = sqlite3.connect('test.db')
    conn.execute(f"SELECT * FROM users WHERE id = {user_id}")

# A08 - Software Integrity
import pickle
import yaml

def unsafe_deserialization(data):
    # ❌ Insecure deserialization
    return pickle.loads(data)

def yaml_vulnerability(data):
    # ❌ YAML load vulnerability
    return yaml.load(data)

# A10 - SSRF
import urllib.request

def ssrf_vulnerability(url):
    # ❌ Potential SSRF
    return urllib.request.urlopen(url)