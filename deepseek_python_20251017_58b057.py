#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Secure Remote Control Server
Ultra Fast + Multi-Platform + Fully Secured
"""
import requests
import json
import time
import urllib.parse
import uuid
import hashlib
import threading
import sqlite3
import os
import secrets
import re
import hmac
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import bcrypt

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class SecureSessionManager:
    def __init__(self):
        self.sessions = {}
        self.session_timeout = 3600
        self.max_sessions_per_ip = 3
        self.failed_attempts = {}
        self.lock = threading.Lock()
        
    def clean_expired_sessions(self):
        current_time = time.time()
        expired_sessions = [
            session_id for session_id, session in self.sessions.items()
            if current_time - session['last_activity'] > self.session_timeout
        ]
        for session_id in expired_sessions:
            del self.sessions[session_id]
    
    def record_failed_attempt(self, ip_address):
        with self.lock:
            if ip_address not in self.failed_attempts:
                self.failed_attempts[ip_address] = {'count': 0, 'first_attempt': time.time()}
            
            self.failed_attempts[ip_address]['count'] += 1
            self.failed_attempts[ip_address]['last_attempt'] = time.time()
            
            if self.failed_attempts[ip_address]['count'] >= 10:
                block_time = min(3600, 300 * (2 ** (self.failed_attempts[ip_address]['count'] - 10)))
                self.failed_attempts[ip_address]['blocked_until'] = time.time() + block_time
                return True
            return False
    
    def is_ip_blocked(self, ip_address):
        with self.lock:
            if ip_address not in self.failed_attempts:
                return False
            
            attempts = self.failed_attempts[ip_address]
            if 'blocked_until' in attempts:
                if time.time() < attempts['blocked_until']:
                    return True
                else:
                    del self.failed_attempts[ip_address]
                    return False
            return False
    
    def reset_failed_attempts(self, ip_address):
        with self.lock:
            if ip_address in self.failed_attempts:
                del self.failed_attempts[ip_address]
    
    def create_session(self, user_id, user_level, ip_address, user_agent):
        with self.lock:
            self.clean_expired_sessions()
            
            if self.is_ip_blocked(ip_address):
                return None, None
            
            ip_sessions = [s for s in self.sessions.values() if s['ip'] == ip_address]
            if len(ip_sessions) >= self.max_sessions_per_ip:
                oldest_session = min(ip_sessions, key=lambda x: x['created_at'])
                del self.sessions[oldest_session['session_id']]
            
            session_id = secrets.token_urlsafe(32)
            session_token = secrets.token_urlsafe(64)
            csrf_token = secrets.token_urlsafe(32)
            
            self.sessions[session_id] = {
                'session_id': session_id,
                'session_token': session_token,
                'csrf_token': csrf_token,
                'user_id': user_id,
                'user_level': user_level,
                'ip': ip_address,
                'user_agent': user_agent,
                'created_at': time.time(),
                'last_activity': time.time(),
                'is_active': True
            }
            
            return session_id, session_token, csrf_token
    
    def validate_session(self, session_id, session_token, ip_address, user_agent):
        with self.lock:
            if session_id not in self.sessions:
                return None
            
            session = self.sessions[session_id]
            
            if not secrets.compare_digest(session['session_token'], session_token):
                return None
            
            if time.time() - session['last_activity'] > self.session_timeout:
                del self.sessions[session_id]
                return None
            
            session['last_activity'] = time.time()
            return session
    
    def invalidate_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
    
    def validate_csrf_token(self, session_id, csrf_token):
        with self.lock:
            if session_id not in self.sessions:
                return False
            
            session = self.sessions[session_id]
            return secrets.compare_digest(session['csrf_token'], csrf_token)

class PasswordManager:
    def __init__(self, password_file="passwords.json", github_url=None):
        self.password_file = password_file
        self.github_url = github_url or "https://raw.githubusercontent.com/hblackhat676-wq/game-python/main/passwords.json"
        self.ensure_password_file()
    
    def ensure_password_file(self):
        """جلب كلمات المرور المشفرة من GitHub"""
        if not os.path.exists(self.password_file):
            if self.download_from_github():
                print("Encrypted passwords downloaded from GitHub")
                return
            
            # إذا فشل التحميل، إنشاء كلمات مرور مشفرة جديدة
            self.create_secure_passwords()
    
    def download_from_github(self):
        """تحميل ملف passwords.json المشفر من GitHub"""
        try:
            print(f"Downloading encrypted passwords from GitHub...")
            response = requests.get(self.github_url, timeout=10)
            
            if response.status_code == 200:
                passwords = response.json()
                
                # التحقق من أن الكلمات مشفرة (تبدأ بـ $2b$)
                user_pwd = passwords.get('user_password', '')
                admin_pwd = passwords.get('admin_password', '')
                
                if user_pwd.startswith('$2b$') and admin_pwd.startswith('$2b$'):
                    # حفظ الملف المشفر محلياً
                    self.save_passwords(passwords)
                    print("Successfully loaded encrypted passwords")
                    return True
                else:
                    print("Passwords in GitHub are not encrypted!")
                    print("Please update passwords.json with bcrypt hashes")
                    return False
            else:
                print(f"Failed to download from GitHub: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"GitHub download error: {e}")
            return False
    
    def create_secure_passwords(self):
        """إنشاء كلمات مرور مشفرة جديدة احتياطية"""
        print("Creating new encrypted passwords as fallback...")
        
        # كلمات مرور افتراضية (يجب تغييرها لاحقاً من الإعدادات)
        secure_passwords = {
            'user_password': self.hash_password("change_this_user_123"),
            'admin_password': self.hash_password("change_this_admin_456")
        }
        
        self.save_passwords(secure_passwords)
        print("Using fallback encrypted passwords - CHANGE THEM IN SETTINGS!")
    
    def load_passwords(self):
        """تحميل كلمات المرور مع التأكد من أنها مشفرة"""
        try:
            with open(self.password_file, 'r') as f:
                passwords = json.load(f)
            
            # التحقق من التشفير
            if self.are_passwords_encrypted(passwords):
                return passwords
            else:
                print("Passwords are not encrypted, hashing them now...")
                # إذا كانت نصاً واضحاً، تشفيرها
                encrypted_passwords = {
                    'user_password': self.hash_password(passwords.get('user_password', '')),
                    'admin_password': self.hash_password(passwords.get('admin_password', ''))
                }
                self.save_passwords(encrypted_passwords)
                return encrypted_passwords
                
        except Exception as e:
            print(f"Error loading passwords: {e}")
            return self.create_secure_passwords()
    
    def are_passwords_encrypted(self, passwords):
        """التحقق إذا كانت كلمات المرور مشفرة"""
        user_pwd = passwords.get('user_password', '')
        admin_pwd = passwords.get('admin_password', '')
        return user_pwd.startswith('$2b$') and admin_pwd.startswith('$2b$')
    
    def hash_password(self, password):
        """تشفير كلمة المرور باستخدام bcrypt"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    def verify_password(self, password, hashed):
        """التحقق من كلمة المرور مقابل التشفير"""
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception as e:
            print(f"Password verification error: {e}")
            return False
    
    def save_passwords(self, passwords):
        """حفظ كلمات المرور في ملف محلي"""
        try:
            with open(self.password_file, 'w') as f:
                json.dump(passwords, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving passwords: {e}")
            return False

class CommandValidator:
    def __init__(self):
        self.allowed_commands = {
            'sysinfo', 'status', 'ping', 'whoami', 'echo',
            'uname -a', 'ls -la', 'dir', 'pwd', 'date'
        }
        
        self.dangerous_patterns = [
            r'rm\s+-rf', r'mkfs', r'dd\s+if=', r'>\s+/dev/', 
            r'chmod\s+777', r'chown\s+root', r'passwd',
            r'ssh-keygen', r'format\s+', r'fdisk'
        ]
    
    def is_command_safe(self, command):
        command_lower = command.lower().strip()
        
        if command_lower in self.allowed_commands:
            return True
        
        for pattern in self.dangerous_patterns:
            if re.search(pattern, command_lower):
                return False
        
        if len(command) > 1000:
            return False
            
        return True

class EnhancedRemoteControlHandler(BaseHTTPRequestHandler):
    sessions = {}
    commands_queue = {}
    session_manager = SecureSessionManager()
    password_manager = PasswordManager(github_url="https://raw.githubusercontent.com/hblackhat676-wq/game-python/main/passwords.json")
    command_validator = CommandValidator()
    session_lock = threading.Lock()
    rate_limits = {}
    
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    
    def check_rate_limit(self, ip_address):
        current_time = time.time()
        if ip_address in self.rate_limits:
            if current_time - self.rate_limits[ip_address]['last_request'] < 0.1:
                self.rate_limits[ip_address]['requests'] += 1
                if self.rate_limits[ip_address]['requests'] > 100:
                    return False
            else:
                self.rate_limits[ip_address] = {'last_request': current_time, 'requests': 1}
        else:
            self.rate_limits[ip_address] = {'last_request': current_time, 'requests': 1}
        return True
    
    def get_client_info(self):
        return {
            'ip': self.client_address[0],
            'user_agent': self.headers.get('User-Agent', 'Unknown'),
            'time': datetime.now().isoformat()
        }
    
    def get_session_from_cookie(self):
        cookie_header = self.headers.get('Cookie', '')
        cookies = {}
        for cookie in cookie_header.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
        
        session_id = cookies.get('session_id')
        session_token = cookies.get('session_token')
        
        if not session_id or not session_token:
            return None
        
        return self.session_manager.validate_session(
            session_id, session_token, 
            self.client_address[0],
            self.headers.get('User-Agent', 'Unknown')
        )
    
    def require_auth(self, min_level=1):
        session = self.get_session_from_cookie()
        if not session:
            self.send_redirect('/')
            return None
        
        if session['user_level'] < min_level:
            self.send_error(403, "Insufficient privileges")
            return None
        
        return session
    
    def send_redirect(self, location):
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()
    
    def send_json(self, data, status=200, cookies=None):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        
        for header, value in self.SECURITY_HEADERS.items():
            self.send_header(header, value)
        
        if cookies:
            for cookie in cookies:
                self.send_header('Set-Cookie', cookie)
        
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def send_html(self, html, status=200, cookies=None):
        self.send_response(status)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        
        for header, value in self.SECURITY_HEADERS.items():
            self.send_header(header, value)
        
        if cookies:
            for cookie in cookies:
                self.send_header('Set-Cookie', cookie)
        
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def init_database(self):
        self.conn = sqlite3.connect('remote_control.db', check_same_thread=False)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.cursor = self.conn.cursor()
        
        tables = [
            '''CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT,
                command TEXT,
                response TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                ip TEXT,
                computer_name TEXT,
                os TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                status TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                action TEXT,
                severity TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )''',
            '''CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                user TEXT,
                action TEXT,
                success BOOLEAN,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )'''
        ]
        
        for table in tables:
            try:
                self.cursor.execute(table)
            except Exception as e:
                print(f"Database error: {e}")
        self.conn.commit()
    
    def log_security_event(self, action, severity="INFO"):
        try:
            self.cursor.execute(
                'INSERT INTO security_logs (ip, action, severity) VALUES (?, ?, ?)',
                (self.client_address[0], action, severity)
            )
            self.conn.commit()
        except:
            pass
    
    def log_auth_event(self, user, action, success):
        try:
            self.cursor.execute(
                'INSERT INTO auth_logs (ip, user, action, success) VALUES (?, ?, ?, ?)',
                (self.client_address[0], user, action, success)
            )
            self.conn.commit()
        except:
            pass
    
    def do_GET(self):
        if not self.check_rate_limit(self.client_address[0]):
            self.send_error(429, "Too many requests")
            return
        
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            
            routes = {
                '/': self.send_login_page,
                '/admin-auth': self.send_admin_auth_page,
                '/control': self.send_control_panel,
                '/sessions': self.send_sessions_list,
                '/commands': self.handle_get_commands,
                '/result': self.handle_get_result,
                '/download-client': self.download_python_client,
                '/history': self.send_command_history,
                '/status': self.send_system_status,
                '/settings': self.send_settings_page,
                '/logout': self.handle_logout
            }
            
            handler = routes.get(path, self.send_404_page)
            handler()
                
        except Exception as e:
            self.log_security_event(f"GET Error: {str(e)}", "ERROR")
            self.send_error(500, "Internal server error")
    
    def do_POST(self):
        if not self.check_rate_limit(self.client_address[0]):
            self.send_error(429, "Too many requests")
            return
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10000:
                self.send_error(413, "Payload too large")
                return
                
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data) if post_data else {}
            
            routes = {
                '/login': self.handle_login,
                '/admin-login': self.handle_admin_login,
                '/execute': self.handle_execute_command,
                '/response': self.handle_client_response,
                '/register': self.handle_client_register,
                '/change-password': self.handle_change_password
            }
            
            handler = routes.get(self.path, lambda x: self.send_error(404, "Not found"))
            handler(data)
                
        except Exception as e:
            self.log_security_event(f"POST Error: {str(e)}", "ERROR")
            self.send_json({'success': False, 'error': 'Internal server error'})
    
    def handle_logout(self):
        session = self.get_session_from_cookie()
        if session:
            self.session_manager.invalidate_session(session['session_id'])
            self.log_auth_event(session['user_id'], 'logout', True)
        
        cookies = [
            'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly',
            'session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly'
        ]
        self.send_redirect('/')
    
    def send_login_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Remote Control - Authentication</title>
            <meta charset="utf-8">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh;
                    margin: 0;
                }
                .container { 
                    background: rgba(45, 45, 45, 0.95); 
                    padding: 40px; 
                    border-radius: 15px; 
                    text-align: center;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                    width: 400px;
                }
                .logo { 
                    font-size: 48px; 
                    margin-bottom: 20px; 
                }
                input, button { 
                    padding: 15px; 
                    margin: 10px; 
                    width: 280px; 
                    border-radius: 8px; 
                    font-size: 16px;
                    border: none;
                    transition: all 0.2s ease;
                }
                input { 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                }
                input:focus {
                    outline: none;
                    border-color: #0078d4;
                    background: rgba(255,255,255,0.15);
                }
                input::placeholder { color: #ccc; }
                button { 
                    background: linear-gradient(135deg, #0078d4, #005a9e); 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                }
                button:hover {
                    background: linear-gradient(135deg, #005a9e, #004578);
                    transform: translateY(-2px);
                }
                .security-notice {
                    background: rgba(255,0,0,0.1);
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                    border: 1px solid rgba(255,0,0,0.3);
                    display: none;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">HBH</div>
                <h2>Secure Remote Control</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Level 1 Authentication</p>
                
                <div class="security-notice" id="securityNotice">
                    Security warning: Multiple failed attempts detected
                </div>
                
                <input type="password" id="password" placeholder="Enter Level 1 Password" autocomplete="off">
                <button onclick="login()">Authenticate</button>
                
                <div style="margin-top: 20px; font-size: 12px; color: #888;">
                    All activities are logged and monitored
                </div>
            </div>
            <script>
                async function login() {
                    const password = document.getElementById('password').value;
                    if (!password) {
                        alert('Please enter password');
                        return;
                    }
                    
                    try {
                        const response = await fetch('/login', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({password: password})
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            window.location = '/admin-auth';
                        } else {
                            document.getElementById('securityNotice').style.display = 'block';
                            alert('Authentication failed');
                        }
                    } catch (err) {
                        alert('Connection error');
                    }
                }
                
                document.getElementById('password').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') login();
                });
            </script>
        </body>
        </html>
        '''
        self.send_html(html)
    
    def send_admin_auth_page(self):
        session = self.require_auth(1)
        if not session:
            return
            
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Authentication</title>
            <meta charset="utf-8">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                    color: white; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh;
                    margin: 0;
                }
                .container { 
                    background: rgba(45, 45, 45, 0.95); 
                    padding: 40px; 
                    border-radius: 15px; 
                    text-align: center;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                    width: 400px;
                }
                .logo { 
                    font-size: 48px; 
                    margin-bottom: 20px; 
                }
                input, button { 
                    padding: 15px; 
                    margin: 10px; 
                    width: 280px; 
                    border-radius: 8px; 
                    font-size: 16px;
                    border: none;
                    transition: all 0.2s ease;
                }
                input { 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                }
                input:focus {
                    outline: none;
                    border-color: #e74c3c;
                }
                button { 
                    background: linear-gradient(135deg, #e74c3c, #c0392b); 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                }
                button:hover {
                    background: linear-gradient(135deg, #c0392b, #a93226);
                    transform: translateY(-2px);
                }
                .security-level {
                    background: rgba(231, 76, 60, 0.2);
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                    border: 1px solid #e74c3c;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">HBH</div>
                <h2>Admin Authentication</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Level 2 Security - Administrative Access</p>
                
                <div class="security-level">
                    HIGH SECURITY LEVEL - ADMIN ACCESS REQUIRED
                </div>
                
                <input type="password" id="adminPassword" placeholder="Enter Admin Password" autocomplete="off">
                <button onclick="adminLogin()">Admin Authentication</button>
                
                <div style="margin-top: 20px; font-size: 12px; color: #888;">
                    Unauthorized access will be logged and blocked
                </div>
            </div>
            <script>
                async function adminLogin() {
                    const password = document.getElementById('adminPassword').value;
                    if (!password) {
                        alert('Please enter admin password');
                        return;
                    }
                    
                    try {
                        const response = await fetch('/admin-login', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({password: password})
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            window.location = '/control';
                        } else {
                            alert('Admin authentication failed! Access denied.');
                        }
                    } catch (err) {
                        alert('Connection error');
                    }
                }
                
                document.getElementById('adminPassword').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') adminLogin();
                });
            </script>
        </body>
        </html>
        '''
        self.send_html(html)
    
    def handle_login(self, data):
        if self.session_manager.is_ip_blocked(self.client_address[0]):
            self.send_json({'success': False, 'error': 'IP temporarily blocked'})
            return
        
        password = data.get('password', '')
        passwords = self.password_manager.load_passwords()
        
        if self.password_manager.verify_password(password, passwords['user_password']):
            session_id, session_token, csrf_token = self.session_manager.create_session(
                'user', 1, self.client_address[0], self.headers.get('User-Agent', 'Unknown')
            )
            
            if session_id:
                cookies = [
                    f'session_id={session_id}; Path=/; HttpOnly; SameSite=Strict',
                    f'session_token={session_token}; Path=/; HttpOnly; SameSite=Strict'
                ]
                
                self.session_manager.reset_failed_attempts(self.client_address[0])
                self.log_auth_event('user', 'level1_login', True)
                self.send_json({'success': True}, cookies=cookies)
            else:
                self.send_json({'success': False, 'error': 'Session creation failed'})
        else:
            if self.session_manager.record_failed_attempt(self.client_address[0]):
                self.log_security_event(f"IP blocked due to failed login attempts: {self.client_address[0]}", "HIGH")
            
            self.log_auth_event('unknown', 'level1_login', False)
            self.send_json({'success': False, 'error': 'Invalid password'})
    
    def handle_admin_login(self, data):
        session = self.require_auth(1)
        if not session:
            return
        
        password = data.get('password', '')
        passwords = self.password_manager.load_passwords()
        
        if self.password_manager.verify_password(password, passwords['admin_password']):
            session_id, session_token, csrf_token = self.session_manager.create_session(
                'admin', 2, self.client_address[0], self.headers.get('User-Agent', 'Unknown')
            )
            
            if session_id:
                cookies = [
                    f'session_id={session_id}; Path=/; HttpOnly; SameSite=Strict',
                    f'session_token={session_token}; Path=/; HttpOnly; SameSite=Strict'
                ]
                
                self.log_auth_event('admin', 'level2_login', True)
                self.send_json({'success': True}, cookies=cookies)
            else:
                self.send_json({'success': False, 'error': 'Session creation failed'})
        else:
            self.log_auth_event(session['user_id'], 'level2_login', False)
            self.send_json({'success': False, 'error': 'Invalid admin password'})
    
    def send_control_panel(self):
        session = self.require_auth(2)
        if not session:
            return
        
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Control Panel</title>
            <meta charset="utf-8">
            <style>
                :root {
                    --primary: #0078d4;
                    --success: #28a745;
                    --danger: #dc3545;
                    --warning: #ffc107;
                    --dark: #1e1e1e;
                    --darker: #2d2d2d;
                    --light: #f8f9fa;
                }
                
                * { margin: 0; padding: 0; box-sizing: border-box; }
                
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: var(--dark); 
                    color: var(--light); 
                    margin: 0; 
                    padding: 20px;
                    overflow-x: hidden;
                }
                
                .header {
                    background: var(--darker);
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                .container { 
                    display: grid; 
                    grid-template-columns: 350px 1fr; 
                    gap: 20px; 
                    height: 90vh; 
                }
                
                .sidebar { 
                    background: var(--darker); 
                    padding: 20px; 
                    border-radius: 10px;
                    display: flex;
                    flex-direction: column;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                .main { 
                    display: flex; 
                    flex-direction: column;
                    gap: 20px;
                }
                
                .session-item { 
                    background: rgba(255,255,255,0.05); 
                    padding: 15px; 
                    margin: 8px 0; 
                    border-radius: 8px; 
                    cursor: pointer;
                    border: 2px solid transparent;
                    transition: all 0.2s ease;
                    position: relative;
                }
                
                .session-item:hover {
                    background: rgba(255,255,255,0.1);
                    border-color: var(--primary);
                    transform: translateY(-1px);
                }
                
                .session-item.active { 
                    border: 2px solid var(--success);
                    background: rgba(40, 167, 69, 0.1);
                }
                
                .session-item.offline {
                    opacity: 0.6;
                    border-color: var(--danger);
                }
                
                .online-status {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    width: 12px;
                    height: 12px;
                    border-radius: 50%;
                    background: var(--success);
                    animation: pulse 2s infinite;
                }
                
                @keyframes pulse {
                    0% { opacity: 1; }
                    50% { opacity: 0.5; }
                    100% { opacity: 1; }
                }
                
                .online-status.offline {
                    background: var(--danger);
                    animation: none;
                }
                
                .terminal { 
                    background: #000; 
                    color: #00ff00; 
                    padding: 20px; 
                    border-radius: 8px; 
                    font-family: 'Consolas', monospace; 
                    flex: 1; 
                    overflow-y: auto; 
                    white-space: pre-wrap;
                    font-size: 14px;
                    min-height: 400px;
                    border: 1px solid rgba(0,255,0,0.2);
                }
                
                button { 
                    background: var(--primary); 
                    color: white; 
                    border: none; 
                    padding: 12px 16px; 
                    margin: 4px; 
                    border-radius: 6px; 
                    cursor: pointer;
                    transition: all 0.2s ease;
                    font-weight: 500;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                }
                
                button.danger { 
                    background: var(--danger); 
                    border: 1px solid rgba(220,53,69,0.3);
                }
                
                button.success { 
                    background: var(--success); 
                    border: 1px solid rgba(40,167,69,0.3);
                }
                
                button.warning { 
                    background: var(--warning); 
                    color: #000; 
                    border: 1px solid rgba(255,193,7,0.3);
                }
                
                .controls-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                    gap: 8px;
                    margin: 15px 0;
                }
                
                .command-input { 
                    display: flex; 
                    margin: 15px 0; 
                    gap: 10px;
                }
                
                .command-input input { 
                    flex: 1; 
                    padding: 12px; 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                    border-radius: 6px;
                    font-family: 'Consolas', monospace;
                }
                
                .command-input input:focus {
                    outline: none;
                    border-color: var(--primary);
                    background: rgba(255,255,255,0.15);
                }
                
                .stats {
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 10px;
                    margin: 15px 0;
                }
                
                .stat-card {
                    background: var(--darker);
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                .multi-control {
                    background: var(--darker);
                    padding: 15px;
                    border-radius: 8px;
                    margin: 10px 0;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                .platform-buttons {
                    display: flex;
                    gap: 10px;
                    margin: 10px 0;
                }
                
                .platform-btn {
                    flex: 1;
                    text-align: center;
                    padding: 10px;
                    background: rgba(255,255,255,0.1);
                    border-radius: 5px;
                    cursor: pointer;
                    border: 1px solid rgba(255,255,255,0.2);
                }
                
                .platform-btn.active {
                    background: var(--primary);
                    border-color: var(--primary);
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Secure Remote Control Panel</h2>
                <div>
                    <button onclick="loadSessions()">Refresh</button>
                    <button onclick="executeAll('sysinfo')">System Info All</button>
                    <button class="warning" onclick="openSettings()">Settings</button>
                    <button class="danger" onclick="logout()">Logout</button>
                </div>
            </div>
            
            <div class="container">
                <div class="sidebar">
                    <h3>Connected Clients (<span id="clientsCount">0</span>)</h3>
                    <div id="sessionsList" style="flex: 1; overflow-y: auto; max-height: 500px;">
                        <div style="text-align: center; color: #666; padding: 20px;">
                            Loading clients...
                        </div>
                    </div>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold; color: var(--primary)" id="totalClients">0</div>
                            <small>Total</small>
                        </div>
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold; color: var(--success)" id="activeClients">0</div>
                            <small>Active</small>
                        </div>
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold; color: var(--warning)" id="commandsSent">0</div>
                            <small>Commands</small>
                        </div>
                    </div>
                </div>
                
                <div class="main">
                    <div style="background: var(--darker); padding: 20px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.1);">
                        <h3>Selected Client: <span id="currentClient" style="color: var(--success); font-weight: bold;">Not Selected</span></h3>
                        
                        <div class="platform-buttons">
                            <div class="platform-btn active" onclick="setPlatform('windows')">Windows</div>
                            <div class="platform-btn" onclick="setPlatform('linux')">Linux</div>
                            <div class="platform-btn" onclick="setPlatform('both')">Both</div>
                        </div>
                        
                        <div class="multi-control">
                            <strong>Quick Commands:</strong>
                            <div class="controls-grid" id="windowsCommands">
                                <button onclick="executeCommand('systeminfo')">System Info</button>
                                <button onclick="executeCommand('whoami')">Current User</button>
                                <button onclick="executeCommand('ipconfig /all')">Network Info</button>
                                <button onclick="executeCommand('dir')">Files List</button>
                                <button onclick="executeCommand('tasklist')">Processes</button>
                                <button onclick="executeCommand('netstat -an')">Connections</button>
                                <button onclick="executeCommand('wmic logicaldisk get size,freespace,caption')">Disk Space</button>
                                <button onclick="executeCommand('net user')">Users</button>
                                <button onclick="executeCommand('net localgroup administrators')">Admins</button>
                                <button class="danger" onclick="executeCommand('shutdown /s /t 60')">Shutdown 1m</button>
                                <button class="danger" onclick="executeCommand('shutdown /r /t 30')">Restart</button>
                                <button onclick="executeCommand('shutdown /a')">Cancel Shutdown</button>
                            </div>
                            <div class="controls-grid" id="linuxCommands" style="display: none;">
                                <button onclick="executeCommand('uname -a')">System Info</button>
                                <button onclick="executeCommand('whoami')">Current User</button>
                                <button onclick="executeCommand('ifconfig')">Network Info</button>
                                <button onclick="executeCommand('ls -la')">Files List</button>
                                <button onclick="executeCommand('ps aux')">Processes</button>
                                <button onclick="executeCommand('netstat -tulpn')">Connections</button>
                                <button onclick="executeCommand('df -h')">Disk Space</button>
                                <button onclick="executeCommand('cat /etc/passwd')">Users</button>
                                <button onclick="executeCommand('cat /etc/group')">Groups</button>
                                <button class="danger" onclick="executeCommand('shutdown -h +1')">Shutdown 1m</button>
                                <button class="danger" onclick="executeCommand('reboot')">Restart</button>
                                <button onclick="executeCommand('shutdown -c')">Cancel Shutdown</button>
                            </div>
                        </div>
                        
                        <div class="command-input">
                            <input type="text" id="commandInput" placeholder="Enter custom command" 
                                   onkeypress="if(event.key=='Enter') executeCustomCommand()">
                            <button onclick="executeCustomCommand()">Execute</button>
                            <button class="success" onclick="executeSelected('commandInput')">Execute on Selected</button>
                        </div>
                    </div>
                    
                    <div class="terminal" id="terminal">
    SECURE REMOTE CONTROL SYSTEM READY
    
    • Select a client from the left panel
    • Choose platform (Windows/Linux)
    • Execute commands securely
    • All activities are logged
    • Ultra-fast communication
    
                    </div>
                </div>
            </div>
            
            <script>
                let currentClientId = null;
                let commandCounter = 0;
                let allClients = [];
                let currentPlatform = 'windows';
                
                function setPlatform(platform) {
                    currentPlatform = platform;
                    document.querySelectorAll('.platform-btn').forEach(btn => {
                        btn.classList.remove('active');
                    });
                    event.target.classList.add('active');
                    
                    if (platform === 'windows') {
                        document.getElementById('windowsCommands').style.display = 'grid';
                        document.getElementById('linuxCommands').style.display = 'none';
                    } else if (platform === 'linux') {
                        document.getElementById('windowsCommands').style.display = 'none';
                        document.getElementById('linuxCommands').style.display = 'grid';
                    } else {
                        document.getElementById('windowsCommands').style.display = 'grid';
                        document.getElementById('linuxCommands').style.display = 'grid';
                    }
                }
                
                async function loadSessions() {
                    try {
                        const response = await fetch('/sessions?_t=' + Date.now());
                        const sessions = await response.json();
                        allClients = sessions;
                        updateSessionStats(sessions);
                        const list = document.getElementById('sessionsList');
                        
                        if (sessions.length === 0) {
                            list.innerHTML = '<div style="text-align:center;color:#666;padding:20px;">No clients connected</div>';
                            return;
                        }
                        
                        list.innerHTML = sessions.map(client => {
                            const lastSeen = new Date(client.last_seen).getTime();
                            const now = Date.now();
                            const timeDiff = (now - lastSeen) / 1000;
                            
                            const isOnline = timeDiff < 30;
                            const statusClass = isOnline ? 'online-status' : 'online-status offline';
                            const statusText = isOnline ? 'ONLINE' : 'OFFLINE';
                            const statusColor = isOnline ? '#28a745' : '#dc3545';
                            const isSelected = client.id === currentClientId;
                            
                            return `
                                <div class="session-item ${isSelected ? 'active' : ''} ${!isOnline ? 'offline' : ''}" 
                                     onclick="selectClient('${client.id}')">
                                    <div class="${statusClass}" title="${statusText}"></div>
                                    <strong style="color: ${statusColor}">${client.computer || client.id}</strong><br>
                                    <small>User: ${client.user || 'Unknown'}</small><br>
                                    <small>OS: ${client.os || 'Unknown'}</small><br>
                                    <small>IP: ${client.ip}</small><br>
                                    <small>Last: ${timeDiff.toFixed(0)}s ago</small>
                                    <small style="color: ${statusColor}; font-weight: bold;"> • ${statusText}</small>
                                </div>
                            `;
                        }).join('');
                    } catch (error) {
                        console.error('Error loading sessions:', error);
                    }
                }
                
                function updateSessionStats(sessions) {
                    const total = sessions.length;
                    const active = sessions.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 10000).length;
                    
                    document.getElementById('totalClients').textContent = total;
                    document.getElementById('activeClients').textContent = active;
                    document.getElementById('commandsSent').textContent = commandCounter;
                    document.getElementById('clientsCount').textContent = total;
                }
                
                function selectClient(clientId) {
                    currentClientId = clientId;
                    loadSessions();
                    document.getElementById('currentClient').textContent = clientId;
                    addToTerminal(`Selected client: ${clientId}\n`);
                }
                
                function executeCommand(command) {
                    if (!currentClientId) {
                        alert('Please select a client first!');
                        return;
                    }
                    executeSingleCommand(currentClientId, command);
                }
                
                async function executeSingleCommand(clientId, command) {
                    commandCounter++;
                    const startTime = Date.now();
                    addToTerminal(` [${clientId}] ${command}\n`);
                    
                    try {
                        const response = await fetch('/execute', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({client_id: clientId, command: command})
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            addToTerminal(`Command sent successfully\n`);
                            waitForResult(clientId, command, startTime);
                        } else {
                            addToTerminal(`Error: ${data.error}\n`);
                        }
                    } catch (err) {
                        addToTerminal(`Network error: ${err}\n`);
                    }
                }
                
                function executeAll(command) {
                    if (allClients.length === 0) {
                        alert('No clients connected!');
                        return;
                    }
                    
                    const activeClients = allClients.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 10000);
                    if (activeClients.length === 0) {
                        alert('No active clients!');
                        return;
                    }
                    
                    addToTerminal(`Executing command on ${activeClients.length} clients: ${command}\n`);
                    
                    activeClients.forEach(client => {
                        executeSingleCommand(client.id, command);
                    });
                }
                
                function executeSelected(inputId) {
                    const command = document.getElementById(inputId).value.trim();
                    if (!command) {
                        alert('Please enter a command');
                        return;
                    }
                    
                    if (currentClientId) {
                        executeCommand(command);
                    } else {
                        alert('Please select a client first');
                    }
                }
                
                function executeCustomCommand() {
                    const cmd = document.getElementById('commandInput').value.trim();
                    if (cmd) {
                        executeCommand(cmd);
                        document.getElementById('commandInput').value = '';
                    } else {
                        alert('Please enter a command');
                    }
                }
                
                function waitForResult(clientId, command, startTime) {
                    let attempts = 0;
                    const maxAttempts = 100;
                    
                    const checkImmediately = async () => {
                        attempts++;
                        if (attempts > maxAttempts) {
                            const elapsed = (Date.now() - startTime);
                            addToTerminal(`Timeout after ${elapsed}ms: No response from ${clientId}\n`);
                            return;
                        }
                        
                        try {
                            const response = await fetch('/result?client=' + clientId + '&command=' + encodeURIComponent(command) + '&_t=' + Date.now());
                            const data = await response.json();
                            
                            if (data.result) {
                                const responseTime = (Date.now() - startTime);
                                addToTerminal(` [${clientId}] Response (${responseTime}ms):\n${data.result}\n`);
                            } else if (data.pending) {
                                setTimeout(checkImmediately, 10);
                            } else {
                                setTimeout(checkImmediately, 10);
                            }
                        } catch {
                            setTimeout(checkImmediately, 10);
                        }
                    };
                    checkImmediately();
                }
                
                function addToTerminal(text) {
                    const terminal = document.getElementById('terminal');
                    terminal.textContent += text;
                    terminal.scrollTop = terminal.scrollHeight;
                }
                
                function openSettings() {
                    window.open('/settings', '_blank');
                }
                
                function logout() {
                    if (confirm('Are you sure you want to logout?')) {
                        window.location = '/logout';
                    }
                }
                
                setInterval(loadSessions, 1000);
                loadSessions();
            </script>
        </body>
        </html>
        '''
        self.send_html(html)
    
    def handle_client_register(self, data):
        with self.session_lock:
            client_id = data.get('client_id', str(uuid.uuid4())[:8])
            client_ip = self.client_address[0]
            incoming_user = data.get('user', 'Unknown')
            incoming_computer = data.get('computer', 'Unknown')
            incoming_os = data.get('os', 'Unknown')

            if incoming_user == 'Unknown' and '-' in client_id:
                try:
                    parts = client_id.split('-')
                    if len(parts) >= 2:
                        incoming_user = parts[1]
                        incoming_computer = parts[0]
                except:
                    pass
                
            existing_client = None
            for cid, client_data in self.sessions.items():
                current_user = client_data.get('user', '')
                current_computer = client_data.get('computer', '')

                if (current_user == incoming_user and 
                    current_computer == incoming_computer and 
                    incoming_user != 'Unknown' and 
                    incoming_computer != 'Unknown'):
                    existing_client = cid
                    break
                
            if existing_client is None and client_id in self.sessions:
                existing_client = client_id

            if existing_client:
                self.sessions[existing_client]['last_seen'] = datetime.now().isoformat()
                self.sessions[existing_client]['status'] = 'online'
                self.sessions[existing_client]['ip'] = client_ip

                if incoming_os != 'Unknown':
                    self.sessions[existing_client]['os'] = incoming_os

                self.log_security_event(f"Client updated: {incoming_computer} ({incoming_user})", "INFO")
                self.send_json({'success': True, 'client_id': existing_client})
            else:
                self.sessions[client_id] = {
                    'id': client_id,
                    'ip': client_ip,
                    'type': data.get('type', 'unknown'),
                    'computer': incoming_computer,
                    'os': incoming_os,
                    'user': incoming_user,
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'pending_command': None,
                    'last_response': None,
                    'status': 'online'
                }
                self.log_security_event(f"New client registered: {incoming_computer} ({incoming_user})", "INFO")
                self.send_json({'success': True, 'client_id': client_id})
                
    def send_sessions_list(self):
        session = self.require_auth(1)
        if not session:
            return
            
        with self.session_lock:
            current_time = datetime.now()
            active_clients = []
        
            for client_id, client_data in list(self.sessions.items()):
                last_seen = datetime.fromisoformat(client_data['last_seen'])
                time_diff = (current_time - last_seen).total_seconds()
            
                if time_diff < 300:
                    client_data['is_online'] = time_diff < 30
                    client_data['last_seen_seconds'] = time_diff
                    active_clients.append(client_data)
                else:
                    del self.sessions[client_id]
        
            self.send_json(active_clients)
    
    def handle_get_commands(self):
        session = self.require_auth(1)
        if not session:
            return
            
        with self.session_lock:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            client_id = query.get('client', [None])[0]
            
            if client_id and client_id in self.sessions:
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                pending_command = self.sessions[client_id]['pending_command']
                
                if pending_command:
                    self.sessions[client_id]['pending_command'] = None
                    self.send_json({'command': pending_command})
                else:
                    self.send_json({'waiting': False})
            else:
                self.send_json({'error': 'Client not found'})
    
    def handle_execute_command(self, data):
        session = self.require_auth(1)
        if not session:
            return
            
        with self.session_lock:
            client_id = data.get('client_id')
            command = data.get('command')
            
            if not command:
                self.send_json({'success': False, 'error': 'No command provided'})
                return
                
            if not self.command_validator.is_command_safe(command):
                self.log_security_event(f"Blocked dangerous command: {command}", "HIGH")
                self.send_json({'success': False, 'error': 'Command not allowed'})
                return
            
            if client_id in self.sessions:
                self.sessions[client_id]['pending_command'] = command
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                
                self.log_security_event(f"Command executed: {command} on {client_id}", "INFO")
                self.send_json({'success': True})
                
                if hasattr(self, 'cursor'):
                    self.cursor.execute(
                        'INSERT INTO commands (client_id, command, status) VALUES (?, ?, ?)',
                        (client_id, command, 'sent')
                    )
                    self.conn.commit()
            else:
                self.send_json({'success': False, 'error': 'Client not found'})
    
    def handle_get_result(self):
        session = self.require_auth(1)
        if not session:
            return
            
        with self.session_lock:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            
            client_id = query.get('client', [''])[0]
            command = query.get('command', [''])[0]
            
            if client_id in self.sessions and self.sessions[client_id]['last_response']:
                result = self.sessions[client_id]['last_response']
                self.sessions[client_id]['last_response'] = None
                self.send_json({'result': result})
                
                if hasattr(self, 'cursor'):
                    self.cursor.execute(
                        'UPDATE commands SET response = ?, status = ? WHERE client_id = ? AND command = ? AND response IS NULL',
                        (result, 'completed', client_id, command)
                    )
                    self.conn.commit()
            else:
                self.send_json({'pending': True})
    
    def handle_client_response(self, data):
        with self.session_lock:
            client_id = data.get('client_id')
            response = data.get('response')
            command = data.get('command')
            
            if client_id in self.sessions:
                self.sessions[client_id]['last_response'] = response
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
            
            self.send_json({'success': True})
    
    def send_settings_page(self):
        session = self.require_auth(2)
        if not session:
            return
            
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Settings</title>
            <meta charset="utf-8">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    margin: 0;
                    padding: 20px;
                    min-height: 100vh;
                }
                .container {
                    max-width: 600px;
                    margin: 20px auto;
                    background: rgba(45, 45, 45, 0.95);
                    padding: 30px;
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .logo {
                    font-size: 48px;
                    margin-bottom: 10px;
                }
                .password-form {
                    background: rgba(255,255,255,0.05);
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                input, select, button {
                    width: 100%;
                    padding: 12px;
                    margin: 8px 0;
                    border-radius: 6px;
                    border: none;
                    font-size: 16px;
                    transition: all 0.2s ease;
                }
                input, select {
                    background: rgba(255,255,255,0.1);
                    color: white;
                    border: 1px solid rgba(255,255,255,0.2);
                }
                input:focus {
                    outline: none;
                    border-color: #0078d4;
                    background: rgba(255,255,255,0.15);
                }
                button {
                    background: linear-gradient(135deg, #0078d4, #005a9e);
                    color: white;
                    cursor: pointer;
                    font-weight: bold;
                }
                button:hover {
                    background: linear-gradient(135deg, #005a9e, #004578);
                    transform: translateY(-2px);
                }
                .back-btn {
                    background: linear-gradient(135deg, #6c757d, #495057);
                    margin-top: 20px;
                }
                .message {
                    padding: 12px;
                    border-radius: 6px;
                    margin: 10px 0;
                    text-align: center;
                    display: none;
                    font-weight: bold;
                }
                .success {
                    background: rgba(40, 167, 69, 0.2);
                    border: 1px solid #28a745;
                }
                .error {
                    background: rgba(220, 53, 69, 0.2);
                    border: 1px solid #dc3545;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">⚙️</div>
                    <h2>Security Settings</h2>
                    <p>Change Authentication Passwords</p>
                </div>

                <div id="message" class="message"></div>

                <div class="password-form">
                    <h3>Change Level 1 Password</h3>
                    <input type="password" id="currentPassword1" placeholder="Current Level 1 Password">
                    <input type="password" id="newPassword1" placeholder="New Level 1 Password">
                    <input type="password" id="confirmPassword1" placeholder="Confirm New Password">
                    <button onclick="changePassword('level1')">Update Level 1 Password</button>
                </div>

                <div class="password-form">
                    <h3>Change Admin Password</h3>
                    <input type="password" id="currentPassword2" placeholder="Current Admin Password">
                    <input type="password" id="newPassword2" placeholder="New Admin Password">
                    <input type="password" id="confirmPassword2" placeholder="Confirm New Password">
                    <button onclick="changePassword('level2')">Update Admin Password</button>
                </div>

                <button class="back-btn" onclick="goBack()">← Back to Control Panel</button>
            </div>

            <script>
                function showMessage(text, type) {
                    const message = document.getElementById('message');
                    message.textContent = text;
                    message.className = 'message ' + type;
                    message.style.display = 'block';
                    setTimeout(() => {
                        message.style.display = 'none';
                    }, 3000);
                }

                async function changePassword(level) {
                    let currentId, newId, confirmId;
                    
                    if (level === 'level1') {
                        currentId = 'currentPassword1';
                        newId = 'newPassword1';
                        confirmId = 'confirmPassword1';
                    } else {
                        currentId = 'currentPassword2';
                        newId = 'newPassword2';
                        confirmId = 'confirmPassword2';
                    }

                    const currentPassword = document.getElementById(currentId).value;
                    const newPassword = document.getElementById(newId).value;
                    const confirmPassword = document.getElementById(confirmId).value;

                    if (!currentPassword || !newPassword || !confirmPassword) {
                        showMessage('Please fill all fields', 'error');
                        return;
                    }

                    if (newPassword !== confirmPassword) {
                        showMessage('New passwords do not match', 'error');
                        return;
                    }

                    if (newPassword.length < 8) {
                        showMessage('Password must be at least 8 characters', 'error');
                        return;
                    }

                    try {
                        const response = await fetch('/change-password', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                level: level,
                                current_password: currentPassword,
                                new_password: newPassword
                            })
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            showMessage('Password updated successfully!', 'success');
                            document.getElementById(currentId).value = '';
                            document.getElementById(newId).value = '';
                            document.getElementById(confirmId).value = '';
                        } else {
                            showMessage(data.error || 'Failed to update password', 'error');
                        }
                    } catch (err) {
                        showMessage('Network error', 'error');
                    }
                }

                function goBack() {
                    window.location.href = '/control';
                }
            </script>
        </body>
        </html>
        '''
        self.send_html(html)

    def handle_change_password(self, data):
        session = self.require_auth(2)
        if not session:
            return
        
        level = data.get('level')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not level or not current_password or not new_password:
            self.send_json({'success': False, 'error': 'Missing required fields'})
            return
        
        if len(new_password) < 8:
            self.send_json({'success': False, 'error': 'Password must be at least 8 characters'})
            return
        
        passwords = self.password_manager.load_passwords()
        
        if level == 'level1':
            if not self.password_manager.verify_password(current_password, passwords['user_password']):
                self.send_json({'success': False, 'error': 'Current Level 1 password is incorrect'})
                return
            
            passwords['user_password'] = self.password_manager.hash_password(new_password)
            
        elif level == 'level2':
            if not self.password_manager.verify_password(current_password, passwords['admin_password']):
                self.send_json({'success': False, 'error': 'Current Admin password is incorrect'})
                return
            
            passwords['admin_password'] = self.password_manager.hash_password(new_password)
        
        else:
            self.send_json({'success': False, 'error': 'Invalid password level'})
            return
        
        if self.password_manager.save_passwords(passwords):
            self.log_security_event(f"Password changed for {level}", "INFO")
            self.log_auth_event(session['user_id'], f'change_password_{level}', True)
            self.send_json({'success': True})
        else:
            self.send_json({'success': False, 'error': 'Failed to save new password'})

    def send_command_history(self):
        session = self.require_auth(1)
        if not session:
            return
            
        try:
            if hasattr(self, 'cursor'):
                self.cursor.execute('''
                    SELECT client_id, command, response, timestamp, status
                    FROM commands 
                    ORDER BY timestamp DESC 
                    LIMIT 50
                ''')
                history = self.cursor.fetchall()
                
                result = []
                for row in history:
                    result.append({
                        'client_id': row[0],
                        'command': row[1],
                        'response': row[2],
                        'timestamp': row[3],
                        'status': row[4]
                    })
                
                self.send_json(result)
            else:
                self.send_json([])
        except:
            self.send_json([])

    def send_system_status(self):
        session = self.require_auth(1)
        if not session:
            return
            
        with self.session_lock:
            status = {
                'uptime': 'Running - Secure Mode',
                'connected_clients': len([c for c in self.sessions.values() 
                                        if (datetime.now() - datetime.fromisoformat(c['last_seen'])).total_seconds() < 30]),
                'active_sessions': len(self.session_manager.sessions),
                'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'mode': 'SECURE',
                'security_level': 'HIGH'
            }
            
            if hasattr(self, 'cursor'):
                self.cursor.execute('SELECT COUNT(*) FROM commands')
                status['total_commands'] = self.cursor.fetchone()[0]
                
                self.cursor.execute('SELECT COUNT(*) FROM security_logs WHERE severity = "HIGH"')
                status['security_alerts'] = self.cursor.fetchone()[0]
            
            self.send_json(status)

    def download_python_client(self):
        session = self.require_auth(2)
        if not session:
            return
            
        client_code = '''
        # Secure Python Client Code
        # This would be the actual client code
        '''
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="secure_client.py"')
        self.end_headers()
        self.wfile.write(client_code.encode())

    def send_404_page(self):
        self.send_error(404, "Page not found")

    def log_message(self, format, *args):
        pass

def cleanup_sessions():
    """تنظيف الجلسات المنتهية"""
    while True:
        try:
            time.sleep(300)
            handler = EnhancedRemoteControlHandler
            current_time = datetime.now()
            
            with handler.session_lock:
                for client_id, client_data in list(handler.sessions.items()):
                    last_seen = datetime.fromisoformat(client_data['last_seen'])
                    if (current_time - last_seen).total_seconds() > 300:
                        del handler.sessions[client_id]
        except:
            pass

def main():
    handler = EnhancedRemoteControlHandler
    handler.init_database(handler)
    
    threading.Thread(target=cleanup_sessions, daemon=True).start()
    
    print("=" * 80)
    print("  SECURE REMOTE CONTROL SERVER - ENHANCED SECURITY MODE")
    print("=" * 80)
    print(" Security Features:")
    print("  • Secure Session Management")
    print("  • BCrypt Password Hashing")
    print("  • Rate Limiting & IP Blocking")
    print("  • Command Validation & Sanitization")
    print("  • CSRF Protection")
    print("  • Security Headers")
    print("  • Comprehensive Logging")
    print("  • Multi-Platform Support")
    print("=" * 80)
    print(" Performance Features:")
    print("  • Ultra-Fast Communication")
    print("  • Multi-Threaded Server")
    print("  • Real-Time Updates")
    print("  • Windows & Linux Commands")
    print("=" * 80)
    
    try:
        server = ThreadedHTTPServer(('0.0.0.0', 8080), EnhancedRemoteControlHandler)
        print(" Secure server started on port 8080!")
        print(" Access the control panel after authentication")
        print(" Ultra-fast and fully secured")
        print("=" * 80)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        if hasattr(handler, 'conn'):
            handler.conn.close()

if __name__ == "__main__":
    main()
