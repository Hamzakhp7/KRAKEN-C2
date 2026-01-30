#!/usr/bin/env python3
# HAMZA SKU C2 - Launcher

import os
import sys
import subprocess
import time

def check_dependencies():
    """تحقق من تثبيت المتطلبات"""
    print("🔍 Checking dependencies...")
    
    try:
        import flask
        import pymetasploit3
        print("✅ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        
        # تثبيت المتطلبات
        print("📦 Installing requirements...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "Flask", "pymetasploit3"])
        
        print("✅ Requirements installed successfully")
        return True

def start_msfrpcd():
    """تشغيل msfrpcd"""
    print("🚀 Starting msfrpcd...")
    
    try:
        # محاولة إيقاف أي عملية msfrpcd قيد التشغيل
        subprocess.run(['pkill', '-f', 'msfrpcd'], capture_output=True)
        time.sleep(1)
        
        # تشغيل msfrpcd جديد
        process = subprocess.Popen([
            'msfrpcd', '-P', 'msf_password', 
            '-S', '-a', '127.0.0.1', '-p', '55553'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        time.sleep(3)
        
        # التحقق من التشغيل
        check = subprocess.run(['pgrep', '-f', 'msfrpcd'], capture_output=True)
        if check.returncode == 0:
            print("✅ msfrpcd started successfully")
            return True
        else:
            print("❌ Failed to start msfrpcd")
            return False
            
    except Exception as e:
        print(f"❌ Error starting msfrpcd: {e}")
        return False

def main():
    """الدالة الرئيسية"""
    print("""
╔═══════════════════════════════════════════════════╗
║        HAMZA SKU C2 - Professional Edition        ║
║           Command & Control System                ║
╚═══════════════════════════════════════════════════╝
    """)
    
    # التحقق من المتطلبات
    if not check_dependencies():
        return
    
    # تشغيل msfrpcd
    print("\n" + "="*50)
    if not start_msfrpcd():
        print("\n⚠️  Make sure Metasploit is installed:")
        print("   sudo apt-get install metasploit-framework")
        print("\n🔧 Manual command to start msfrpcd:")
        print("   msfrpcd -P msf_password -S -a 127.0.0.1")
        print("\nPress Enter to continue anyway...")
        input()
    
    # تشغيل السيرفر
    print("\n" + "="*50)
    print("🌐 Starting HAMZA SKU C2 Server...")
    
    try:
        import server
        print("\n✅ Server is running!")
        print("\n🌐 Open in browser: http://localhost:5000")
        print("🔑 Password: hamza_sku_2026")
        print("\n📢 Press Ctrl+C to stop the server")
        
        # تشغيل السيرفر
        server.socketio.run(server.app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
        
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == '__main__':
    main()