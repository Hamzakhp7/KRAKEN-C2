#!/bin/bash

# HAMZA SKU C2 - Installation Script
# النسخة الاحترافية

echo "=========================================="
echo "🔥 HAMZA SKU C2 Dashboard - Installer"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   echo "Please run: sudo bash install.sh"
   exit 1
fi

print_info "Starting installation..."
echo ""

# Check Python version
print_info "Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    print_success "Python $PYTHON_VERSION found"
else
    print_error "Python 3 is not installed"
    print_info "Installing Python 3..."
    apt-get update
    apt-get install -y python3 python3-pip
fi

# Check Metasploit
print_info "Checking Metasploit Framework..."
if command -v msfconsole &> /dev/null; then
    MSF_VERSION=$(msfconsole -v | head -1)
    print_success "Metasploit found: $MSF_VERSION"
else
    print_error "Metasploit Framework is not installed"
    print_info "Please install Metasploit first:"
    echo "  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall"
    echo "  chmod 755 msfinstall"
    echo "  ./msfinstall"
    exit 1
fi

# Install Python dependencies
print_info "Installing Python dependencies..."
if pip3 install -r requirements.txt --break-system-packages; then
    print_success "Python dependencies installed"
else
    print_error "Failed to install dependencies"
    exit 1
fi

# Create directories
print_info "Creating necessary directories..."
mkdir -p downloads logs screenshots
chmod 755 downloads logs screenshots
print_success "Directories created"

# Check if msfrpcd is running
print_info "Checking msfrpcd status..."
if pgrep -x "msfrpcd" > /dev/null; then
    print_info "msfrpcd is already running"
else
    print_info "Starting msfrpcd..."
    msfrpcd -P msf_password -S -a 127.0.0.1 &
    sleep 3
    
    if pgrep -x "msfrpcd" > /dev/null; then
        print_success "msfrpcd started successfully"
    else
        print_error "Failed to start msfrpcd"
        print_info "You can start it manually:"
        echo "  msfrpcd -P msf_password -S -a 127.0.0.1"
    fi
fi

# Test installation
print_info "Testing installation..."
if python3 -c "import flask, flask_socketio, pymetasploit3" 2>/dev/null; then
    print_success "All dependencies working"
else
    print_error "Some dependencies are missing"
    exit 1
fi

echo ""
echo "=========================================="
print_success "Installation completed successfully!"
echo "=========================================="
echo ""
print_info "To start the dashboard:"
echo "  1. Make sure msfrpcd is running:"
echo "     msfrpcd -P msf_password -S -a 127.0.0.1"
echo ""
echo "  2. Start the server:"
echo "     python3 server.py"
echo ""
echo "  3. Open browser:"
echo "     http://localhost:5000"
echo ""
echo "  4. Login with:"
echo "     Password: hamza_sku_2026"
echo ""
print_info "For full guide, read GUIDE.md"
echo ""
echo "🔥 HAMZA SKU C2 - Ready to use!"
