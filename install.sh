#!/bin/bash

# Yealink Monitor Installation Script
# This script installs the Yealink phone monitoring service

set -e  # Exit on any error

# Print colored status messages
function echo_status() {
    echo -e "\e[1;34m>>> $1\e[0m"
}

# Print error messages
function echo_error() {
    echo -e "\e[1;31m!!! ERROR: $1\e[0m"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo_error "This script must be run as root"
    exit 1
fi

echo_status "Starting Yealink Monitor installation"

# Update system and install dependencies
echo_status "Updating system and installing dependencies"
apt update
apt install -y python3 python3-pip python3-venv arp-scan

# Create installation directory
echo_status "Creating installation directory"
INSTALL_DIR="/opt/voip-monitor"
mkdir -p $INSTALL_DIR

# Copy files to installation directory
echo_status "Copying files to installation directory"
cp -r ./* $INSTALL_DIR/

# Set up Python virtual environment
echo_status "Setting up Python virtual environment"
cd $INSTALL_DIR
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo_status "Installing Python dependencies"
pip install requests pyyaml urllib3

# Create config if it doesn't exist
if [ ! -f "$INSTALL_DIR/config.yaml" ] && [ -f "$INSTALL_DIR/config.yaml.example" ]; then
    echo_status "Creating initial configuration file"
    cp config.yaml.example config.yaml
    echo_status "Please edit $INSTALL_DIR/config.yaml to configure your settings"
fi

# Make the script executable
echo_status "Making the script executable"
chmod +x voip-monitor.py

# Create systemd service file
echo_status "Creating systemd service file"
cat > /etc/systemd/system/voip-monitor.service << 'EOSVC'
[Unit]
Description=VoIP Phone Monitoring Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/voip-monitor
ExecStart=/opt/voip-monitor/venv/bin/python /opt/voip-monitor/voip-monitor.py
Environment="PYTHONUNBUFFERED=1"
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=voip-monitor

[Install]
WantedBy=multi-user.target
EOSVC

# Enable and start the service
echo_status "Enabling and starting the service"
systemctl daemon-reload
systemctl enable voip-monitor.service
systemctl start voip-monitor.service

# Check service status
echo_status "Checking service status"
systemctl status voip-monitor.service

echo_status "Installation complete!"
echo_status "You should edit the configuration file at $INSTALL_DIR/config.yaml"
echo_status "to update email notifications and authentication settings."
echo_status "View logs with: sudo journalctl -u voip-monitor.service -f"

chmod +x install.sh
