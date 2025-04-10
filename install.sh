#!/bin/bash

# VoIP Monitor Installation Script
# This script installs the VoIP phone monitoring service

# Parse command line arguments
SILENT_INSTALL=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -s|--silent) SILENT_INSTALL=true ;;
        -h|--help) 
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -s, --silent     Silent package installation (reduces output)"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

set -e  # Exit on any error

# Print colored status messages
function echo_status() {
    echo -e "\e[1;34m>>> $1\e[0m"
}

# Print error messages
function echo_error() {
    echo -e "\e[1;31m!!! ERROR: $1\e[0m" >&2
}

# Print prompts for user input
function echo_prompt() {
    echo -e "\e[1;32m??? $1\e[0m"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo_error "This script must be run as root"
    exit 1
fi

echo_status "Starting VoIP Monitor installation"

# Update system and install dependencies
echo_status "Updating system and installing dependencies"
if [ "$SILENT_INSTALL" = true ]; then
    # Silent installation of packages
    apt update -qq > /dev/null
    apt install -y -qq python3 python3-pip python3-venv arp-scan > /dev/null
else
    # Normal installation with output
    apt update
    apt install -y python3 python3-pip python3-venv arp-scan
fi

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
if [ "$SILENT_INSTALL" = true ]; then
    pip install -q requests pyyaml urllib3 > /dev/null
else
    pip install requests pyyaml urllib3
fi

# Interactive configuration
echo_status "Setting up configuration"

# Copy the example config as a starting point
if [ -f "config.yaml.example" ]; then
    cp config.yaml.example config.yaml
else
    echo_error "config.yaml.example not found. Cannot create configuration."
    exit 1
fi

# Prompt for phone credentials
echo_prompt "Let's configure phone authentication credentials"
echo_prompt "Enter username for phone access (default: admin):"
read -r phone_username
phone_username=${phone_username:-admin}

echo_prompt "Enter password for phone access (default: admin):"
read -r phone_password
phone_password=${phone_password:-admin}

echo_prompt "Enter a second password to try (optional):"
read -r phone_password2

echo_prompt "Enter a third password to try (optional):"
read -r phone_password3

# Update auth_options in config.yaml
sed -i '/auth_options:/,/^[a-z]/ { /auth_options:/!{ /^[a-z]/!d } }' config.yaml
echo "auth_options:" >> config.yaml
echo "  - username: $phone_username" >> config.yaml
echo "    password: $phone_password" >> config.yaml

if [ -n "$phone_password2" ]; then
    echo "  - username: $phone_username" >> config.yaml
    echo "    password: $phone_password2" >> config.yaml
fi

if [ -n "$phone_password3" ]; then
    echo "  - username: $phone_username" >> config.yaml
    echo "    password: $phone_password3" >> config.yaml
fi

# Prompt for notification emails
echo_prompt "Let's configure notification emails"
echo_prompt "Enter email addresses to receive notifications (comma-separated):"
read -r notification_emails

# Convert comma-separated emails to list
IFS=',' read -ra email_array <<< "$notification_emails"

# Update notification_email in config.yaml
sed -i '/notification_email:/,/^[a-z]/ { /notification_email:/!{ /^[a-z]/!d } }' config.yaml
echo "notification_email:" >> config.yaml
for email in "${email_array[@]}"; do
    # Trim whitespace
    email=$(echo "$email" | xargs)
    echo "  - $email" >> config.yaml
done

# Prompt for SMTP configuration
echo_prompt "Let's configure SMTP settings for sending notifications"
echo_prompt "Enter SMTP server address:"
read -r smtp_server

echo_prompt "Enter SMTP port (default: 587):"
read -r smtp_port
smtp_port=${smtp_port:-587}

echo_prompt "Enter SMTP username (email address for authentication):"
read -r smtp_username

echo_prompt "Enter SMTP password:"
read -r smtp_password

# Update SMTP configuration in config.yaml
sed -i '/smtp:/,/^[a-z]/ { /smtp:/!{ /^[a-z]/!d } }' config.yaml
echo "smtp:" >> config.yaml
echo "  server: $smtp_server" >> config.yaml
echo "  port: $smtp_port" >> config.yaml
echo "  username: $smtp_username" >> config.yaml
echo "  password: $smtp_password" >> config.yaml

echo_status "Configuration updated successfully!"

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
if [ "$SILENT_INSTALL" = true ]; then
    systemctl daemon-reload > /dev/null
    systemctl enable voip-monitor.service > /dev/null 2>&1
    systemctl start voip-monitor.service > /dev/null
else
    systemctl daemon-reload
    systemctl enable voip-monitor.service
    systemctl start voip-monitor.service
fi

# Always show service status at the end
systemctl status voip-monitor.service

echo_status "Installation complete!"
echo_status "Configuration has been saved to $INSTALL_DIR/config.yaml"
echo_status "View logs with: sudo journalctl -u voip-monitor.service -f"