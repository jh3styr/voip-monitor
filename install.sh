#!/bin/bash

# VoIP Monitor Installation Script
# This script installs the VoIP phone monitoring service

set -e  # Exit on any error

# Print colored status messages
function echo_status() {
    echo -e "\e[1;34m>>> $1\e[0m"
}

# Print error messages
function echo_error() {
    echo -e "\e[1;31m!!! ERROR: $1\e[0m"
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

# Interactive configuration
echo_status "Setting up configuration"

# Copy the example config as a starting point
if [ -f "config.yaml.example" ]; then
    cp config.yaml.example config.yaml
else
    echo_error "config.yaml.example not found. Cannot create configuration."
    exit 1
fi

# Function to update YAML values
update_yaml() {
    local file=$1
    local key=$2
    local value=$3
    local indent=$4
    
    # Escape special characters for sed
    value=$(echo "$value" | sed 's/[\/&]/\\&/g')
    
    # Check if key exists and update it, otherwise append it
    if grep -q "^${indent}${key}:" "$file"; then
        sed -i "s/^${indent}${key}:.*/${indent}${key}: $value/" "$file"
    else
        echo "${indent}${key}: $value" >> "$file"
    fi
}

# Function to update YAML list values
update_yaml_list() {
    local file=$1
    local key=$2
    local values=$3
    local indent=$4
    
    # Remove existing list entries
    sed -i "/^${indent}${key}:/,/^${indent}[a-z]/ { /^${indent}${key}:/!{ /^${indent}[a-z]/!d } }" "$file"
    
    # Check if key exists
    if grep -q "^${indent}${key}:" "$file"; then
        # Key exists, add new values
        for value in $values; do
            # Escape special characters for sed
            escaped_value=$(echo "$value" | sed 's/[\/&]/\\&/g')
            sed -i "/^${indent}${key}:/a\\${indent}  - $escaped_value" "$file"
        done
    else
        # Key doesn't exist, add it with values
        echo "${indent}${key}:" >> "$file"
        for value in $values; do
            echo "${indent}  - $value" >> "$file"
        done
    fi
}

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
systemctl daemon-reload
systemctl enable voip-monitor.service
systemctl start voip-monitor.service

# Check service status
echo_status "Checking service status"
systemctl status voip-monitor.service

echo_status "Installation complete!"
echo_status "Configuration has been saved to $INSTALL_DIR/config.yaml"
echo_status "View logs with: sudo journalctl -u voip-monitor.service -f"