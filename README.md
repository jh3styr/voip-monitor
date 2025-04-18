# Yealink Phone Monitor

A monitoring service that automatically discovers and monitors Yealink IP phones on your network, sending alerts when phones go offline.

## Features

- Automatic discovery of Yealink phones using MAC address prefixes
- Multiple authentication options for accessing phone APIs
- Email notifications when phones go offline
- Detailed logging and status reporting

## Installation

### Option 1: Clone the Repository and Install

```bash
# Clone the repository
git clone https://github.com/jh3styr/voip-monitor.git
cd voip-monitor

# Run the installation script
./install.sh
```

### Option 2: One-Line Installation (if you trust the source)

```bash
git clone https://github.com/jh3styr/voip-monitor.git /tmp/voip-monitor && cd /tmp/voip-monitor && chmod +x install.sh && ./install.sh
```

## Configuration

After installation, edit the configuration file:

```bash
nano /opt/voip-monitor/config.yaml
```

Key configuration options:
- `yealink_mac_prefixes`: MAC address prefixes for your Yealink phones
- `auth_options`: Username/password combinations to try when connecting to phones
- `notification_email`: Email address(es) to receive alerts
- `smtp`: SMTP server configuration for sending emails

## Updating

To update to the latest version:

```bash
cd /opt/voip-monitor
git pull
systemctl restart voip-monitor.service
```

## Viewing Logs

```bash
journalctl -u voip-monitor.service -f
```

## Configuration File Example

```yaml
# Check interval in seconds
check_interval: 300

# MAC address scan interval in seconds (default: 3600 = 1 hour)
mac_scan_interval: 3600

# Enable debug logging
debug: true

# Yealink MAC address prefixes
yealink_mac_prefixes:
  - '80:5E:0C'  # Common Yealink prefix
  - '00:15:65'  # Another Yealink prefix
  - '24:9A:D8'  # Another Yealink prefix

# Default settings for discovered endpoints
default_protocol: https
default_port: 443
default_path: /api/status

# Authentication options for accessing phone APIs
# The script will try each option in order until one works
auth_options:
  - username: admin
    password: admin
  - username: admin
    password: admin123
  - username: admin
    password: password

# Notification emails (can be a single email or a list)
notification_email:
  - admin@example.com
  # Add more email addresses as needed

# SMTP configuration for sending emails
smtp:
  server: smtp.example.com
  port: 587
  username: alerts@example.com
  password: your_smtp_password
```
