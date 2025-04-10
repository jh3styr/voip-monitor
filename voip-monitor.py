#!/usr/bin/env python3
import requests
import smtplib
import logging
import time
import yaml
import urllib3
import subprocess
import re
import os
import socket
import json
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from requests.exceptions import RequestException

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("yealink_monitor.log"),
        logging.StreamHandler()
    ]
)

def load_config(config_file="config.yaml"):
    """Load configuration from YAML file"""
    try:
        with open(config_file, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        raise

def save_config(config, config_file="config.yaml"):
    """Save configuration to YAML file"""
    try:
        with open(config_file, 'w') as file:
            yaml.dump(config, file, default_flow_style=False)
        logging.info(f"Configuration saved to {config_file}")
        return True
    except Exception as e:
        logging.error(f"Failed to save configuration: {e}")
        return False

def get_local_subnet():
    """Get the local subnet for scanning"""
    try:
        # Get the default route interface
        route_cmd = subprocess.run(
            ["ip", "route", "show", "default"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        default_interface = route_cmd.stdout.split()[4]
        
        # Get the IP address of that interface
        ip_cmd = subprocess.run(
            ["ip", "-f", "inet", "addr", "show", default_interface], 
            capture_output=True, 
            text=True, 
            check=True
        )
        ip_output = ip_cmd.stdout
        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', ip_output)
        
        if ip_match:
            ip = ip_match.group(1)
            subnet_prefix = ip.rsplit('.', 1)[0]
            return subnet_prefix
        else:
            logging.warning("Could not determine local subnet, using 192.168.1 as default")
            return "192.168.1"
    except Exception as e:
        logging.error(f"Error determining local subnet: {e}")
        logging.warning("Using 192.168.1 as default subnet")
        return "192.168.1"

def normalize_mac(mac):
    """Normalize MAC address format to uppercase with colons"""
    if not mac:
        return None
    
    # Remove all separators and whitespace
    mac = re.sub(r'[^0-9a-fA-F]', '', mac)
    
    # Ensure we have 12 hex characters
    if len(mac) != 12:
        return None
    
    # Format with colons
    return ':'.join(mac[i:i+2].upper() for i in range(0, 12, 2))

def mac_matches_prefix(mac, prefix):
    """Check if a MAC address matches a prefix, with flexible matching"""
    # Normalize both MAC and prefix
    norm_mac = normalize_mac(mac)
    if not norm_mac:
        return False
    
    # Handle different prefix formats
    # Remove any separators from the prefix
    clean_prefix = re.sub(r'[^0-9a-fA-F]', '', prefix.upper())
    
    # Check if the MAC starts with the prefix (ignoring separators)
    clean_mac = re.sub(r'[^0-9a-fA-F]', '', norm_mac)
    
    result = clean_mac.startswith(clean_prefix)
    
    # Add detailed debug logging
    logging.debug(f"MAC prefix check: MAC={norm_mac}, Prefix={prefix}, " +
                 f"Clean MAC={clean_mac}, Clean Prefix={clean_prefix}, Match={result}")
    
    return result

def analyze_network_macs(subnet=None):
    """
    Scan the network and analyze MAC addresses to help identify Yealink devices
    """
    if subnet is None:
        subnet = get_local_subnet()
    
    logging.info(f"Analyzing MAC addresses on subnet {subnet}.*")
    
    try:
        # Run arp-scan
        scan_cmd = subprocess.run(
            ["arp-scan", f"{subnet}.0/24"], 
            capture_output=True, 
            text=True
        )
        
        # Group devices by MAC prefix (first 3 octets)
        prefix_groups = {}
        
        for line in scan_cmd.stdout.splitlines():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})\s+(.*)', line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                vendor = match.group(3).strip()
                
                # Normalize the MAC address
                norm_mac = normalize_mac(mac)
                if not norm_mac:
                    continue
                
                # Extract the prefix (first 3 octets)
                prefix = ':'.join(norm_mac.split(':')[:3])
                
                if prefix not in prefix_groups:
                    prefix_groups[prefix] = []
                
                prefix_groups[prefix].append({
                    'ip': ip,
                    'mac': norm_mac,
                    'vendor': vendor
                })
        
        # Log the results
        logging.info("MAC prefix analysis results:")
        for prefix, devices in prefix_groups.items():
            vendors = set(device['vendor'] for device in devices)
            logging.info(f"Prefix {prefix}: {len(devices)} devices, Vendors: {', '.join(vendors)}")
            
            # If any vendor name contains "YEALINK", highlight it
            if any('YEALINK' in vendor.upper() for vendor in vendors):
                logging.info(f"*** POTENTIAL YEALINK PREFIX: {prefix} ***")
                for device in devices:
                    logging.info(f"  - IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}")
        
        return prefix_groups
    
    except Exception as e:
        logging.error(f"Error analyzing network MACs: {e}")
        return {}

def scan_network_for_macs(mac_prefixes, subnet=None):
    """
    Scan the network for devices with specific MAC address prefixes
    Returns a dictionary mapping MAC addresses to IP addresses
    """
    if subnet is None:
        subnet = get_local_subnet()
    
    logging.info(f"Scanning subnet {subnet}.* for Yealink devices")
    logging.info(f"Looking for MAC prefixes: {mac_prefixes}")
    
    # Run arp-scan to find devices on the network
    try:
        # Check if arp-scan is installed
        subprocess.run(["which", "arp-scan"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Run arp-scan
        scan_cmd = subprocess.run(
            ["arp-scan", f"{subnet}.0/24"], 
            capture_output=True, 
            text=True
        )
        
        if scan_cmd.returncode != 0:
            logging.warning(f"arp-scan returned non-zero exit code: {scan_cmd.returncode}")
            logging.warning(f"Error output: {scan_cmd.stderr}")
        
        # Parse the output
        mac_to_ip = {}
        
        # Log the raw output for debugging
        logging.debug(f"arp-scan raw output: {scan_cmd.stdout}")
        
        for line in scan_cmd.stdout.splitlines():
            # Log each line for debugging
            logging.debug(f"Processing line: {line}")
            
            # Look for lines with IP and MAC addresses
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17}|[0-9a-fA-F-]{17})', line)
            if match:
                ip = match.group(1)
                mac = match.group(2)
                
                # Normalize the MAC address
                norm_mac = normalize_mac(mac)
                if not norm_mac:
                    continue
                
                logging.debug(f"Found device: IP={ip}, MAC={mac}, Normalized MAC={norm_mac}")
                
                # Check if this MAC matches any of our prefixes
                for prefix in mac_prefixes:
                    if mac_matches_prefix(norm_mac, prefix):
                        mac_to_ip[norm_mac] = ip
                        logging.info(f"Found Yealink device with MAC {norm_mac} at IP {ip} (matches prefix {prefix})")
                        break
        
        # Log summary
        if mac_to_ip:
            logging.info(f"Found {len(mac_to_ip)} Yealink devices: {mac_to_ip}")
        else:
            logging.warning("No Yealink devices found with the specified MAC prefixes")
        
        return mac_to_ip
    
    except subprocess.CalledProcessError:
        logging.error("arp-scan not found. Please install it with: sudo apt install arp-scan")
        return {}
    except Exception as e:
        logging.error(f"Error scanning network: {e}")
        return {}

def get_phone_info(ip, protocol, port, auth_options=None):
    """
    Get information about the phone including registered username/extension
    Tries multiple authentication options if provided
    Returns a dictionary with phone information
    """
    phone_info = {
        "ip": ip,
        "extension": None,
        "display_name": None,
        "model": None,
        "mac": None,
        "status": "unknown"
    }
    
    # Different Yealink models have different API endpoints
    api_paths = [
        "/api/v1/system/status",  # Newer models
        "/servlet?m=mod_data&p=status",  # Older models
        "/cgi-bin/cgiServer.exx?page=status",  # Some models
        "/api/status"  # Generic endpoint
    ]
    
    # If no auth options provided, try without authentication
    if not auth_options:
        auth_options = [None]
    elif isinstance(auth_options, dict):
        auth_options = [auth_options]  # Convert single auth to list
    
    # Try each authentication option
    for auth in auth_options:
        headers = {}
        if auth:
            # Add basic authentication
            auth_string = f"{auth['username']}:{auth['password']}"
            encoded_auth = base64.b64encode(auth_string.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_auth}"
            logging.debug(f"Trying authentication with username: {auth['username']}")
        else:
            logging.debug("Trying without authentication")
        
        # Try each API path
        for path in api_paths:
            try:
                url = f"{protocol}://{ip}:{port}{path}"
                response = requests.get(url, headers=headers, timeout=5, verify=False)
                
                if response.status_code == 200:
                    logging.debug(f"Successful connection to {url}" + 
                                 (f" with user {auth['username']}" if auth else " without auth"))
                    
                    # Try to parse the response as JSON
                    try:
                        data = response.json()
                        phone_info["status"] = "online"
                        
                        # Extract information based on the API response format
                        if "account" in data:
                            account = data["account"]
                            if isinstance(account, list) and len(account) > 0:
                                phone_info["extension"] = account[0].get("user_name", "")
                                phone_info["display_name"] = account[0].get("display_name", "")
                        elif "accounts" in data:
                            accounts = data["accounts"]
                            if isinstance(accounts, list) and len(accounts) > 0:
                                phone_info["extension"] = accounts[0].get("username", "")
                                phone_info["display_name"] = accounts[0].get("display_name", "")
                        
                        # Try to get model information
                        if "device" in data:
                            phone_info["model"] = data["device"].get("model", "")
                            phone_info["mac"] = data["device"].get("mac", "")
                        
                        return phone_info
                    except json.JSONDecodeError:
                        # If it's not JSON, try to parse HTML or text response
                        content = response.text
                        
                        # Look for extension in the content
                        ext_match = re.search(r'Extension:\s*(\d+)', content)
                        if ext_match:
                            phone_info["extension"] = ext_match.group(1)
                        
                        # Look for display name
                        name_match = re.search(r'Display Name:\s*([^<\n]+)', content)
                        if name_match:
                            phone_info["display_name"] = name_match.group(1).strip()
                        
                        # Look for model
                        model_match = re.search(r'Model:\s*([^<\n]+)', content)
                        if model_match:
                            phone_info["model"] = model_match.group(1).strip()
                        
                        phone_info["status"] = "online"
                        return phone_info
                elif response.status_code == 401:
                    # Authentication failed, try next auth option
                    logging.debug(f"Authentication failed for {url}" + 
                                 (f" with user {auth['username']}" if auth else " without auth"))
                    break  # Try next auth option
            
            except Exception as e:
                logging.debug(f"Failed to get info from {url}: {e}")
                continue
    
    # If we couldn't get detailed info but the phone is reachable
    try:
        url = f"{protocol}://{ip}:{port}"
        response = requests.get(url, timeout=3, verify=False)
        if response.status_code == 200:
            phone_info["status"] = "online"
        elif response.status_code == 401:
            # Authentication required but we couldn't authenticate
            phone_info["status"] = "auth_required"
    except Exception:
        phone_info["status"] = "offline"
    
    return phone_info

def update_endpoints_from_discovered_macs(config, mac_to_ip):
    """
    Update the endpoints in the config based on discovered MAC-to-IP mappings
    Automatically creates endpoint URLs for all discovered Yealink devices
    """
    if not mac_to_ip:
        logging.warning("No Yealink devices discovered, skipping endpoint update")
        return False
    
    updated = False
    
    # Get default endpoint settings
    default_protocol = config.get('default_protocol', 'https')
    default_port = config.get('default_port', 443)
    default_port = config.get('default_port', 443 if default_protocol == 'https' else 80)
    default_path = config.get('default_path', '/api/status')
    
    # Get authentication options if available
    auth_options = config.get('auth_options', [])
    if not auth_options and 'auth' in config:
        # For backward compatibility
        auth_options = [config['auth']]
    
    # Create or initialize the endpoints dictionary
    if 'endpoints' not in config or not isinstance(config['endpoints'], dict):
        config['endpoints'] = {}
    
    # Track discovered devices
    discovered_devices = {}
    
    # Process each discovered device
    for mac, ip in mac_to_ip.items():
        # Get phone information including extension
        phone_info = get_phone_info(ip, default_protocol, default_port, auth_options)
        
        # Create endpoint URL
        endpoint_url = f"{default_protocol}://{ip}:{default_port}{default_path}"
        
        # Store device information
        discovered_devices[mac] = {
            "ip": ip,
            "url": endpoint_url,
            "extension": phone_info["extension"],
            "display_name": phone_info["display_name"],
            "model": phone_info["model"],
            "status": phone_info["status"]
        }
        
        # Check if this is a new or updated endpoint
        if mac not in config['endpoints'] or config['endpoints'][mac]['ip'] != ip:
            logging.info(f"Adding/updating endpoint: {endpoint_url} (MAC: {mac}, Extension: {phone_info['extension']})")
            updated = True
    
    # Update the endpoints dictionary with all discovered devices
    config['endpoints'] = discovered_devices
    
    return updated

def check_endpoint(endpoint_info, timeout=5):
    """Check if an endpoint is available"""
    url = endpoint_info.get('url')
    if not url:
        return False
    
    try:
        # Disable SSL certificate verification
        response = requests.get(url, timeout=timeout, verify=False)
        if response.status_code == 200:
            logging.info(f"Endpoint {url} is available")
            return True
        else:
            logging.warning(f"Endpoint {url} returned status code {response.status_code}")
            return False
    except RequestException as e:
        logging.error(f"Failed to connect to {url}: {e}")
        return False

def send_email_notifications(smtp_config, recipients, subject, message):
    """Send email notifications to multiple recipients"""
    if isinstance(recipients, str):
        recipients = [recipients]  # Convert single email to list
    
    success = True
    for recipient in recipients:
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_config['username']
            msg['To'] = recipient
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            server.starttls()
            server.login(smtp_config['username'], smtp_config['password'])
            server.send_message(msg)
            server.quit()
            
            logging.info(f"Email notification sent to {recipient}")
        except Exception as e:
            logging.error(f"Failed to send email to {recipient}: {e}")
            success = False
    
    return success

def main():
    # Load configuration
    config = load_config()
    
    # Extract configuration values
    check_interval = config.get('check_interval', 300)
    notification_email = config.get('notification_email')
    smtp_config = config.get('smtp', {})
    mac_scan_interval = config.get('mac_scan_interval', 3600)  # Default: scan every hour
    
    # Set debug level if specified in config
    if config.get('debug', False):
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug logging enabled")
    
    # Analyze network MACs to help identify Yealink devices
    logging.info("Analyzing network to identify Yealink MAC prefixes...")
    analyze_network_macs()
    
    # Track previously down endpoints to avoid duplicate notifications
    down_endpoints = set()
    
    # Track when we last scanned for MAC addresses
    last_mac_scan = 0
    
    logging.info("Starting Yealink endpoint monitoring")
    
    while True:
        current_time = time.time()
        
        # Check if it's time to scan for MAC addresses
        if current_time - last_mac_scan >= mac_scan_interval:
            logging.info("Performing scheduled MAC address scan")
            
            # Get Yealink MAC address prefixes from config
            yealink_mac_prefixes = config.get('yealink_mac_prefixes', ['80:5E:0C', '00:15:65'])
            
            # Scan for devices with Yealink MAC addresses
            mac_to_ip = scan_network_for_macs(yealink_mac_prefixes)
            
            # Update endpoints based on discovered devices
            if mac_to_ip and update_endpoints_from_discovered_macs(config, mac_to_ip):
                # Save the updated configuration
                save_config(config)
            
            last_mac_scan = current_time
        
        # Get the current endpoints dictionary
        endpoints = config.get('endpoints', {})
        
        if not endpoints:
            logging.warning("No endpoints configured. Waiting for next MAC scan.")
            time.sleep(min(check_interval, mac_scan_interval))
            continue
        
        current_down_endpoints = set()
        
        for mac, endpoint_info in endpoints.items():
            if not check_endpoint(endpoint_info):
                current_down_endpoints.add(mac)
                
                # Only notify for newly down endpoints
                if mac not in down_endpoints and notification_email and smtp_config:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Create a more informative subject with extension if available
                    extension = endpoint_info.get('extension', 'Unknown')
                    display_name = endpoint_info.get('display_name', 'Unknown User')
                    
                    if extension and extension != 'Unknown':
                        subject = f"Yealink Phone Down Alert - Extension {extension} - {timestamp}"
                    else:
                        subject = f"Yealink Phone Down Alert - {timestamp}"
                    
                    # Create a detailed message with all available information
                    message = f"""
Yealink phone is not available:

Extension: {extension}
Display Name: {display_name}
Model: {endpoint_info.get('model', 'Unknown')}
MAC Address: {mac}
IP Address: {endpoint_info.get('ip', 'Unknown')}
URL: {endpoint_info.get('url', 'Unknown')}
Time: {timestamp}

This is an automated notification.
"""
                    send_email_notifications(
                        smtp_config,
                        notification_email,
                        subject,
                        message
                    )
        
        # Update the set of down endpoints
        down_endpoints = current_down_endpoints
        
        # Sleep before next check
        time.sleep(check_interval)

if __name__ == "__main__":
    main()
