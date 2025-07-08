#!/bin/bash

# Honeypot Traffic Logger for Raspberry Pi
# Logs all incoming connections to your honeypot with source IPs

LOG_FILE="/var/log/honeypot-traffic.log"
INTERFACE="eth0"  # Change to your actual interface
HONEYPOT_PORT="6400"
TELNET_PORT="23"

# Create log file if it doesn't exist
sudo touch $LOG_FILE
sudo chmod 644 $LOG_FILE

echo "Starting honeypot traffic monitoring..."
echo "Logging to: $LOG_FILE"
echo "Monitoring interface: $INTERFACE"
echo "Ports: $HONEYPOT_PORT, $TELNET_PORT"
echo "Press Ctrl+C to stop"

# Function to handle cleanup
cleanup() {
    echo "Stopping traffic monitoring..."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start packet capture with timestamp and source IP logging
sudo tcpdump -i $INTERFACE -n -l \
    "port $HONEYPOT_PORT or port $TELNET_PORT" \
    2>/dev/null | while read line; do
    
    # Extract timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log the raw packet info with timestamp
    echo "[$timestamp] $line" | sudo tee -a $LOG_FILE
    
    # Extract and highlight source IP for console output
    if [[ $line =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]+).*\>.*\.($HONEYPOT_PORT|$TELNET_PORT) ]]; then
        src_ip="${BASH_REMATCH[1]}"
        src_port="${BASH_REMATCH[2]}"
        echo "🎯 NEW CONNECTION: $src_ip:$src_port -> honeypot"
    fi
done
