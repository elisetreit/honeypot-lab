#!/usr/bin/env python3
import socket
import threading
import datetime
import json
import os
import sys
import time

# Configuration
LOG_FILE = '/home/elise/honeypot-logs/attacks.json'
TCP_SER_HOST = 'localhost'
TCP_SER_PORT = 6500
LISTEN_PORT = 6400
MAX_CONNECTIONS = 5
IDLE_TIMEOUT = 120  # Disconnect after 2 minutes of no activity

# Global connection tracking
active_connections = {}
connections_lock = threading.Lock()

def ensure_log_dir():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log_attempt(ip, username, password):
    attempt = {
        "timestamp": datetime.datetime.now().isoformat(),
        "ip": ip,
        "username": username,
        "password": password
    }
    print(f"[LOGGED] {ip} - {username}:{password}", flush=True)
    
    ensure_log_dir()
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(attempt) + '\n')

def show_connections():
    """Display all active connections"""
    with connections_lock:
        if not active_connections:
            print("[STATUS] No active connections", flush=True)
        else:
            print(f"[STATUS] {len(active_connections)} active connection(s):", flush=True)
            for conn_id, info in active_connections.items():
                idle_time = time.time() - info['last_activity']
                print(f"  - {info['address']} (connected: {info['connect_time']}, idle: {idle_time:.0f}s)", flush=True)

def handle_client(client_socket, client_address):
    conn_id = f"{client_address[0]}:{client_address[1]}_{time.time()}"
    
    # Track this connection
    with connections_lock:
        active_connections[conn_id] = {
            'socket': client_socket,
            'address': f"{client_address[0]}:{client_address[1]}",
            'connect_time': datetime.datetime.now().strftime("%H:%M:%S"),
            'last_activity': time.time()
        }
    
    print(f"[CONNECT] {client_address[0]}:{client_address[1]}", flush=True)
    show_connections()
    
    # Connect to tcpser
    try:
        ser_sock = socket.create_connection((TCP_SER_HOST, TCP_SER_PORT))
    except Exception as e:
        print(f"[ERROR] Could not connect to tcpser: {e}", flush=True)
        with connections_lock:
            del active_connections[conn_id]
        client_socket.close()
        return
    
    username = ""
    password = ""
    mode = None
    serial_buffer = ""
    connection_alive = True
    
    def check_idle_timeout():
        """Monitor for idle timeout"""
        nonlocal connection_alive
        while connection_alive:
            time.sleep(10)  # Check every 10 seconds
            with connections_lock:
                if conn_id in active_connections:
                    idle_time = time.time() - active_connections[conn_id]['last_activity']
                    if idle_time > IDLE_TIMEOUT:
                        print(f"[TIMEOUT] Disconnecting idle connection from {client_address[0]}:{client_address[1]}", flush=True)
                        try:
                            client_socket.close()
                            ser_sock.close()
                        except:
                            pass
                        connection_alive = False
                        break
    
    def update_activity():
        """Update last activity timestamp"""
        with connections_lock:
            if conn_id in active_connections:
                active_connections[conn_id]['last_activity'] = time.time()
    
    def forward_serial_to_client():
        nonlocal mode, serial_buffer, connection_alive
        try:
            while connection_alive:
                ser_sock.settimeout(1.0)
                try:
                    data = ser_sock.recv(1024)
                    if not data:
                        break
                    
                    decoded = data.decode('ascii', errors='ignore')
                    
                    if "BUSY" in decoded:
                        print("[WARNING] Received BUSY from serial", flush=True)
                    
                    client_socket.sendall(data)
                    update_activity()
                    
                    serial_buffer += decoded
                    if len(serial_buffer) > 200:
                        serial_buffer = serial_buffer[-200:]
                    
                    if "LOGIN:" in serial_buffer:
                        mode = "username"
                        print("[PROMPT] Detected LOGIN", flush=True)
                        serial_buffer = ""
                    elif "PASSWORD:" in serial_buffer:
                        mode = "password"
                        print("[PROMPT] Detected PASSWORD", flush=True)
                        serial_buffer = ""
                except socket.timeout:
                    continue
        except Exception as e:
            if connection_alive:
                print(f"[SERIAL ERROR] {e}", flush=True)
        connection_alive = False
    
    def forward_client_to_serial():
        nonlocal mode, username, password, connection_alive
        try:
            while connection_alive:
                client_socket.settimeout(1.0)
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    ser_sock.sendall(data)
                    update_activity()
                    
                    decoded = data.decode('ascii', errors='ignore').strip()
                    
                    if decoded:
                        print(f"[CLIENT INPUT] from {client_address[0]}: {repr(decoded)}", flush=True)
                        
                        if mode == "username":
                            username = decoded
                            mode = None
                        elif mode == "password":
                            password = decoded
                            log_attempt(client_address[0], username, password)
                            mode = None
                except socket.timeout:
                    continue
        except:
            pass
        connection_alive = False
    
    # Start threads
    t1 = threading.Thread(target=forward_serial_to_client)
    t2 = threading.Thread(target=forward_client_to_serial)
    t3 = threading.Thread(target=check_idle_timeout)
    
    t1.start()
    t2.start()
    t3.start()
    
    t1.join()
    t2.join()
    connection_alive = False
    t3.join()
    
    # Cleanup
    try:
        ser_sock.close()
        client_socket.close()
    except:
        pass
    
    # Remove from active connections
    with connections_lock:
        if conn_id in active_connections:
            del active_connections[conn_id]
    
    print(f"[DISCONNECT] {client_address[0]}:{client_address[1]}", flush=True)
    show_connections()

def monitor_thread():
    """Periodically show connection status"""
    while True:
        time.sleep(30)  # Every 30 seconds
        show_connections()

def main():
    ensure_log_dir()
    print(f"Honeypot logger starting on port {LISTEN_PORT}", flush=True)
    print(f"Idle timeout: {IDLE_TIMEOUT} seconds", flush=True)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(MAX_CONNECTIONS)
    
    print(f"Honeypot logger listening on port {LISTEN_PORT}", flush=True)
    
    # Start monitoring thread
    monitor = threading.Thread(target=monitor_thread)
    monitor.daemon = True
    monitor.start()
    
    while True:
        try:
            client_socket, client_address = server.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            thread.daemon = True
            thread.start()
        except KeyboardInterrupt:
            print("\nShutting down...", flush=True)
            show_connections()
            sys.exit(0)
        except Exception as e:
            print(f"[ACCEPT ERROR] {e}", flush=True)

if __name__ == '__main__':
    main()
