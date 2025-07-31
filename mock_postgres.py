#!/usr/bin/env python3
"""
Mock PostgreSQL server for testing port scanner detection capabilities.
Implements basic PostgreSQL startup handshake protocol.
"""

import socket
import struct
import threading
import sys

def postgres_startup_response():
    """Return a PostgreSQL startup response message."""
    # PostgreSQL uses a specific format for authentication messages
    # This simulates a successful authentication challenge
    
    # Authentication OK (Type R, length 8, auth type 0)
    auth_ok = b'R' + struct.pack('>I', 8) + struct.pack('>I', 0)
    
    # BackendKeyData (Type K, length 12, process_id, secret_key)
    backend_key = b'K' + struct.pack('>I', 12) + struct.pack('>I', 12345) + struct.pack('>I', 67890)
    
    # ReadyForQuery (Type Z, length 5, status I=idle)
    ready = b'Z' + struct.pack('>I', 5) + b'I'
    
    return auth_ok + backend_key + ready

def handle_client(client_socket, address):
    """Handle individual client connections with PostgreSQL protocol."""
    print(f"[MockPostgres] Connection from {address}")
    try:
        # Read startup message
        data = client_socket.recv(1024)
        if not data:
            return
            
        print(f"[MockPostgres] Received startup: {data[:50]}...")
        
        # Send authentication response
        response = postgres_startup_response()
        client_socket.send(response)
        print(f"[MockPostgres] Sent auth response: {len(response)} bytes")
        
        # Handle any additional queries
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            print(f"[MockPostgres] Query received: {data[:30]}...")
            
            # Send a simple response to any query
            # ErrorResponse (Type E)
            error_msg = b"PostgreSQL mock server ready"
            error_response = b'E' + struct.pack('>I', len(error_msg) + 5) + error_msg + b'\x00'
            client_socket.send(error_response)
            
    except Exception as e:
        print(f"[MockPostgres] Error handling client {address}: {e}")
    finally:
        client_socket.close()
        print(f"[MockPostgres] Connection closed: {address}")

def start_mock_postgres(port=5433):
    """Start the mock PostgreSQL server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('127.0.0.1', port))
        server.listen(5)
        print(f"[MockPostgres] Server listening on 127.0.0.1:{port}")
        
        while True:
            client_socket, address = server.accept()
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client_socket, address),
                daemon=True
            )
            client_thread.start()
            
    except KeyboardInterrupt:
        print("[MockPostgres] Server shutting down...")
    except Exception as e:
        print(f"[MockPostgres] Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5433
    start_mock_postgres(port)