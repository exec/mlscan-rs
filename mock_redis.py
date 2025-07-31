#!/usr/bin/env python3
"""
Mock Redis server for testing port scanner detection capabilities.
Implements basic RESP protocol responses.
"""

import socket
import threading
import sys

def redis_response(command):
    """Return appropriate Redis RESP protocol responses."""
    command = command.strip().upper()
    
    if command.startswith(b'PING'):
        return b'+PONG\r\n'
    elif command.startswith(b'INFO'):
        return b'$158\r\n# Server\r\nredis_version:7.0.0\r\nredis_git_sha1:00000000\r\nredis_git_dirty:0\r\nredis_build_id:12345\r\nredis_mode:standalone\r\nos:Linux 5.4.0\r\narch_bits:64\r\n\r\n'
    elif command.startswith(b'ECHO'):
        msg = command[5:].strip()
        return f'${len(msg)}\r\n'.encode() + msg + b'\r\n'
    elif command.startswith(b'GET'):
        return b'$-1\r\n'  # NULL response
    elif command.startswith(b'SET'):
        return b'+OK\r\n'
    elif command.startswith(b'AUTH'):
        return b'-ERR AUTH <password> called without any password configured for the default user\r\n'
    else:
        return b'-ERR unknown command\r\n'

def handle_client(client_socket, address):
    """Handle individual client connections."""
    print(f"[MockRedis] Connection from {address}")
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            
            print(f"[MockRedis] Received: {data}")
            response = redis_response(data)
            client_socket.send(response)
            print(f"[MockRedis] Sent: {response}")
    except Exception as e:
        print(f"[MockRedis] Error handling client {address}: {e}")
    finally:
        client_socket.close()
        print(f"[MockRedis] Connection closed: {address}")

def start_mock_redis(port=6379):
    """Start the mock Redis server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('127.0.0.1', port))
        server.listen(5)
        print(f"[MockRedis] Server listening on 127.0.0.1:{port}")
        
        while True:
            client_socket, address = server.accept()
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client_socket, address),
                daemon=True
            )
            client_thread.start()
            
    except KeyboardInterrupt:
        print("[MockRedis] Server shutting down...")
    except Exception as e:
        print(f"[MockRedis] Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 6379
    start_mock_redis(port)