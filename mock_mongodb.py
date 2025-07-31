#!/usr/bin/env python3
"""
Mock MongoDB server for testing port scanner detection capabilities.
Implements basic MongoDB wire protocol response.
"""

import socket
import struct
import threading
import sys

def create_bson_response():
    """Create a MongoDB BSON response for isMaster command."""
    # Simple BSON document: {"ismaster": true, "maxBsonObjectSize": 16777216}
    bson_doc = (
        b'\x30\x00\x00\x00'  # Document length (48 bytes)
        b'\x08ismaster\x00\x01'  # boolean field "ismaster" = true
        b'\x10maxBsonObjectSize\x00\x00\x00\x00\x01'  # int32 field
        b'\x02version\x00\x06\x00\x00\x00mock\x00'  # string field "version" = "mock"
        b'\x00'  # End of document
    )
    return bson_doc

def create_mongodb_response(request_id):
    """Create a complete MongoDB wire protocol response."""
    bson_response = create_bson_response()
    
    # MongoDB wire protocol header
    # messageLength (4), requestID (4), responseTo (4), opCode (4)
    message_length = 16 + len(bson_response)  # header + bson
    response_header = struct.pack('<i', message_length)  # Total message length
    response_header += struct.pack('<i', 12345)          # Response ID
    response_header += struct.pack('<i', request_id)     # Response to request ID
    response_header += struct.pack('<i', 1)              # OP_REPLY opcode
    
    # OP_REPLY specific fields
    response_flags = struct.pack('<i', 0)        # Response flags
    cursor_id = struct.pack('<q', 0)             # Cursor ID (8 bytes)
    starting_from = struct.pack('<i', 0)         # Starting from
    number_returned = struct.pack('<i', 1)       # Number of documents returned
    
    return response_header + response_flags + cursor_id + starting_from + number_returned + bson_response

def handle_client(client_socket, address):
    """Handle individual client connections with MongoDB protocol."""
    print(f"[MockMongoDB] Connection from {address}")
    try:
        while True:
            # Read MongoDB message header (16 bytes)
            header_data = client_socket.recv(16)
            if not header_data or len(header_data) < 16:
                break
                
            # Parse message header
            message_length, request_id, response_to, op_code = struct.unpack('<iiii', header_data)
            print(f"[MockMongoDB] Message: len={message_length}, reqid={request_id}, opcode={op_code}")
            
            # Read the rest of the message
            remaining = message_length - 16
            if remaining > 0:
                body_data = client_socket.recv(remaining)
                print(f"[MockMongoDB] Body: {body_data[:50]}...")
            
            # Send MongoDB response
            response = create_mongodb_response(request_id)
            client_socket.send(response)
            print(f"[MockMongoDB] Sent response: {len(response)} bytes")
            
    except Exception as e:
        print(f"[MockMongoDB] Error handling client {address}: {e}")
    finally:
        client_socket.close()
        print(f"[MockMongoDB] Connection closed: {address}")

def start_mock_mongodb(port=27018):
    """Start the mock MongoDB server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('127.0.0.1', port))
        server.listen(5)
        print(f"[MockMongoDB] Server listening on 127.0.0.1:{port}")
        
        while True:
            client_socket, address = server.accept()
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client_socket, address),
                daemon=True
            )
            client_thread.start()
            
    except KeyboardInterrupt:
        print("[MockMongoDB] Server shutting down...")
    except Exception as e:
        print(f"[MockMongoDB] Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 27018
    start_mock_mongodb(port)