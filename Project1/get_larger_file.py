import socket

# Host and port details
host = "gaia.cs.umass.edu"
port = 80
request = "GET /wireshark-labs/HTTP-wireshark-file3.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n"

# Create a socket and connect
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((host, port))
    client_socket.sendall(request.encode())  # Send the GET request
    
    response = b""  # Use a bytes object for concatenation
    while True:
        chunk = client_socket.recv(4096)  # Read in chunks
        if not chunk:
            break  # Connection closed
        response += chunk

# Print the first and last few lines of the response
response_text = response.decode(errors='ignore')
lines = response_text.splitlines()
print("\n".join(lines[:10]))  # First 10 lines
print("...\n")
print("\n".join(lines[-10:]))  # Last 10 lines
