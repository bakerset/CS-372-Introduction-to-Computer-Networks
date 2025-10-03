import socket

# Host and port details
host = "gaia.cs.umass.edu"
port = 80
request = "GET /wireshark-labs/INTRO-wireshark-file1.html HTTP/1.1\r\nHost:gaia.cs.umass.edu\r\n\r\n"

# Create a socket and connect
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect((host, port)) # Connecting to host and port number
    client_socket.sendall(request.encode())  # Send the GET request
    response = client_socket.recv(4096)  # Receive response (small file)

# Print the server's response
print(response.decode(errors='ignore'))
