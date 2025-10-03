import socket

# Server configuration
host = "127.0.0.1"
port = 8080  # Ensure this port is not in use

# Create and bind the socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse the address
    server_socket.bind((host, port))
    server_socket.listen(1)  # Listen for one connection
    print(f"Server is running at http://{host}:{port}/")

    while True:
        print("Waiting for a connection...")
        client_socket, client_address = server_socket.accept() # Server must accept clients socket and address
        print(f"Accepted connection from {client_address}")

        with client_socket:
            request = client_socket.recv(1024).decode() # Request decoding of client socket
            print(f"Request received:\n{request}")

            # Send HTTP response
            data = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                "<html>Congratulations! You've downloaded the first Wireshark lab file!</html>\r\n"
            )
            client_socket.sendall(data.encode())
            print("Response sent. Closing connection.")
