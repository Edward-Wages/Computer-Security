from socket import *
import threading

# P2P Architecture
# Each user will act as both a client and a server, sending and receiving messages from other users.
#This will function as a class that handles a listener and a sender.

class Connection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.other_host = other_host
        self.other_port = other_port
        self.socket = socket(AF_INET, SOCK_STREAM)

    def start_listener(host, port):
        #Uses socked bind and listern, waits for the other user to connect to the user's IP
        serverSocket = socket(AF_INET, SOCK_STREAM)
        socket.bind((host, port))
        socket.listen(1)
        connection, address = serverSocket.accept()
        print(f"Connected to {address}")
        return serverSocket


    def start_sender(peer_host, peer_port):
        #Triggered when the user types in their other user's IP and clicks "Connect" in the GUI using socket connect
        #Sends one complete encrypted message over the active TCP connection. 
        #This should only handle bytes (ciphertext), not plaintext strings. 
        #In practice it should include framing (length header + payload) so the receiver knows message boundaries.
        clientSocket = socket(AF_INET, SOCK_STREAM)
        clientSocket.connect((peer_host, peer_port))
        print(f"Connected to {peer_host}:{peer_port}")
        return clientSocket


    def send_message(message): #Sends one complete encrypted message over the active TCP connection.
        serverSocket.send(message.encode('utf-8')) #Check to make sure this is fine. 
        print(f"Sent message to {peer_host}:{peer_port}")

    def receive_loop(callback):
        #Runs continuously (usually in a background thread), reading incoming framed messages from the socket. 
        #For each full message received, it calls callback(message_bytes) so upper layers (GUI/crypto) can process it.
        while True:
            message = serverSocket.recv(1024)
            callback(message)
            print(f"Received message from {peer_host}:{peer_port}")

    def close_connection():
        #Closes the TCP connection.
        # Shuts down open sockets/threads and releases network resources, marks the connection a slcosed so the app can 
        # exit cleanly or reconnect if needed.
        serverSocket.close()
        clientSocket.close()
        print("Connection closed")