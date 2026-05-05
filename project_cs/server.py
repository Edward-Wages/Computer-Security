import socket
import threading
import os

HOST = '127.0.0.1'
PORT = 12345
KEY_UPDATE_INTERVAL = 5          

clients = {}
pair = None
msg_counter = 0
current_salt = None

def generate_salt():
    return os.urandom(16).hex()

def broadcast(line):
    """Send a line to all connected clients."""
    for conn in clients.values():
        try:
            conn.sendall((line + '\n').encode())
        except:
            pass

def handle_client(conn, addr, username):
    global pair, msg_counter, current_salt

    print(f"{username} connected from {addr}")

    # If both are present, initialise the salt if not already done
    if len(clients) == 2:
        if current_salt is None:
            current_salt = generate_salt()
            broadcast(f"SALT:{current_salt}")
        pair = tuple(clients.values())
        msg_counter = 0

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            line = data.decode().strip()
            if line.startswith("MSG:"):
                # Extract just the Base64 ciphertext
                b64 = line.split(":", 1)[1]
                if pair:
                    other = pair[1] if conn == pair[0] else pair[0]
                    # Prepend sender's username for the receiver
                    other.sendall(f"MSG:{username}:{b64}\n".encode())
                    msg_counter += 1
                    if msg_counter >= KEY_UPDATE_INTERVAL:
                        current_salt = generate_salt()
                        broadcast(f"NEWSALT:{current_salt}")
                        msg_counter = 0
            elif line.startswith("GETSALT"):
                if current_salt:
                    conn.sendall(f"SALT:{current_salt}\n".encode())
    except Exception as e:
        print(f"Error with {username}: {e}")
    finally:
        conn.close()
        if username in clients:
            del clients[username]
        pair = None   # pair is invalid now
        print(f"{username} disconnected")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)
    print(f"Server listening on {HOST}:{PORT} – waiting for two clients...")

    while True:
        conn, addr = server.accept()
        data = conn.recv(1024).decode().strip()
        if data.startswith("NAME:"):
            username = data.split(":", 1)[1].strip()
            if not username:
                conn.sendall(b"ERROR:Invalid username\n")
                conn.close()
                continue
            if username in clients:
                conn.sendall(b"ERROR:Username already taken\n")
                conn.close()
                continue
            if len(clients) >= 2:
                conn.sendall(b"ERROR:Server full (only two users allowed)\n")
                conn.close()
                continue

            conn.sendall(b"OK\n")
            clients[username] = conn
            threading.Thread(target=handle_client,
                             args=(conn, addr, username), daemon=True).start()

            # If we now have exactly two clients, generate the initial salt
            if len(clients) == 2:
                current_salt = generate_salt()
                broadcast(f"SALT:{current_salt}")
                pair = tuple(clients.values())
                msg_counter = 0
        else:
            conn.close()

if __name__ == "__main__":
    main()