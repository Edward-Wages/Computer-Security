import socket
import threading

HOST = "127.0.0.1"
PORT = 12345
KEY_UPDATE_INTERVAL = 5

clients = {}
msg_counter = 0
key_epoch = 1
state_lock = threading.Lock()


def broadcast(line):
    for conn in clients.values():
        try:
            conn.sendall((line + "\n").encode())
        except Exception:
            pass


def send_pair_ready_if_needed():
    if len(clients) == 2:
        names = sorted(clients.keys())
        broadcast(f"PEER_READY:{names[0]}:{names[1]}:{key_epoch}")


def get_other_conn(username):
    for other_name, other_conn in clients.items():
        if other_name != username:
            return other_conn
    return None


def handle_client(conn, addr, username):
    global msg_counter, key_epoch
    print(f"{username} connected from {addr}")

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            line = data.decode().strip()
            if not line:
                continue

            if line.startswith("MSG:"):
                b64 = line.split(":", 1)[1]
                with state_lock:
                    other = get_other_conn(username)
                    if other:
                        other.sendall(f"MSG:{username}:{b64}\n".encode())
                        msg_counter += 1
                        if msg_counter >= KEY_UPDATE_INTERVAL and len(clients) == 2:
                            key_epoch += 1
                            msg_counter = 0
                            broadcast(f"REKEY_NOW:{key_epoch}")

            elif line.startswith("KX_INIT:"):
                with state_lock:
                    other = get_other_conn(username)
                    if other:
                        other.sendall((line + "\n").encode())

            elif line == "HELLO":
                with state_lock:
                    send_pair_ready_if_needed()

    except Exception as e:
        print(f"Error with {username}: {e}")
    finally:
        conn.close()
        with state_lock:
            if username in clients:
                del clients[username]
            print(f"{username} disconnected")


def main():
    global msg_counter, key_epoch
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)
    print(f"Server listening on {HOST}:{PORT} - waiting for two clients...")

    while True:
        conn, addr = server.accept()
        data = conn.recv(1024).decode().strip()

        if not data.startswith("NAME:"):
            conn.close()
            continue

        username = data.split(":", 1)[1].strip()
        if not username:
            conn.sendall(b"ERROR:Invalid username\n")
            conn.close()
            continue

        with state_lock:
            if username in clients:
                conn.sendall(b"ERROR:Username already taken\n")
                conn.close()
                continue

            if len(clients) >= 2:
                conn.sendall(b"ERROR:Server full (only two users allowed)\n")
                conn.close()
                continue

            clients[username] = conn
            conn.sendall(b"OK\n")

            if len(clients) == 2:
                msg_counter = 0
                key_epoch = 1
                send_pair_ready_if_needed()

        threading.Thread(target=handle_client, args=(conn, addr, username), daemon=True).start()


if __name__ == "__main__":
    main()