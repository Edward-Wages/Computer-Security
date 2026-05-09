# client_custom_enc.py
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import socket, threading, base64, os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from queue import Queue, Empty

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

class CustomEncChatClient:
    def __init__(self, master, username):
        self.master = master
        self.username = username
        self.sock = None
        self.k1 = None    # first key (CTR)
        self.k2 = None    # second key (CBC)
        self.password = None
        self.running = False
        self.ui_queue = Queue()

        master.title(f"CustomEnc IM – {username}")
        # ... GUI setup identical to previous client, omitted for brevity ...

        # Actually implement the GUI (same as before)
        self.chat_display = scrolledtext.ScrolledText(master, state='disabled', width=60, height=20)
        self.chat_display.grid(row=0, column=0, columnspan=3, padx=5, pady=5)
        self.msg_entry = tk.Entry(master, width=40)
        self.msg_entry.grid(row=1, column=0, padx=5, pady=5)
        self.send_btn = tk.Button(master, text="Send", command=self.send_message)
        self.send_btn.grid(row=1, column=1, padx=5, pady=5)
        self.sent_cipher_label = tk.Label(master, text="Sent Ciphertext: ", wraplength=400)
        self.sent_cipher_label.grid(row=2, column=0, columnspan=3, sticky='w', padx=5)
        self.recv_cipher_label = tk.Label(master, text="Received Ciphertext: ", wraplength=400)
        self.recv_cipher_label.grid(row=3, column=0, columnspan=3, sticky='w', padx=5)

        self.connect_to_server()
        self.process_ui_queue()

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            self.sock.sendall(f"NAME:{self.username}\n".encode())
            response = self.sock.recv(1024).decode().strip()
            if response != "OK":
                messagebox.showerror("Error", f"Server rejected: {response}")
                self.master.destroy()
                return
            self.running = True
            threading.Thread(target=self.receive_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.master.destroy()

    def derive_two_keys(self, password, salt_bytes):
        # Derive two independent keys using different info strings
        kdf1 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes+b'1', iterations=100000)
        k1 = kdf1.derive(password.encode())
        kdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes+b'2', iterations=100000)
        k2 = kdf2.derive(password.encode())
        return k1, k2

    def custom_encrypt(self, plaintext):
        # Step 1: AES-256-CTR with random nonce
        nonce = os.urandom(16)
        cipher_ctr = Cipher(algorithms.AES(self.k1), modes.CTR(nonce))
        encryptor_ctr = cipher_ctr.encryptor()
        ct1 = encryptor_ctr.update(plaintext.encode()) + encryptor_ctr.finalize()

        # Step 2: AES-256-CBC over ct1 with random IV
        iv = os.urandom(16)
        cipher_cbc = Cipher(algorithms.AES(self.k2), modes.CBC(iv))
        encryptor_cbc = cipher_cbc.encryptor()
        padder = PKCS7(128).padder()
        padded = padder.update(ct1) + padder.finalize()
        ct2 = encryptor_cbc.update(padded) + encryptor_cbc.finalize()

        # Return nonce + iv + final ciphertext
        return nonce + iv + ct2

    def custom_decrypt(self, data):
        nonce = data[:16]
        iv = data[16:32]
        ct2 = data[32:]

        # Reverse CBC layer
        cipher_cbc = Cipher(algorithms.AES(self.k2), modes.CBC(iv))
        decryptor_cbc = cipher_cbc.decryptor()
        padded_ct1 = decryptor_cbc.update(ct2) + decryptor_cbc.finalize()
        unpadder = PKCS7(128).unpadder()
        ct1 = unpadder.update(padded_ct1) + unpadder.finalize()

        # Reverse CTR layer
        cipher_ctr = Cipher(algorithms.AES(self.k1), modes.CTR(nonce))
        decryptor_ctr = cipher_ctr.decryptor()
        plain = decryptor_ctr.update(ct1) + decryptor_ctr.finalize()
        return plain.decode()

    def send_message(self):
        plain = self.msg_entry.get()
        if not plain or not self.k1:
            return
        encrypted = self.custom_encrypt(plain)
        encoded = base64.b64encode(encrypted).decode()
        self.sock.sendall(f"MSG:{encoded}\n".encode())
        self.sent_cipher_label.config(text=f"Sent Ciphertext: {encoded}")
        self.display_message(f"[{self.username}]: {plain}")
        self.msg_entry.delete(0, tk.END)

    def display_message(self, msg):
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, msg + '\n')
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def receive_loop(self):
        buffer = ""
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                buffer += data.decode()
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    self.handle_server_line(line.strip())
            except:
                break
        self.running = False

    def handle_server_line(self, line):
        if line.startswith("SALT:") or line.startswith("NEWSALT:"):
            self.ui_queue.put(('salt', line))
        elif line.startswith("MSG:"):
            parts = line.split(':', 2)
            if len(parts) == 3:
                _, sender, b64 = parts
                cipher_bytes = base64.b64decode(b64)
                self.recv_cipher_label.config(text=f"Received Ciphertext: {b64}")
                try:
                    plaintext = self.custom_decrypt(cipher_bytes)
                    self.display_message(f"[{sender}]: {plaintext}")
                except Exception as e:
                    self.display_message(f"[Error] Decryption failed: {e}")
            else:
                self.display_message("[Error] Malformed message.")
        elif line.startswith("ERROR:"):
            self.display_message(f"Server: {line[6:]}")

    def process_ui_queue(self):
        try:
            while True:
                task = self.ui_queue.get_nowait()
                if task[0] == 'salt':
                    self._prompt_and_derive_keys(task[1])
        except Empty:
            pass
        self.master.after(100, self.process_ui_queue)

    def _prompt_and_derive_keys(self, salt_line):
        if self.password is None:
            pwd = simpledialog.askstring("Password", "Enter shared password:", show='*')
            if not pwd:
                messagebox.showerror("Error", "Password required.")
                self.master.destroy()
                return
            self.password = pwd
        salt_hex = salt_line.split(":", 1)[1]
        salt = bytes.fromhex(salt_hex)
        self.k1, self.k2 = self.derive_two_keys(self.password, salt)
        msg = "Key established." if salt_line.startswith("SALT:") else "Key updated (re‑key)."
        self.display_message(f"[System] {msg}")

    def on_closing(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self.master.destroy()

if __name__ == "__main__":
    import sys
    username = sys.argv[1] if len(sys.argv) > 1 else "Alice"
    root = tk.Tk()
    app = CustomEncChatClient(root, username)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()