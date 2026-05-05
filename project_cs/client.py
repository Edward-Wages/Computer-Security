import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import socket
import threading
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from queue import Queue, Empty

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

class SecureChatClient:
    def __init__(self, master, username):
        self.master = master
        self.username = username
        self.sock = None
        self.key = None
        self.password = None
        self.running = False
        self.ui_queue = Queue()

        master.title(f"Secure IM – {username}")

        self.chat_display = scrolledtext.ScrolledText(master, state='disabled',
                                                      width=60, height=20)
        self.chat_display.grid(row=0, column=0, columnspan=3, padx=5, pady=5)

        self.msg_entry = tk.Entry(master, width=40)
        self.msg_entry.grid(row=1, column=0, padx=5, pady=5)
        self.send_btn = tk.Button(master, text="Send", command=self.send_message)
        self.send_btn.grid(row=1, column=1, padx=5, pady=5)

        self.sent_cipher_label = tk.Label(master, text="Sent Ciphertext: ",
                                          wraplength=400, justify='left')
        self.sent_cipher_label.grid(row=2, column=0, columnspan=3, sticky='w', padx=5)
        self.recv_cipher_label = tk.Label(master, text="Received Ciphertext: ",
                                          wraplength=400, justify='left')
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

    def derive_key(self, password, salt_bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        return kdf.derive(password.encode())

    def encrypt_message(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_message(self, data):
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ct) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        plain = unpadder.update(padded_plain) + unpadder.finalize()
        return plain.decode()

    def send_message(self):
        plain = self.msg_entry.get()
        if not plain:
            return
        if self.key is None:
            messagebox.showwarning("Key not ready", "Wait for key establishment.")
            return
        encrypted = self.encrypt_message(plain)
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
            except Exception as e:
                print("Recv error:", e)
                break
        self.running = False

    def handle_server_line(self, line):
        if line.startswith("SALT:") or line.startswith("NEWSALT:"):
            self.ui_queue.put(('salt', line))
        elif line.startswith("MSG:"):
            # format: MSG:sender_username:base64cipher
            parts = line.split(':', 2)
            if len(parts) == 3:
                _, sender, b64 = parts
                try:
                    cipher_bytes = base64.b64decode(b64)
                    self.recv_cipher_label.config(text=f"Received Ciphertext: {b64}")
                    plaintext = self.decrypt_message(cipher_bytes)
                    self.display_message(f"[{sender}]: {plaintext}")
                except Exception as e:
                    self.display_message(f"[Error] Decryption failed: {e}")
            else:
                self.display_message("[Error] Malformed message from server.")
        elif line.startswith("ERROR:"):
            self.display_message(f"Server: {line[6:]}")

    def process_ui_queue(self):
        try:
            while True:
                task = self.ui_queue.get_nowait()
                if task[0] == 'salt':
                    self._prompt_password_and_derive_key(task[1])
        except Empty:
            pass
        self.master.after(100, self.process_ui_queue)

    def _prompt_password_and_derive_key(self, salt_line):
        if self.password is None:
            pwd = simpledialog.askstring("Password",
                                         "Enter shared password:",
                                         show='*')
            if not pwd:
                messagebox.showerror("Error", "Password required.")
                self.master.destroy()
                return
            self.password = pwd

        salt_hex = salt_line.split(":", 1)[1]
        salt = bytes.fromhex(salt_hex)
        self.key = self.derive_key(self.password, salt)
        if salt_line.startswith("SALT:"):
            self.display_message("[System] Key established.")
        else:
            self.display_message("[System] Key updated (periodic re‑key).")

    def on_closing(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self.master.destroy()

if __name__ == "__main__":
    import sys

    # Allow any unique username – ask if not provided
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        # Use a temporary hidden root to ask for the username
        temp_root = tk.Tk()
        temp_root.withdraw()
        username = simpledialog.askstring("Username", "Enter your username:",
                                          parent=temp_root)
        temp_root.destroy()
        if not username:
            sys.exit(0)

    root = tk.Tk()
    app = SecureChatClient(root, username)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()