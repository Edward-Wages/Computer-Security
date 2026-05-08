# client_custom_enc.py
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import socket, threading, base64, os
import json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
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
        self.running = False
        self.ui_queue = Queue()
        self.current_epoch = 0
        self.kx_local = {}
        self.kx_peer = {}
        self.id_private_key = self._load_or_create_identity_key()

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
            self.sock.sendall(b"HELLO\n")
            self.running = True
            threading.Thread(target=self.receive_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.master.destroy()

    def _safe_username(self):
        chars = []
        for ch in self.username:
            if ch.isalnum() or ch in ("-", "_"):
                chars.append(ch)
        cleaned = "".join(chars)
        return cleaned if cleaned else "user"

    def _identity_private_path(self):
        base = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base, f"{self._safe_username()}_ed25519.pem")

    def _trust_store_path(self):
        base = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base, "trusted_identities.json")

    def _load_or_create_identity_key(self):
        path = self._identity_private_path()
        if os.path.exists(path):
            with open(path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)

        private_key = ed25519.Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(path, "wb") as f:
            f.write(pem)
        return private_key

    def _load_trust_store(self):
        path = self._trust_store_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_trust_store(self, data):
        with open(self._trust_store_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _pin_or_verify_identity(self, peer_username, peer_pub_raw):
        store = self._load_trust_store()
        peer_b64 = base64.b64encode(peer_pub_raw).decode()
        trusted = store.get(peer_username)

        if trusted and trusted != peer_b64:
            self.display_message(f"[Security] Identity mismatch for {peer_username}. Possible MITM.")
            self.running = False
            self.sock.close()
            self.master.after(0, lambda: messagebox.showerror("Security Error", f"Identity key for {peer_username} changed."))
            return False

        if trusted is None:
            store[peer_username] = peer_b64
            self._save_trust_store(store)
            fingerprint = hashes.Hash(hashes.SHA256())
            fingerprint.update(peer_pub_raw)
            fp_hex = fingerprint.finalize().hex()[:16]
            self.display_message(f"[Security] First-seen identity pinned for {peer_username} (fp {fp_hex}).")
        return True

    def _start_key_exchange(self, epoch):
        eph_private = x25519.X25519PrivateKey.generate()
        eph_public_raw = eph_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        nonce = os.urandom(16)
        id_public_raw = self.id_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        signed_payload = b"|".join([
            b"KX1",
            str(epoch).encode(),
            self.username.encode(),
            id_public_raw,
            eph_public_raw,
            nonce,
        ])
        signature = self.id_private_key.sign(signed_payload)

        self.kx_local[epoch] = {
            "eph_private": eph_private,
            "nonce": nonce,
            "id_public": id_public_raw,
        }

        line = "KX_INIT:{epoch}:{user}:{id_pub}:{eph_pub}:{nonce}:{sig}".format(
            epoch=epoch,
            user=self.username,
            id_pub=base64.b64encode(id_public_raw).decode(),
            eph_pub=base64.b64encode(eph_public_raw).decode(),
            nonce=base64.b64encode(nonce).decode(),
            sig=base64.b64encode(signature).decode(),
        )
        self.sock.sendall((line + "\n").encode())
        self.display_message(f"[System] Started authenticated key exchange (epoch {epoch}).")

    def _try_finalize_key_exchange(self, epoch):
        local = self.kx_local.get(epoch)
        peer = self.kx_peer.get(epoch)
        if not local or not peer:
            return

        if peer["username"] == self.username:
            return

        signed_payload = b"|".join([
            b"KX1",
            str(epoch).encode(),
            peer["username"].encode(),
            peer["id_pub_raw"],
            peer["eph_pub_raw"],
            peer["nonce"],
        ])

        try:
            ed25519.Ed25519PublicKey.from_public_bytes(peer["id_pub_raw"]).verify(peer["signature"], signed_payload)
        except Exception:
            self.display_message("[Security] Invalid peer signature. Dropping key exchange.")
            return

        if not self._pin_or_verify_identity(peer["username"], peer["id_pub_raw"]):
            return

        shared_secret = local["eph_private"].exchange(
            x25519.X25519PublicKey.from_public_bytes(peer["eph_pub_raw"])
        )
        if self.username < peer["username"]:
            salt = local["nonce"] + peer["nonce"]
        else:
            salt = peer["nonce"] + local["nonce"]
        info = f"customenc-epoch-{epoch}".encode()
        keymat = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info).derive(shared_secret)
        self.k1, self.k2 = keymat[:32], keymat[32:]
        self.current_epoch = epoch

        auth_code_hash = hashes.Hash(hashes.SHA256())
        auth_code_hash.update(shared_secret)
        auth_code = auth_code_hash.finalize().hex()[:8]

        if epoch == 1:
            self.display_message(f"[System] Key established via authenticated KX. Verify code: {auth_code}")
        else:
            self.display_message(f"[System] Key updated via re-key (epoch {epoch}). Verify code: {auth_code}")

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
                    self.ui_queue.put(('line', line.strip()))
            except:
                break
        self.running = False

    def handle_server_line(self, line):
        if line.startswith("PEER_READY:"):
            parts = line.split(":", 3)
            if len(parts) == 4:
                epoch = int(parts[3])
                self._start_key_exchange(epoch)
        elif line.startswith("REKEY_NOW:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                epoch = int(parts[1])
                self._start_key_exchange(epoch)
        elif line.startswith("KX_INIT:"):
            parts = line.split(":", 6)
            if len(parts) == 7:
                _, epoch_str, peer_user, id_pub_b64, eph_pub_b64, nonce_b64, sig_b64 = parts
                epoch = int(epoch_str)
                self.kx_peer[epoch] = {
                    "username": peer_user,
                    "id_pub_raw": base64.b64decode(id_pub_b64),
                    "eph_pub_raw": base64.b64decode(eph_pub_b64),
                    "nonce": base64.b64decode(nonce_b64),
                    "signature": base64.b64decode(sig_b64),
                }
                self._try_finalize_key_exchange(epoch)
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
                if task[0] == 'line':
                    self.handle_server_line(task[1])
        except Empty:
            pass
        self.master.after(100, self.process_ui_queue)

    def on_closing(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self.master.destroy()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        temp_root = tk.Tk()
        temp_root.withdraw()
        username = simpledialog.askstring("Username", "Enter your username:", parent=temp_root)
        temp_root.destroy()
        if not username:
            sys.exit(0)

    root = tk.Tk()
    app = CustomEncChatClient(root, username)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()