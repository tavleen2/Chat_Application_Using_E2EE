# client.py
import socket
import threading
import json
import os
import base64
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = "127.0.0.1"
PORT = 5000

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

class E2EEClient:
    def __init__(self, username):
        self.username = username
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sessions = {}         # peer -> AES key (bytes)
        self.peer_pubkeys = {}     # peer -> RSA key object
        self.messages_file = "messages.json"
        if not os.path.exists(self.messages_file):
            with open(self.messages_file, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2)

        # RSA keypair
        self.rsa_key = RSA.generate(2048)
        self.rsa_public_pem = self.rsa_key.publickey().export_key().decode("utf-8")
        self.rsa_private = self.rsa_key  # keep in memory only

    def save_log(self, entry):
        entry["ts"] = datetime.now().isoformat(timespec="seconds")
        try:
            with open(self.messages_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []
        data.append(entry)
        with open(self.messages_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def send_json(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

    def connect_and_register(self):
        self.sock.connect((HOST, PORT))
        self.send_json({
            "type": "register",
            "username": self.username,
            "public_key": self.rsa_public_pem
        })

    def request_pubkey(self, target):
        self.send_json({"type": "get_pubkey", "target": target})

    def set_session_with(self, peer, aes_key: bytes):
        self.sessions[peer] = aes_key
        print(f"[{self.username}] 🔑 Session key established with {peer} (AES-{len(aes_key)*8}).")

    def start_session(self, peer):
        # Get peer public key first if needed
        if peer not in self.peer_pubkeys:
            self.request_pubkey(peer)
            print(f"[{self.username}] Requested {peer}'s public key... (wait for 'pubkey' message)")
            return

        # Create AES session key and send encrypted with RSA OAEP
        aes_key = get_random_bytes(16)  # AES-128
        peer_pub = self.peer_pubkeys[peer]
        cipher_rsa = PKCS1_OAEP.new(peer_pub)
        enc_key = cipher_rsa.encrypt(aes_key)

        self.send_json({
            "type": "session_key",
            "from": self.username,
            "to": peer,
            "payload": b64e(enc_key)
        })
        # Optimistically store session key; receiver confirms by using it
        self.set_session_with(peer, aes_key)

    def send_secure(self, peer, plaintext: str):
        if peer not in self.sessions:
            print(f"[{self.username}] No session with {peer}. Use /chat {peer} first.")
            return
        key = self.sessions[peer]
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

        # Log locally (sender)
        self.save_log({
            "direction": "sent",
            "to": peer,
            "ciphertext": b64e(ciphertext),
            "plaintext": plaintext
        })

        # Send to server -> peer
        self.send_json({
            "type": "message",
            "from": self.username,
            "to": peer,
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
            "tag": b64e(tag)
        })
        print(f"[{self.username}] ➡️ Sent encrypted message to {peer}.")

    def handle_server_msg(self, msg):
        mtype = msg.get("type")
        if mtype == "register_ok":
            print(f"[{self.username}] Registered on server.")

        elif mtype == "pubkey":
            user = msg.get("username")
            pem = msg.get("public_key")
            try:
                key = RSA.import_key(pem)
                self.peer_pubkeys[user] = key
                print(f"[{self.username}] Received {user}'s public key.")
            except Exception:
                print(f"[{self.username}] Failed to import {user}'s public key.")

        elif mtype == "session_key":
            sender = msg.get("from")
            enc = b64d(msg.get("payload"))
            try:
                cipher_rsa = PKCS1_OAEP.new(self.rsa_private)
                aes_key = cipher_rsa.decrypt(enc)
                self.set_session_with(sender, aes_key)
                print(f"[{self.username}] 📬 Session key received from {sender}.")
            except Exception as e:
                print(f"[{self.username}] Failed to decrypt session key: {e}")

        elif mtype == "message":
            sender = msg.get("from")
            nonce = b64d(msg.get("nonce"))
            ciphertext = b64d(msg.get("ciphertext"))
            tag = b64d(msg.get("tag"))

            # First display encrypted (as required)
            print(f"[{self.username}] 📥 Encrypted from {sender}: {base64.b64encode(ciphertext)[:60].decode()}...")

            # Then decrypt and display plaintext
            key = self.sessions.get(sender)
            if not key:
                print(f"[{self.username}] No session key for {sender}. Cannot decrypt.")
                return
            try:
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
                print(f"[{self.username}] 🔓 Decrypted from {sender}: {plaintext}")
                # Log locally (receiver)
                self.save_log({
                    "direction": "received",
                    "from": sender,
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "plaintext": plaintext
                })
            except Exception as e:
                print(f"[{self.username}] Decryption failed: {e}")

        elif mtype == "error":
            print(f"[{self.username}] [ERROR] {msg.get('message')}")

    def listen(self):
        buf = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except json.JSONDecodeError:
                        continue
                    self.handle_server_msg(msg)
        except ConnectionResetError:
            pass
        finally:
            print(f"[{self.username}] Disconnected from server.")

    def repl(self):
        print(f"Commands:\n"
              f"  /chat <Peer>                -> exchange/establish session key with Peer\n"
              f"  /send <Peer> <message...>   -> send encrypted message to Peer\n"
              f"  /getpub <Peer>              -> fetch Peer public key\n"
              f"  /quit                       -> exit\n")
        while True:
            try:
                line = input(f"{self.username}> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                continue
            if line == "/quit":
                break
            if line.startswith("/chat "):
                _, peer = line.split(maxsplit=1)
                self.start_session(peer)
                continue
            if line.startswith("/getpub "):
                _, peer = line.split(maxsplit=1)
                self.request_pubkey(peer)
                continue
            if line.startswith("/send "):
                parts = line.split(maxsplit=2)
                if len(parts) < 3:
                    print("Usage: /send <Peer> <message>")
                    continue
                _, peer, msg = parts
                self.send_secure(peer, msg)
                continue
            print("Unknown command. See commands listed above.")
        self.sock.close()

def main():
    username = input("Enter your username: ").strip()
    if not username:
        print("Username required.")
        return
    client = E2EEClient(username)
    client.connect_and_register()
    threading.Thread(target=client.listen, daemon=True).start()
    client.repl()

if __name__ == "__main__":
    main()
