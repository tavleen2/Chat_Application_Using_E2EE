import socket
import json
import base64
from pathlib import Path
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST, PORT = "127.0.0.1", 5000

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

class SenderApp:
    def __init__(self, me_disp: str, peer_disp: str):
        self.me_disp = me_disp.strip() or "Alice"
        self.me = self.me_disp.lower()
        self.peer_disp = peer_disp.strip() or "Bob"
        self.peer = self.peer_disp.lower()

        self.cwd = Path.cwd()
        self.log_root = self.cwd / "messages.json"
        self.log_user = self.cwd / f"messages_{self.me}.json"
        for p in (self.log_root, self.log_user):
            if not p.exists():
                p.write_text("[]", encoding="utf-8")
        print(f"[{self.me_disp}] Logging to: {self.log_root} and {self.log_user}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rsa = RSA.generate(2048)
        self.pub_pem = self.rsa.publickey().export_key().decode("utf-8")

        self.peer_pub = {}      
        self.sessions = {}      

    def _save_log(self, entry: dict):
        e = dict(entry)
        e["ts"] = datetime.now().isoformat(timespec="seconds")
        for p in (self.log_root, self.log_user):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                data = []
            data.append(e)
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _send_json(self, obj: dict):
        self.sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

    def _recv_line(self) -> dict:
        buf = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Server closed connection")
            buf += chunk
            if b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    return json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    continue

    def connect(self):
        self.sock.connect((HOST, PORT))
        self._send_json({"type": "register", "username": self.me_disp, "public_key": self.pub_pem})
        print(f"[{self.me_disp}] Connected as SENDER. Talking to {self.peer_disp}.")

    def _ensure_session(self):
        if self.peer in self.sessions:
            return

        # One request only
        self._send_json({"type": "get_pubkey", "target": self.peer_disp})
        print(f"[{self.me_disp}] Waiting for {self.peer_disp} to connect...")

        while True:
            msg = self._recv_line()
            mtype = msg.get("type")

            if mtype == "pubkey":
                pem = msg["public_key"]
                try:
                    self.peer_pub[msg["username"]] = RSA.import_key(pem)
                except (ValueError, IndexError, TypeError) as e:
                    print(f"[{self.me_disp}] Failed to import public key: {e}")
                    return
                print(f"[{self.me_disp}] Got {self.peer_disp}'s public key.")

                aes = get_random_bytes(16)  
                enc_key = PKCS1_OAEP.new(self.peer_pub[self.peer]).encrypt(aes)
                self._send_json({
                    "type": "session_key",
                    "from": self.me_disp,
                    "to": self.peer_disp,
                    "payload": b64e(enc_key)
                })
                self.sessions[self.peer] = aes
                print(f"[{self.me_disp}] Session key established with {self.peer_disp}.")
                return

            elif mtype == "wait":
                continue

            elif mtype == "register_ok":
                continue

            elif mtype == "error":
                print(f"[{self.me_disp}] Server error: {msg.get('message')}")
                return

            else:
                continue

    def _encrypt_packet(self, plaintext: str) -> dict:
        key = self.sessions[self.peer]
        nonce = get_random_bytes(12)
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = c.encrypt_and_digest(plaintext.encode("utf-8"))
        return {"nonce": b64e(nonce), "ciphertext": b64e(ct), "tag": b64e(tag)}

    def _handle_incoming(self, msg: dict):
        if msg.get("type") != "message":
            return
        sender = msg["from"]
        sender_lc = sender.lower()

        ct_b = b64d(msg["ciphertext"])
        print(f"[{self.me_disp}]  Encrypted from {sender}: {b64e(ct_b)[:60]}...")

        key = self.sessions.get(sender_lc)
        if not key:
            print(f"[{self.me_disp}] No session key for {sender}.")
            return

        nonce = b64d(msg["nonce"])
        tag = b64d(msg["tag"])
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = c.decrypt_and_verify(ct_b, tag).decode("utf-8")
        print(f"[{self.me_disp}] Decrypted from {sender}: {pt}")

        self._save_log({
            "direction": "received",
            "from": sender,
            "ciphertext": b64e(ct_b),
            "plaintext": pt
        })

    def run(self):
        self._ensure_session()

        while True:
            text = input(f"{self.me_disp} (your turn) > ").strip()
            if text.lower() in ("exit", "quit"):
                break

            pkt = self._encrypt_packet(text)
            self._send_json({"type": "message", "from": self.me_disp, "to": self.peer_disp, **pkt})
            self._save_log({
                "direction": "sent",
                "to": self.peer_disp,
                "ciphertext": pkt["ciphertext"],
                "plaintext": text
            })
            print(f"[{self.me_disp}] Sent encrypted message to {self.peer_disp}. Waiting for reply...")

            msg = self._recv_line()  
            self._handle_incoming(msg)

def main():
    me = input("Enter your name : ").strip() or "Alice"
    peer = input("Enter receiver name : ").strip() or "Bob"
    app = SenderApp(me, peer)
    app.connect()
    app.run()

if __name__ == "__main__":
    main()
