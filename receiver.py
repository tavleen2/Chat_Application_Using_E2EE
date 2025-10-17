import socket, json, base64
from pathlib import Path
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST, PORT = "127.0.0.1", 5000

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("utf-8")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("utf-8"))

import os
LOG_PATH = Path(__file__).resolve().parent / "messages.json"

def append_jsonl(entry: dict):
    e = dict(entry)
    if "ts" not in e:
        e["ts"] = datetime.now().isoformat(timespec="seconds")
    line = json.dumps(e, ensure_ascii=False) + "\n"
    fd = os.open(str(LOG_PATH), os.O_APPEND | os.O_CREAT | os.O_WRONLY)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

class ReceiverApp:
    def __init__(self, me_disp: str, peer_disp: str):
        self.me_disp = me_disp.strip()
        self.me = self.me_disp.lower()
        self.peer_disp = peer_disp.strip()
        self.peer = self.peer_disp.lower()

        print(f"[{self.me_disp}] Logging to: {LOG_PATH}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self._rsa = RSA.generate(2048)
        self._pub_pem = self._rsa.publickey().export_key().decode("utf-8")

        self.sessions = {}  

    def _save_log(self, entry: dict):
        append_jsonl(entry)

    def _send_json(self, obj: dict):
        self.sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

    def _recv_line(self) -> dict:
        buf = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk: raise ConnectionError("Server closed")
            buf += chunk
            if b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                return json.loads(line.decode("utf-8"))

    def connect(self):
        self.sock.connect((HOST, PORT))
        self._send_json({"type": "register", "username": self.me_disp, "public_key": self._pub_pem})
        print(f"[{self.me_disp}] Connected as RECEIVER. Waiting for first encrypted message...")

    def _decrypt_and_show(self, msg: dict):
        sender = msg.get("from")
        sender_lc = sender.lower()

        if msg.get("type") == "session_key":
            aes = PKCS1_OAEP.new(self._rsa).decrypt(b64d(msg["payload"]))
            self.sessions[sender_lc] = aes
            print(f"[{self.me_disp}]  Session key received from {sender}.")
            msg = self._recv_line() 

        ct_b = b64d(msg["ciphertext"])
        print(f"[{self.me_disp}]  Encrypted from {sender}: {b64e(ct_b)[:60]}...")

        key = self.sessions.get(sender_lc)
        if not key:
            print(f"[{self.me_disp}] No session key yet; cannot decrypt.")
            return

        nonce = b64d(msg["nonce"])
        tag = b64d(msg["tag"])
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = c.decrypt_and_verify(ct_b, tag).decode("utf-8")
        print(f"[{self.me_disp}] Decrypted from {sender}: {pt}")

        self._save_log({
            "who": self.me_disp,
            "direction": "received",
            "from": sender,
            "ciphertext": b64e(ct_b),
            "plaintext": pt
        })

    def _encrypt_packet(self, plaintext: str) -> dict:
        key = self.sessions[self.peer]
        nonce = get_random_bytes(12)
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = c.encrypt_and_digest(plaintext.encode("utf-8"))
        return {"nonce": b64e(nonce), "ciphertext": b64e(ct), "tag": b64e(tag)}

    def run(self):
        while True:
            msg = self._recv_line()
            if msg.get("type") in ("session_key", "message"):
                self._decrypt_and_show(msg)
            else:
                continue

            text = input(f"{self.me_disp} (your turn) > ").strip()
            if text.lower() in ("exit", "quit"):
                break
            pkt = self._encrypt_packet(text)
            self._send_json({"type": "message", "from": self.me_disp, "to": self.peer_disp, **pkt})
            self._save_log({
                "who": self.me_disp,
                "direction": "sent",
                "to": self.peer_disp,
                "ciphertext": pkt["ciphertext"],
                "plaintext": text
            })
            print(f"[{self.me_disp}]  Sent encrypted reply to {self.peer_disp}. Waiting again...")

def main():
    me = input("Enter your name : ").strip() or "Bob"
    peer = input("Enter sender name : ").strip() or "Alice"
    app = ReceiverApp(me, peer)
    app.connect()
    app.run()

if __name__ == "__main__":
    main()
