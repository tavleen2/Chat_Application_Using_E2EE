import socket
import threading
import json

HOST, PORT = "127.0.0.1", 5000
clients = {}      
pubkeys = {}      
lock = threading.Lock()

def send_json(sock, obj):
    try:
        sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))
    except Exception:
        pass

def recv_lines(sock):
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            yield line.decode("utf-8")
    if buf:
        yield buf.decode("utf-8")

def handle_client(conn, addr):
    user_lc = None
    try:
        for line in recv_lines(conn):
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            t = msg.get("type")

            if t == "register":
                user = (msg.get("username") or "").strip()
                user_lc = user.lower()
                with lock:
                    clients[user_lc] = conn
                    pubkeys[user_lc] = msg["public_key"]
                print(f"[SERVER] {user} registered. Public key stored.")
                send_json(conn, {"type": "register_ok", "you": user})

            elif t == "get_pubkey":
                target = (msg.get("target") or "").strip().lower()
                with lock:
                    key = pubkeys.get(target)
                if key:
                    send_json(conn, {"type": "pubkey", "username": target, "public_key": key})
                else:
                    send_json(conn, {"type": "error", "message": f"No public key for {msg.get('target')}"})

            elif t in ("session_key", "message"):
                to_disp = (msg.get("to") or "").strip()
                to_lc = to_disp.lower()
                with lock:
                    dst = clients.get(to_lc)
                if dst:
                    if t == "session_key":
                        print(f"[SERVER] Encrypted session_key {msg.get('from')} -> {to_disp}: {str(msg.get('payload'))[:60]}...")
                    else:
                        print(f"[SERVER] Encrypted message {msg.get('from')} -> {to_disp}: {str(msg.get('ciphertext'))[:60]}...")
                    send_json(dst, msg)
                else:
                    send_json(conn, {"type": "error", "message": f"{to_disp} not connected"})

            else:
                send_json(conn, {"type": "error", "message": "Unknown message type"})

    except ConnectionResetError:
        pass
    finally:
        if user_lc:
            with lock:
                if clients.get(user_lc) is conn:
                    del clients[user_lc]
        conn.close()
        print(f"[SERVER] {(user_lc or addr)} disconnected.")

def main():
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            c, a = s.accept()
            threading.Thread(target=handle_client, args=(c, a), daemon=True).start()

if __name__ == "__main__":
    main()
