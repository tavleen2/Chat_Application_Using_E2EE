# server.py
import socket
import threading
import json

HOST = "127.0.0.1"
PORT = 5000

clients = {}        # username -> socket
public_keys = {}    # username -> PEM string

lock = threading.Lock()

def send_json(sock, obj):
    data = (json.dumps(obj) + "\n").encode("utf-8")
    sock.sendall(data)

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
    username = None
    try:
        for line in recv_lines(conn):
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            mtype = msg.get("type")

            if mtype == "register":
                # {type:"register", username:"Alice", public_key:"PEM"}
                with lock:
                    username = msg["username"]
                    clients[username] = conn
                    public_keys[username] = msg["public_key"]
                print(f"[SERVER] {username} registered. PubKey stored.")
                send_json(conn, {"type": "register_ok"})

            elif mtype == "get_pubkey":
                # {type:"get_pubkey", target:"Bob"}
                target = msg.get("target")
                with lock:
                    key = public_keys.get(target)
                if key:
                    send_json(conn, {"type": "pubkey", "username": target, "public_key": key})
                else:
                    send_json(conn, {"type": "error", "message": f"No public key for {target}"})

            elif mtype in ("session_key", "message"):
                # Forward to target; log encrypted payload visibly
                to_user = msg.get("to")
                with lock:
                    target_conn = clients.get(to_user)
                if target_conn:
                    # Log encrypted content on server (cannot decrypt)
                    if mtype == "session_key":
                        print(f"[SERVER] Encrypted session_key from {msg.get('from')} -> {to_user}: {msg.get('payload')[:60]}...")
                    else:
                        # message has nonce/ciphertext/tag; log ciphertext
                        print(f"[SERVER] Encrypted message from {msg.get('from')} -> {to_user}: {msg.get('ciphertext')[:60]}...")
                    send_json(target_conn, msg)
                else:
                    send_json(conn, {"type": "error", "message": f"{to_user} not connected"})

            else:
                send_json(conn, {"type": "error", "message": "Unknown message type"})

    except ConnectionResetError:
        pass
    finally:
        if username:
            with lock:
                if clients.get(username) is conn:
                    del clients[username]
        conn.close()
        print(f"[SERVER] {username or addr} disconnected.")

def main():
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
