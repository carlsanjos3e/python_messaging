# RSA Chat App (Single-File Version)
# Supports user registration, login, encrypted chat with RSA, message hashing, and network discovery

import socket
import threading
import hashlib
import time
import os

USERS_FILE = "users.txt"
MSG_FILE = "msg.txt"
BROADCAST_PORT = 9999
CHAT_PORT = 12345
online_users = {}

# === RSA Crypto ===
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if gcd(e, phi) != 1:
        raise ValueError("e and phi are not coprime")
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def encrypt_message(public_key, message):
    e, n = public_key
    return ','.join([str(pow(ord(c), e, n)) for c in message])

def decrypt_message(private_key, encrypted):
    d, n = private_key
    return ''.join([chr(pow(int(c), d, n)) for c in encrypted.split(',')])

def hash_message(msg):
    return hashlib.sha256(msg.encode()).hexdigest()

# === Auth System ===
def save_user(username, ip, password_hash, public_key):
    with open(USERS_FILE, 'a') as f:
        f.write(f"{username},{ip},{password_hash},{public_key[0]}:{public_key[1]}\n")

def load_users():
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 4:
                    uname, ip, pwd_hash, pk = parts
                    e, n = map(int, pk.split(':'))
                    users[uname] = {'ip': ip, 'password_hash': pwd_hash, 'public_key': (e, n)}
    return users

def register_user():
    username = input("Enter username: ")
    ip = input("Enter your IP address: ")
    password = input("Enter password: ")
    users = load_users()
    if username in users:
        print("Username already exists.")
        return None

    password_hash = hash_message(password)
    public_key, private_key = generate_keypair(17, 19)
    save_user(username, ip, password_hash, public_key)
    print("Registration successful.")
    return {'username': username, 'ip': ip, 'public_key': public_key, 'private_key': private_key}

def login_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    users = load_users()
    if username not in users:
        print("User not found.")
        return None
    if users[username]['password_hash'] != hash_message(password):
        print("Incorrect password.")
        return None

    public_key = users[username]['public_key']
    private_key = generate_keypair(17, 19)[1]  # Use fixed p, q for demo
    ip = users[username]['ip']
    return {'username': username, 'ip': ip, 'public_key': public_key, 'private_key': private_key}

# === Discovery ===
def send_broadcast(username, ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        msg = f"{username},{ip}"
        sock.sendto(msg.encode(), ('<broadcast>', BROADCAST_PORT))
        time.sleep(5)

def listen_for_users(my_username):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', BROADCAST_PORT))
    while True:
        data, _ = sock.recvfrom(1024)
        try:
            msg = data.decode()
            uname, ip = msg.split(',')
            if uname != my_username:
                online_users[uname] = ip
        except:
            continue

# === Messaging ===
def log_message(sender, receiver, message, checksum):
    with open(MSG_FILE, 'a') as f:
        f.write(f"From: {sender}, To: {receiver}, Msg: {message}, Hash: {checksum}\n")

def handle_incoming(conn, addr, user):
    print(f"\n[!] Incoming connection from {addr}. Accept? (y/n)")
    if input(">> ").strip().lower() != 'y':
        conn.close()
        return

    conn.send(f"{user['public_key'][0]},{user['public_key'][1]}".encode())
    peer_key = tuple(map(int, conn.recv(1024).decode().split(',')))

    def recv():
        while True:
            try:
                data = conn.recv(4096).decode()
                if not data:
                    break
                enc_msg, checksum = data.split('||')
                msg = decrypt_message(user['private_key'], enc_msg)
                valid = hash_message(msg) == checksum
                print(f"\n[Friend]: {msg} {'[✓]' if valid else '[CORRUPTED]'}")
                log_message("Friend", user['username'], msg, checksum)
            except:
                break

    def send():
        while True:
            msg = input()
            checksum = hash_message(msg)
            enc_msg = encrypt_message(peer_key, msg)
            conn.send(f"{enc_msg}||{checksum}".encode())
            log_message(user['username'], "Friend", msg, checksum)

    threading.Thread(target=recv).start()
    threading.Thread(target=send).start()

def start_server(user):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', CHAT_PORT))
    server.listen(5)
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_incoming, args=(conn, addr, user)).start()

def connect_to_user(ip, user, peer_username):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, CHAT_PORT))
        peer_key = tuple(map(int, sock.recv(1024).decode().split(',')))
        sock.send(f"{user['public_key'][0]},{user['public_key'][1]}".encode())

        def recv():
            while True:
                data = sock.recv(4096).decode()
                if not data:
                    break
                enc_msg, checksum = data.split('||')
                msg = decrypt_message(user['private_key'], enc_msg)
                valid = hash_message(msg) == checksum
                print(f"\n[{peer_username}]: {msg} {'[✓]' if valid else '[CORRUPTED]'}")
                log_message(peer_username, user['username'], msg, checksum)

        def send():
            while True:
                msg = input()
                checksum = hash_message(msg)
                enc_msg = encrypt_message(peer_key, msg)
                sock.send(f"{enc_msg}||{checksum}".encode())
                log_message(user['username'], peer_username, msg, checksum)

        threading.Thread(target=recv).start()
        threading.Thread(target=send).start()

    except Exception as e:
        print(f"[!] Connection failed: {e}")

# === Main Menu ===
def start_interface(user):
    threading.Thread(target=listen_for_users, args=(user['username'],), daemon=True).start()
    threading.Thread(target=send_broadcast, args=(user['username'], user['ip']), daemon=True).start()
    threading.Thread(target=start_server, args=(user,), daemon=True).start()

    while True:
        print("\n--- CHAT MENU ---")
        print("1. View Online Users")
        print("2. Connect to a user")
        print("3. Logout")
        choice = input("Select an option: ")
        if choice == '1':
            print("\n--- Online Users ---")
            for uname, ip in online_users.items():
                print(f"- {uname} @ {ip}")
        elif choice == '2':
            uname = input("Enter username to connect to: ")
            if uname not in online_users:
                print("User not found.")
            else:
                connect_to_user(online_users[uname], user, uname)
        elif choice == '3':
            print("Logging out...")
            break
        else:
            print("Invalid option.")

# === Entry Point ===
def main():
    print("=== Welcome to RSA Chat App ===")
    while True:
        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Select an option: ")
        if choice == '1':
            user = register_user()
            if user:
                start_interface(user)
        elif choice == '2':
            user = login_user()
            if user:
                start_interface(user)
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid input.")

if __name__ == "__main__":
    main()
