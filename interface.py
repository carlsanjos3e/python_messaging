import threading
import socket
import crypto_utils
import rsa_crypto
from discovery import send_broadcast, listen_for_users, online_users
import os

CHAT_PORT = 12345

# Store message logs with hash
def log_message(sender, receiver, message, message_hash):
    with open("msg.txt", "a") as f:
        f.write(f"From: {sender}, To: {receiver}, Msg: {message}, Hash: {message_hash}\n")

# Function to handle incoming messages
def handle_connection(conn, addr, my_user):
    print(f"\n[!] Incoming connection from {addr}. Accept? (y/n)")
    choice = input(">> ").strip().lower()
    if choice != 'y':
        conn.close()
        print("[x] Connection refused.")
        return

    # Step 1: Exchange RSA public keys
    conn.send(f"{my_user['public_key'][0]},{my_user['public_key'][1]}".encode())
    peer_key_raw = conn.recv(1024).decode()
    peer_public_key = tuple(map(int, peer_key_raw.split(',')))

    print(f"[✓] Connection established with {addr}. Start chatting!\n")

    def receive():
        while True:
            try:
                encrypted = conn.recv(4096).decode()
                if not encrypted:
                    break
                message, checksum = encrypted.split('||')
                decrypted = crypto_utils.decrypt_message(my_user['private_key'], message)
                valid = crypto_utils.hash_message(decrypted) == checksum
                print(f"\n[Friend]: {decrypted} {'[✓]' if valid else '[CORRUPTED]'}")
                log_message("Friend", my_user['username'], decrypted, checksum)
            except:
                print("[!] Connection lost.")
                break

    def send():
        while True:
            try:
                msg = input()
                checksum = rsa_crypto.hash_message(msg)
                encrypted = crypto_utils.encrypt_message(peer_public_key, msg)
                conn.send(f"{encrypted}||{checksum}".encode())
                log_message(my_user['username'], "Friend", msg, checksum)
            except:
                print("[!] Failed to send message.")
                break

    threading.Thread(target=receive).start()
    threading.Thread(target=send).start()

# Start listening for incoming connections
def start_server(my_user):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', CHAT_PORT))
    server.listen(5)
    print("[Server] Listening for incoming connections...")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_connection, args=(conn, addr, my_user)).start()

# Client connection function
def connect_to_peer(ip, my_username, peer_username):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, CHAT_PORT))
        print(f"[✓] Connected to {peer_username} @ {ip}")

        # Key exchange
        peer_key_raw = sock.recv(1024).decode()
        peer_public_key = tuple(map(int, peer_key_raw.split(',')))
        from auth import get_keys_for_user
        public_key, private_key = get_keys_for_user(my_username)
        sock.send(f"{public_key[0]},{public_key[1]}".encode())

        def receive():
            while True:
                try:
                    encrypted = sock.recv(4096).decode()
                    if not encrypted:
                        break
                    message, checksum = encrypted.split('||')
                    decrypted = crypto_utils.decrypt_message(private_key, message)
                    valid = rsa_crypto.hash_message(decrypted) == checksum
                    print(f"\n[{peer_username}]: {decrypted} {'[✓]' if valid else '[CORRUPTED]'}")
                    log_message(peer_username, my_username, decrypted, checksum)
                except:
                    print("[!] Disconnected.")
                    break

        def send():
            while True:
                try:
                    msg = input()
                    checksum = rsa_crypto.hash_message(msg)
                    encrypted = crypto_utils.encrypt_message(peer_public_key, msg)
                    sock.send(f"{encrypted}||{checksum}".encode())
                    log_message(my_username, peer_username, msg, checksum)
                except:
                    print("[!] Failed to send.")
                    break

        threading.Thread(target=receive).start()
        threading.Thread(target=send).start()

    except Exception as e:
        print(f"[!] Connection failed: {e}")

# Chat menu interface
def start_interface(user):
    # Start background services
    threading.Thread(target=listen_for_users, args=(user['username'],), daemon=True).start()
    threading.Thread(target=send_broadcast, args=(user['username'], user['ip']), daemon=True).start()
    threading.Thread(target=start_server, args=(user,), daemon=True).start()

    while True:
        print("\n--- CHAT MENU ---")
        print("1. View Online Users")
        print("2. Connect to a user")
        print("3. Logout")
        choice = input("Select an option: ").strip()

        if choice == '1':
            print("\n--- Online Users ---")
            if not online_users:
                print("No users currently online.")
            else:
                for uname, ip in online_users.items():
                    print(f"- {uname} @ {ip}")

        elif choice == '2':
            target = input("Enter username to connect to: ").strip()
            if target not in online_users:
                print("User not found or not online.")
            elif target == user['username']:
                print("Cannot connect to yourself.")
            else:
                ip = online_users[target]
                connect_to_peer(ip, user['username'], target)

        elif choice == '3':
            print("Logging out...")
            break
        else:
            print("Invalid input.")
