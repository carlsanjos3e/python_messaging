import socket
import threading
import hashlib
from crypto_utils import generate_keypair, encrypt_message, decrypt_message

MSG_LOG = 'msg.txt'
my_public_key, my_private_key = generate_keypair()

def log_message(sender, recipient, message):
    try:
        checksum = hashlib.sha256(message.encode()).hexdigest()
        with open(MSG_LOG, 'a') as f:
            f.write(f"{sender}->{recipient}: {message} [SHA256: {checksum}]\n")
    except Exception as e:
        print(f"Failed to log message: {e}")

def handle_client(conn, addr, my_username):
    try:
        print(f"\nIncoming connection from {addr}")
        decision = input("Do you want to accept the chat? (yes/no): ").strip().lower()
        if decision != 'yes':
            conn.send("REJECT".encode())
            conn.close()
            return

        conn.send("ACCEPT".encode())
        conn.send(f"{my_public_key[0]},{my_public_key[1]}".encode())
        their_key_raw = conn.recv(1024).decode()
        their_public_key = tuple(map(int, their_key_raw.split(',')))

        print("Connected. Type 'exit' to end chat.")
        start_chat(conn, their_public_key, my_private_key, my_username, "Peer")

    except Exception as e:
        print(f"Error during chat setup: {e}")
        conn.close()

def start_server(my_username, my_ip):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((my_ip, 12345))
        server.listen(5)
        print(f"[Server] Listening on {my_ip}:12345...")
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr, my_username)).start()
    except Exception as e:
        print(f"Server error: {e}")

def connect_to_peer(target_ip, my_username, peer_username):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_ip, 12345))

        response = client.recv(1024).decode()
        if response != "ACCEPT":
            print("Chat request was rejected.")
            client.close()
            return

        their_key_raw = client.recv(1024).decode()
        their_public_key = tuple(map(int, their_key_raw.split(',')))
        client.send(f"{my_public_key[0]},{my_public_key[1]}".encode())

        print("Connected. Type 'exit' to end chat.")
        start_chat(client, their_public_key, my_private_key, my_username, peer_username)

    except Exception as e:
        print(f"Connection failed: {e}")

def start_chat(conn, their_public_key, my_private_key, my_username, peer_username):
    def receive():
        while True:
            try:
                encrypted = conn.recv(4096).decode()
                if not encrypted:
                    break
                decrypted = decrypt_message(my_private_key, encrypted)
                print(f"\n[{peer_username}]: {decrypted}")
                log_message(peer_username, my_username, decrypted)
            except:
                break

    def send():
        while True:
            try:
                msg = input()
                if msg.lower() == 'exit':
                    conn.close()
                    break
                encrypted = encrypt_message(their_public_key, msg)
                conn.send(encrypted.encode())
                log_message(my_username, peer_username, msg)
            except:
                print("Error sending message.")
                break

    threading.Thread(target=receive, daemon=True).start()
    send()
