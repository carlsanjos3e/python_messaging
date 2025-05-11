import socket
import threading
import time

BROADCAST_PORT = 54545
BROADCAST_INTERVAL = 10  # seconds
online_users = {}

def send_broadcast(username, ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = f"{username},{ip}".encode()
    while True:
        sock.sendto(message, ('255.255.255.255', BROADCAST_PORT))
        time.sleep(BROADCAST_INTERVAL)

def listen_for_users(my_username):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', BROADCAST_PORT))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            decoded = data.decode().strip()
            username, ip = decoded.split(',')
            if username != my_username:  # Ignore self
                online_users[username] = ip
        except Exception as e:
            print(f"[!] Discovery error: {e}")
