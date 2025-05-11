from auth import register_user, login_user, load_users
from chat import start_server, connect_to_peer
import threading

def start_interface(user):
    threading.Thread(target=start_server, args=(user['username'], user['ip']), daemon=True).start()

    while True:
        try:
            print("\n--- CHAT MENU ---")
            print("1. View users")
            print("2. Connect to a user")
            print("3. Logout")
            choice = input("Choose an option: ").strip()

            if choice == '1':
                users = load_users()
                print("\n--- Registered Users ---")
                for uname in users:
                    if uname != user['username']:
                        print(f"- {uname} @ {users[uname]['ip']}")
            elif choice == '2':
                target = input("Enter username to connect to: ").strip()
                users = load_users()
                if target not in users:
                    print("User not found.")
                elif target == user['username']:
                    print("Cannot connect to yourself.")
                else:
                    ip = users[target]['ip']
                    connect_to_peer(ip, user['username'], target)
            elif choice == '3':
                print("Logging out.")
                break
            else:
                print("Invalid option.")
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Returning to main menu.")
            break

def main():
    while True:
        try:
            print("\n--- MENU ---")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose an option: ").strip()

            if choice == '1':
                if register_user():
                    continue
            elif choice == '2':
                user = login_user()
                if user:
                    start_interface(user)
            elif choice == '3':
                print("Goodbye.")
                break
            else:
                print("Invalid choice.")
        except KeyboardInterrupt:
            print("\n[!] Exiting.")
            break

if __name__ == '__main__':
    main()
