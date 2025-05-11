from discovery import send_broadcast, listen_for_users, online_users

def start_interface(user):
    # Start discovery service
    threading.Thread(target=listen_for_users, args=(user['username'],), daemon=True).start()
    threading.Thread(target=send_broadcast, args=(user['username'], user['ip']), daemon=True).start()

    while True:
        print("\n--- CHAT MENU ---")
        print("1. View Online Users")
        print("2. Connect to a user")
        print("3. Logout")
        choice = input("Choose an option: ").strip()

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
            print("Logging out.")
            break

        else:
            print("Invalid option.")
