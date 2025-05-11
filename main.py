from auth import register_user, login_user
from interface import start_interface

def main():
    print("=== Welcome to RSA Chat App ===")
    
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Select an option: ").strip()

        if choice == '1':
            register_user()

        elif choice == '2':
            user = login_user()
            if user:
                start_interface(user)

        elif choice == '3':
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
