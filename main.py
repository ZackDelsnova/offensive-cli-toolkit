import packet_sniffer
import port_scanner

def show_menu():
    print("===== Offensive CLI Cybersecurity Toolkit =====")
    print("0. Exit")
    print("1. Packet sniffer")
    print("2. Port and vulnerbility scanner")
    print("3. Brute force (demo)")
    print("4. Hash Cracker")
    print("5. Subdomain enumerator")

def main():
    while True:
        show_menu()
        choice = int(input("enter your choice: "))
        if choice == 0:
            break
        elif choice == 1:
            packet_sniffer.start_sniffer()
        elif choice == 2:
            port_scanner.start_scan()
        elif choice == 3:
            pass
        elif choice == 4:
            pass
        elif choice == 5:
            pass
        else:
            print("invalid choice")
        
if __name__ == "__main__":
    main()