import packet_sniffer
import port_scanner
import hash_cracker
import subdomain_enumerator

def show_menu():
    print("===== Offensive CLI Cybersecurity Toolkit =====")
    print("0. Exit")
    print("1. Packet sniffer")
    print("2. Port and vulnerbility scanner")
    print("3. Hash Cracker")
    print("4. Subdomain enumerator")

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
            hash_cracker.start()
        elif choice == 4:
            subdomain_enumerator.start()
        else:
            print("invalid choice")
        
if __name__ == "__main__":
    main()