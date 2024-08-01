import nmap
BLUE = "\33[94m"
END= "\033[0m"
banner = f"""
  {BLUE}


 _____           _                                                 _                        _           _                 
|_   _|         | |    _                                          | |                      | |         | |                
  | | ___   ___ | |   (_)  _ __  _ __ ___   __ _ _ __   __ _ _   _| |_ ___  _ __ ___   __ _| |_ ___  __| |                
  | |/ _ \ / _ \| |       | '_ \| '_ ` _ \ / _` | '_ \ / _` | | | | __/ _ \| '_ ` _ \ / _` | __/ _ \/ _` |                
  | | (_) | (_) | |    _  | | | | | | | | | (_| | |_) | (_| | |_| | || (_) | | | | | | (_| | ||  __| (_| |                
  \_/\___/ \___/|_|   (_) |_| |_|_| |_| |_|\__,_| .__/ \__,_|\__,_|\__\___/|_| |_| |_|\__,_|\__\___|\__,_|                
                                                | |______                                                                 
                                                |_|______|                                                                
  ___        _   _                               ___  _    ______ _____ _   _   ___                      _     _____ __   
 / _ \      | | | |                 _     ____  / _ \| |   | ___ |_   _| \ | | |_  |                    | |   |  _  /  |  
/ /_\ \_   _| |_| |__   ___  _ __  (_)   / __ \/ /_\ | |   | |_/ / | | |  \| |   | | ___  ___  ___ _ __ | |__ | |/' `| |  
|  _  | | | | __| '_ \ / _ \| '__|      / / _` |  _  | |   | ___ \ | | | . ` |   | |/ _ \/ __|/ _ | '_ \| '_ \|  /| || |  
| | | | |_| | |_| | | | (_) | |     _  | | (_| | | | | |___| |_/ /_| |_| |\  /\__/ | (_) \__ |  __| |_) | | | \ |_/ _| |_ 
\_| |_/\__,_|\__|_| |_|\___/|_|    (_)  \ \__,_\_| |_\_____\____/ \___/\_| \_\____/ \___/|___/\___| .__/|_| |_|\___/\___/ 
                                         \____/                                                   | |                     
                                                                                                  |_|                     


{END}"""  
print(banner)
def perform_nmap_scan(target, options):
    nm = nmap.PortScanner()
    
    try:
        nm.scan(hosts=target, arguments=options)

        for host in nm.all_hosts():
            print(f"Host : {host} ({nm[host].hostname()})")
            print(f"State : {nm[host].state()}")

            for proto in nm[host].all_protocols():
                print("----------")
                print(f"Protocol : {proto}")

                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = nm[host][proto][port]
                    print(f"Port : {port}\tState : {port_info['state']}")
                    print(f"\tReason : {port_info['reason']}")
                    
                    if 'version' in port_info:
                        print(f"\tService : {port_info['name']}")
                        print(f"\tVersion : {port_info.get('version', 'N/A')}")
                    
            if 'osmatch' in nm[host]:
                print("OS Details:")
                for os_match in nm[host]['osmatch']:
                    print(f"\tOS Name: {os_match['name']}")
                    print(f"\tOS Accuracy: {os_match['accuracy']}")
    
    except Exception as e:
        print(f"Exception occurred: {str(e)}")

def main():
    target = input("Enter target IP address or range: ")
    print("entered ip address or range is :{target}")
    
    print("\nSelect an Nmap scan option:")
    print("1. TCP SYN Scan (-sS)")
    print("2. TCP Connect Scan (-sT)")
    print("3. UDP Scan (-sU)")
    print("4. OS Detection Scan (-O)")
    print("5. Version Detection Scan (-sV)")
    print("6. Aggressive Scan (-A)")
    print("7. Custom Script Scan (--script)")
    print("8. Save Scan Results in Output Format")
    print("9. Combine Version Detection with Other Scans") 
    choice = input("Enter your choice (1-9): ")

    options = ''
    additional_args = ''
    if choice == '1':
        options = '-sS -Pn -p '
    elif choice == '2':
        options = '-sT -Pn -p '
    elif choice == '3':
        options = '-sU -Pn -p '
    elif choice == '4':
        options = '-O -Pn'
    elif choice == '5':
        options = '-sV -Pn -p '
    elif choice == '6':
        options = '-A -Pn'
    elif choice == '7':
        script = input("Enter Nmap script(s) (comma-separated): ")
        additional_args = f'--script {script}'
    elif choice == '8':
        print("Select output format:")
        print("1. Normal")
        print("2. XML")
        print("3. JSON")
        print("4. Grepable")
        output_choice = input("Enter your choice (1-4): ")
        if output_choice == '1':
            additional_args = '-oN output.txt'
        elif output_choice == '2':
            additional_args = '-oX output.xml'
        elif output_choice == '3':
            additional_args = '-oJ output.json'
        elif output_choice == '4':
            additional_args = '-oG output.gnmap'
        else:
            print("Invalid choice.")
            return
    elif choice == '9':
        base_scan = input("Enter base scan option (e.g., -sS, -sT, -sU): ")
        if base_scan in ['-sS', '-sT', '-sU']:
            options = f'{base_scan} -sV -Pn -p 1-1000'
        else:
            print("Invalid base scan option.")
            return
    else:
        print("Invalid choice.")
        return
        
    if choice in ['1', '2', '3', '5', '9']:
        port_range = input("Enter port range (e.g., 1-1000 or 80,443): ")
        options += f' {port_range}'
    
    if additional_args:
        options += f' {additional_args}'

    print(f"\nPerforming Nmap scan with options: {options}")
    perform_nmap_scan(target, options)

if __name__ == "__main__":
    main()
