'''
Program: FenrirSight.py
Author: Prin Puyakul
Date: 22/05/2025

==================================================================================================================================================================
Purpose: 
This Python script is a versatile and user-friendly tool for scanning network ports. 
It utilises four libraries: geoip2.database, socket, nmap, and os to provide comprehensive scanning functionalities. 
Here's an overview of the script's workflow and features:

    User Input and Validation:
        1. The script begins by prompting the user to input a target address.
        2. It validates the entered address to ensure it is correct. If the address is invalid, the script will repeatedly ask for a valid input.

    Menu Selection:
        Upon entering a valid address, the user is presented with a menu offering five options:
            1. Scan All Ports: This option allows the user to scan all available ports on the target address.
            2. Scan Specific Port: This option enables the user to scan a specific port on the target address.
            3. Scan Top Ports: This option lets the user scan the most commonly used ports.
            4. Scan Port Range: This option permits the user to specify a range of ports to scan.
            5. Exit: This option allows the user to exit the script.

    Functional Libraries:
        geoip2.database: Used for geographical IP location data.
        socket: Employed for network connections and communication.
        nmap: Utilised for network discovery and security auditing.
        os: Used for interacting with the operating system.

This script is designed to be robust, ensuring that users can easily interact with it to perform various types of port scans on a specified target address.

==================================================================================================================================================================

Result explaination:
    1. The script will display the physical location of the target host, including the continent, country, city, and postal code 
    along with the IP address, protocol, and state.
        
        Host name: www.scanme.org
        IP address: 45.33.32.156
        Continent name: North America
        Country name: United States
        City name: Fremont
        Postal code: 94536
        State: up
        Protocol: tcp

    2. It will then perform the selected port scan based on the user's choice.
    3. The script will display the results of the port scan, including the port number, state, service name, reason, and Common Platform Enumeration (CPE)* data.
    *Note: CPE data provides information about the vendor, product, version, and update of the service running on the port.
    4. Port status will be colour-coded for easy identification: green for open, red for closed, and yellow for other states.
            
    --------------------------------------------------------------------------------------------------------------
    Port  State      Service Name         Reason               Common Platform Enumeration
    --------------------------------------------------------------------------------------------------------------
    21    closed     ftp                  conn-refused        
    22    open       ssh                  syn-ack              linux linux_kernel
    
    5. Scan results will also be saved to a file named 'scan_result.txt' for future reference.

==================================================================================================================================================================

'''
# Import libraries
import geoip2.database
import socket
import nmap
import os

# Define constants
SCAN_RESULT = "./scan_result.txt"

USER_CHOICE = ""

VALID_HOST = False

# GeoIP constants
COUNTRY_DB_READER = geoip2.database.Reader('GeoLite2-Country.mmdb')
CITY_DB_READER = geoip2.database.Reader('GeoLite2-City.mmdb')

# Nmap contstants
NMAP_SCAN = nmap.PortScanner()
PORT_NUMBERS = ""
SCANNED_PORT = []

########### Functions definitions ###########

# Function 0.1 Clear the screen
def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    

# Fucntion 1: Get a host name from the user
def get_host_name():
    host_name = input("Please enter host name: ")
    return host_name

# Function 2 Validate the host name


def validate_host_name(hostname):
    try:
        print("Validating host name...")
        # Get IP address of the ifinput host is valid
        ip_address = socket.gethostbyname(hostname)
        VALID_HOST = True
        return ip_address, VALID_HOST
    except:
        VALID_HOST = False
        return None, VALID_HOST

# Function 3: Pysical location of the host


def get_host_location(host_name, host_ip):
    hostCountryInfo = COUNTRY_DB_READER.country(host_ip)
    hostCityInfo = CITY_DB_READER.city(host_ip)
    print("#########################################################\n" +
          "############# Target host physical location #############\n" +
          "#########################################################\n")
    print(f"Host name: {host_name}\nIP address: {host_ip}")
    print(f"Continent name: {hostCountryInfo.continent.name}")
    print(f"Country name: {hostCountryInfo.country.name}")
    print(f"City name: {hostCityInfo.city.name}")
    print(f"Postal code: {hostCityInfo.postal.code}")

# Pre-requirement for function 4: Parse CPE data
# The purpose of this function is tp extract and convert the Common Platform Enumeration (CPE) string data
# from the Nmap scan result to a dictionary format.


def parse_cpe_data(cpe_string):
    # Remove prefix cpe: and split them by :
    components = cpe_string[4:].split(':')

    # Create a dictionary to store the CPE data
    cpe_date = {
        'part': components[0] if len(components) > 0 else None,
        'vendor': components[1] if len(components) > 1 else None,
        'product': components[2] if len(components) > 2 else None,
        'version': components[3] if len(components) > 3 else None,
        'update': components[4] if len(components) > 4 else None
    }
    return cpe_date


# Function 4: Nmap scan
def nmap_scan(host, host_ip):
    # Get the physical location of the host from get_host_location function
    get_host_location(host, host_ip)

    for host in NMAP_SCAN.all_hosts():
        # print(f"Host: {host :s} {NMAP_SCAN[host].hostname()}")
        print(F"State: {NMAP_SCAN[host].state() :s}")
        for protocols in NMAP_SCAN[host].all_protocols():
            print(f"Protocol: {protocols:s}\n")

            SCANNED_PORT = NMAP_SCAN[host][protocols].keys()
            print("----------------------"*5)
            print(
                f"{ 'Port' :5s} {'State' :10s} {'Service Name' :20s} { 'Reason' :20s} { 'Common Platform Enumeration' :20s}")
            print("----------------------"*5)

            for port in SCANNED_PORT:
                port_status = NMAP_SCAN[host][protocols][port]['state']
                port_service = NMAP_SCAN[host][protocols][port]['name']
                port_reason = NMAP_SCAN[host][protocols][port]['reason']
                port_cpe = NMAP_SCAN[host][protocols][port]['cpe']
                if port_cpe:
                    # Parse the CPE data
                    cpe_info = parse_cpe_data(port_cpe)
                    # Colour code the output according to the port status
                    # Green for open, red for closed everything else (or filtered) will show as yellow.
                    port_status_color = "\033[92m" if port_status == 'open' else "\033[91m" if port_status == 'closed' else "\033[93m"
                    print(
                        f"{port :5d} {port_status_color}{port_status :10s}\033[0m {port_service :20s} {port_reason :20s} {cpe_info['vendor'] :3s} {cpe_info['product'] :3s}")
                else:
                    port_status_color = "\033[92m" if port_status == 'open' else "\033[91m" if port_status == 'closed' else "\033[93m"
                    print(
                        f"{port :5d} {port_status_color}{port_status :10s}\033[0m {port_service :20s} {port_reason :20s}")
            print("----------------------"*5)
    input("\nPress enter to return to the Scan options menu...")
    clear_screen()

########### 5. Menu option function definitions ###########
# Function 5.1: Scan all ports


def scan_all_ports(host_name, host_ip):
    clear_screen()
    print("Scanning all ports...")
    NMAP_SCAN.scan(hosts=host_name, arguments=f'-p- -sV -T4')
    nmap_scan(host_name, host_ip)

# Function 5.2: Scan specific ports


def scan_specific_ports(host_name, host_ip):
    clear_screen()
    print("Scanning specific ports...")
    PORT_NUMBERS = input("Enter the port number: ")
    NMAP_SCAN.scan(hosts=host_name, ports=PORT_NUMBERS,
                   arguments=f'-sV --script=banner -oN {SCAN_RESULT}')
    nmap_scan(host_name, host_ip)

# Function 5.3: Scan top ports


def scan_top_ports(host_name, host_ip):
    clear_screen()
    print("Scanning top ports...")
    NMAP_SCAN.scan(hosts=host_name,
                   arguments=f'-F -sV --script=banner -oN {SCAN_RESULT}')
    nmap_scan(host_name, host_ip)

# Function 5.4: Scan port range


def scan_port_range(host_name, host_ip):
    clear_screen()
    print("Scanning port range...")
    PORT_NUMBERS = input("Enter the port range (e.g. 20-80): ")
    NMAP_SCAN.scan(hosts=host_name, ports=PORT_NUMBERS,
                   arguments=f'-sV --script=banner -oN {SCAN_RESULT}')
    nmap_scan(host_name, host_ip)

# Function 5.5: Exit program


def exit_program():
    print("Exiting the program...")
    exit()


# Menu options constants
MENU_CHOICES = {
    "1": scan_all_ports,
    "2": scan_specific_ports,
    "3": scan_top_ports,
    "4": scan_port_range,
    "5": exit_program
}

# Main function


def main():

    host_name = get_host_name()
    hostIP, isValid = validate_host_name(host_name)

    while not isValid:
        print("\nInvalid host name. Please try again.")
        host_name = get_host_name()
        hostIP, isValid = validate_host_name(host_name)
        # Debugging line
        # print(f"hostIP: {hostIP}, isValid: {isValid}")
        if isValid:
            break

    while isValid:

        # Display menu options for user to choose.
        print("\nScan options menu: \n" +
              "======================================")

        for menu_choice, menu_description in MENU_CHOICES.items():
            print(
                f"{menu_choice}: {menu_description.__name__.replace('_', ' ').title()}")

        # Get user choice and update USER_CHOICE variable
        USER_CHOICE = input("Enter your choice: ")
        if USER_CHOICE in MENU_CHOICES:
            if MENU_CHOICES[USER_CHOICE] == exit_program:
                MENU_CHOICES[USER_CHOICE]()
            else:
                MENU_CHOICES[USER_CHOICE](host_name, hostIP)
        else:
            clear_screen()
            print("Invalid choice. Please try again.")


# Start main function
if __name__ == "__main__":
    main()
