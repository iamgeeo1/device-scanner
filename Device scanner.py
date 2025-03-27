import scapy.all as scapy
import re
import socket
import time
import sys
import pyfiglet
from datetime import datetime

# Regular Expression Pattern to recognize IPv4 addresses with subnet mask.
ip_add_range_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$")

# Function to resolve the device name (hostname) from IP address
def get_device_name(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]  # Return the hostname
    except socket.herror:
        return "Unknown Device"  # If the hostname is not found

# Function to display ARP results in a table format
def display_arp_results(results):
    # Get the current date
    current_date = datetime.now().strftime("%m/%d/%Y")
    
    # Header with consistent column width and improved formatting
    header = f"{'DATE':<12} {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'DEVICE NAME':<30} {'CONNECTED':<10}"
    separator = "-" * len(header)
    
    print(header)
    print(separator)  # Line separator
    
    for sent, received in results:
        # Resolve device name and print the formatted result
        device_name = get_device_name(received.psrc)
        ip_address = received.psrc
        mac_address = received.hwsrc
        connected = "Y"  # Mark as connected if we found the device

        # Print the details in tabular format, ensuring that everything aligns well
        print(f"{current_date:<12} {ip_address:<18} {mac_address:<20} {device_name:<30} {connected:<10}")

# Function to simulate a loading animation while scanning
def loading_animation():
    print("Scanning in progress, please wait...")
    animation = "|/-\\"
    for i in range(20):  # Adjust the range as necessary for the scan duration
        sys.stdout.write(f"\r{animation[i % len(animation)]} Scanning...")
        sys.stdout.flush()
        time.sleep(0.2)  # Adjust the speed of the animation

# Function to perform ARP scan
def perform_arp_scan():
    while True:
        ip_add_range_entered = input("\nPlease enter the IP address range (e.g., 192.168.1.0/24): ")

        # Validate the input using regex.
        if ip_add_range_pattern.match(ip_add_range_entered):
            print(f"{ip_add_range_entered} is a valid IP address range.")
            break
        else:
            print(f"Invalid IP address range. Please follow the correct format (e.g., 192.168.1.0/24).")

    # Simulate loading animation and send ARP requests to the entered IP address range.
    try:
        loading_animation()  # Show loading animation
        arp_result = scapy.arping(ip_add_range_entered, timeout=2, verbose=False)

        # Check if there were any results
        if arp_result[0]:
            display_arp_results(arp_result[0])
        else:
            print("No devices found in the given IP range.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Function to display the ASCII art welcome message
def display_ascii_art():
    ascii_art = pyfiglet.figlet_format("Device Scanner")
    print(ascii_art)
    print("Welcome to the Device Scanner Program. Please choose an option below.\n")

# Main menu to keep the program running
def main_menu():
    while True:
        display_ascii_art()  # Display ASCII art for the title
        print("\033[1;32m===================================")  # Green color for menu borders
        print("1. Perform A Scan")
        print("2. Exit")
        print("===================================")
        print("\033[0m")  # Reset color to default
        choice = input("Please choose an option (1 or 2): ")

        if choice == '1':
            perform_arp_scan()
        elif choice == '2':
            print("\nExiting the program... Thank you!")
            break
        else:
            print("\033[1;31mInvalid choice. Please select 1 or 2.\033[0m")  # Red color for error messages

# Start the program by showing the main menu
if __name__ == "__main__":
    main_menu()
