from scapy.all import ARP, Ether, srp
import socket

def get_local_network_info():
    """
    Returns the default local subnet.
    Modify this if you want to scan a different range.
    """
    return "192.168.1.0/24"  # Common default. Change if needed.

def scan_network(subnet):
    """
    Scans the given subnet and returns a list of devices found.
    Each device is a dictionary with IP, MAC, and Hostname (if available).
    """
    print(f"Scanning network: {subnet} ...")

    # Create an ARP request packet
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and get the response
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"

        devices.append({
            "IP": received.psrc,
            "MAC": received.hwsrc,
            "Hostname": hostname
        })
    
    return devices

def display_devices(devices):
    """
    Nicely prints the list of found devices.
    """
    print("\nDevices found on the network:")
    print("-" * 50)
    print(f"{'IP Address':<16} {'MAC Address':<18} {'Hostname'}")
    print("-" * 50)

    for device in devices:
        print(f"{device['IP']:<16} {device['MAC']:<18} {device['Hostname']}")

if __name__ == "__main__":
    subnet = get_local_network_info()
    devices = scan_network(subnet)
    display_devices(devices)
