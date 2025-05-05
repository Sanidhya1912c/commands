import subprocess
import socket
import ipaddress
import concurrent.futures
import os

def get_subnet():
    """
    Return your local subnet. You can adjust this manually if needed.
    """
    return ipaddress.ip_network("192.168.29.0/24", strict=False)

def ping_ip(ip):
    """
    Pings an IP to check if it's active. Returns device info if alive.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL
        )
        if result.returncode == 0:
            hostname = get_hostname(str(ip))
            mac = get_mac(str(ip))
            return {
                "IP": str(ip),
                "Hostname": hostname,
                "MAC": mac
            }
    except Exception:
        pass
    return None

def get_hostname(ip):
    """
    Tries to get the hostname of an IP address.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_mac(ip):
    """
    Tries to get MAC address of an IP using 'arp' command.
    Only works if IP has been pinged recently.
    """
    try:
        arp_output = subprocess.check_output(["arp", "-n", ip], text=True)
        lines = arp_output.splitlines()
        for line in lines:
            if ip in line:
                parts = line.split()
                for part in parts:
                    if ":" in part and len(part) == 17:
                        return part
        return "Unknown"
    except Exception:
        return "Unknown"

def scan_network():
    """
    Scans the subnet and collects info about active devices.
    """
    subnet = get_subnet()
    print(f"[+] Scanning subnet: {subnet}...\n")

    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(ping_ip, subnet.hosts())
        for res in results:
            if res:
                devices.append(res)

    return devices

def display_results(devices):
    """
    Displays all device info in a table format.
    """
    print(f"{'IP Address':<18} {'Hostname':<30} {'MAC Address'}")
    print("-" * 70)
    for dev in devices:
        print(f"{dev['IP']:<18} {dev['Hostname']:<30} {dev['MAC']}")
    print("-" * 70)
    print(f"[✓] {len(devices)} device(s) found.\n")

if __name__ == "__main__":
    devices = scan_network()
    display_results(devices)
