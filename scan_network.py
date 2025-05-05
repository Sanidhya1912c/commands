import subprocess
import socket
import ipaddress
import concurrent.futures

def get_subnet():
    """
    Get subnet range. Change base IP if needed (default is 192.168.1.0/24).
    """
    return ipaddress.ip_network("192.168.1.0/24", strict=False)

def ping_ip(ip):
    """
    Ping an IP address. Returns (IP, is_up).
    Works without root on Termux using system ping.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL
        )
        if result.returncode == 0:
            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
            except socket.herror:
                hostname = "Unknown"
            return (str(ip), hostname)
    except Exception:
        pass
    return None

def scan_network():
    """
    Scans the subnet using multithreading for faster execution.
    """
    subnet = get_subnet()
    print(f"Scanning subnet: {subnet} ...")

    active_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(ping_ip, subnet.hosts())
        for res in results:
            if res:
                active_hosts.append(res)

    return active_hosts

def display_results(devices):
    """
    Display active devices found.
    """
    print("\nActive Devices Found:")
    print("-" * 40)
    print(f"{'IP Address':<18} {'Hostname'}")
    print("-" * 40)
    for ip, hostname in devices:
        print(f"{ip:<18} {hostname}")
    print("-" * 40)

if __name__ == "__main__":
    devices = scan_network()
    display_results(devices)
