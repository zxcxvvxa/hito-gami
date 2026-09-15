import subprocess
import time
import re

MAX_CONNECTIONS = 100
CHECK_INTERVAL = 10
WHITELIST = ["127.0.0.1", "::1"]

def get_connection_counts():
    counts = {}
    try:
        # Runs netstat to count IP connections
        output = subprocess.check_output("netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c", shell=True).decode()
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) == 2:
                count, ip = int(parts[0]), parts[1]
                counts[ip] = count
    except Exception as e:
        print(f"[Anti-DDoS Error] Failed to fetch netstat: {e}")
    return counts

def block_ip(ip):
    if ip in WHITELIST:
        return
    try:
        # Check if already blocked
        check = subprocess.run(f"iptables -C INPUT -s {ip} -j DROP", shell=True, stderr=subprocess.DEVNULL)
        if check.returncode != 0:
            subprocess.run(f"iptables -I INPUT -s {ip} -j DROP", shell=True, check=True)
            print(f"[Anti-DDoS] Blocked malicious IP: {ip}")
    except Exception as e:
        print(f"[Anti-DDoS Error] Could not block IP {ip}: {e}")

def main():
    print("[Anti-DDoS] Service started monitoring connection limits...")
    while True:
        connections = get_connection_counts()
        for ip, count in connections.items():
            if count > MAX_CONNECTIONS:
                print(f"[Anti-DDoS Warning] High connections detected from {ip}: {count}")
                block_ip(ip)
        time.sleep(CHECK_INTERVAL)

if __name__ == '__main__':
    main()
