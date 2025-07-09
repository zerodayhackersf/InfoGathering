import os
import socket
import dns.resolver
import requests
import re
from PIL import Image

# ===== Fixed WHOIS Implementation =====
def whois_lookup_fixed(domain):
    try:
        import whois  # Using python-whois instead of pythonwhois
        print(f"\n[+] Performing WHOIS lookup for {domain}...")
        w = whois.whois(domain)
        for key, value in w.items():
            print(f"  {key}: {value}")
    except Exception as e:
        print(f"  [!] Error: {e}")

# ===== Tool Functions =====
def port_scan(target, ports):
    print(f"\n[+] Scanning {target}...")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"  [✓] Port {port} is open")
        sock.close()

def dns_enum(domain):
    print(f"\n[+] Enumerating DNS records for {domain}...")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            print(f"\n{record} Records:")
            for server in answers:
                print(f"  {server.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue

def dir_bruteforce(url, wordlist="common_dirs.txt"):
    print(f"\n[+] Bruteforcing directories on {url}...")
    try:
        with open(wordlist, 'r') as f:
            directories = f.read().splitlines()
        
        for dir in directories:
            full_url = f"{url}/{dir}"
            try:
                response = requests.get(full_url, timeout=3)
                if response.status_code == 200:
                    print(f"  [✓] Found: {full_url}")
            except requests.RequestException:
                continue
    except FileNotFoundError:
        print(f"[!] Wordlist file {wordlist} not found!")

def subdomain_finder(domain, wordlist="subdomains.txt"):
    print(f"\n[+] Finding subdomains for {domain}...")
    try:
        with open(wordlist, 'r') as f:
            subdomains = f.read().splitlines()
        
        for sub in subdomains:
            url = f"http://{sub}.{domain}"
            try:
                requests.get(url, timeout=3)
                print(f"  [✓] Found: {url}")
            except requests.ConnectionError:
                continue
    except FileNotFoundError:
        print(f"[!] Wordlist file {wordlist} not found!")

def email_harvester(url):
    print(f"\n[+] Harvesting emails from {url}...")
    try:
        response = requests.get(url)
        emails = re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text)
        if emails:
            for email in set(emails):
                print(f"  {email}")
        else:
            print("  [!] No emails found.")
    except requests.RequestException as e:
        print(f"  [!] Error: {e}")

def username_check(username):
    print(f"\n[+] Checking username {username} across platforms...")
    sites = {
        'GitHub': f'https://github.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}'
    }
    
    for site, url in sites.items():
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(f"  [✓] {site}: {url} - Exists")
            else:
                print(f"  [✗] {site}: {url} - Not found")
        except requests.RequestException as e:
            print(f"  [!] {site}: Error - {e}")

def geoip_lookup(ip):
    print(f"\n[+] Performing GeoIP lookup for {ip}...")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            print(f"  Country: {data['country']}")
            print(f"  Region: {data['regionName']}")
            print(f"  City: {data['city']}")
            print(f"  ISP: {data['isp']}")
            print(f"  Lat/Lon: {data['lat']},{data['lon']}")
        else:
            print(f"  [!] Lookup failed: {data.get('message', 'Unknown error')}")
    except requests.RequestException as e:
        print(f"  [!] Error: {e}")

def extract_metadata(file_path):
    print(f"\n[+] Extracting metadata from {file_path}...")
    try:
        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif')):
            image = Image.open(file_path)
            for key, value in image.info.items():
                print(f"  {key}: {value}")
        else:
            print("  [!] File format not supported for metadata extraction")
    except Exception as e:
        print(f"  [!] Error: {e}")

# ===== Main Menu =====
def main():
    while True:
        print("\n" + "="*50)
        print("Information Gathering Toolkit".center(50))
        print("="*50)
        print("1. Port Scanner")
        print("2. DNS Enumeration")
        print("3. Directory Bruteforcer")
        print("4. Subdomain Finder")
        print("5. Email Harvester")
        print("6. Username Checker")
        print("7. WHOIS Lookup")
        print("8. GeoIP Locator")
        print("9. Metadata Extractor")
        print("0. Exit")
        
        choice = input("\nSelect an option (0-9): ")
        
        if choice == "1":
            target = input("Enter target IP/hostname: ")
            port_range = input("Enter port range (e.g., 1-100): ")
            start, end = map(int, port_range.split('-'))
            port_scan(target, range(start, end+1))
        
        elif choice == "2":
            domain = input("Enter domain: ")
            dns_enum(domain)
        
        elif choice == "3":
            url = input("Enter URL (e.g., http://example.com): ")
            wordlist = input("Enter wordlist path [common_dirs.txt]: ") or "common_dirs.txt"
            dir_bruteforce(url, wordlist)
        
        elif choice == "4":
            domain = input("Enter domain: ")
            wordlist = input("Enter wordlist path [subdomains.txt]: ") or "subdomains.txt"
            subdomain_finder(domain, wordlist)
        
        elif choice == "5":
            url = input("Enter URL to scan: ")
            email_harvester(url)
        
        elif choice == "6":
            username = input("Enter username to check: ")
            username_check(username)
        
        elif choice == "7":
            domain = input("Enter domain: ")
            whois_lookup_fixed(domain)
        
        elif choice == "8":
            ip = input("Enter IP address: ")
            geoip_lookup(ip)
        
        elif choice == "9":
            file_path = input("Enter file path: ")
            extract_metadata(file_path)
        
        elif choice == "0":
            print("\n[+] Exiting...")
            break
        
        else:
            print("\n[!] Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting...")