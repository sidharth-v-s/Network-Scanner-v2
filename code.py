import nmap
import requests
import concurrent.futures
import threading

# Subdirectory Scanner Function
def find_subdirectories(url, wordlist_file, callback=None, stopInstance=None):
    results = []
    
    # Ensure the URL format ends with a '/'
    if not url.endswith('/'):
        url += '/'
    
    # Read the wordlist file with the appropriate encoding
    try:
        with open(wordlist_file, 'r', encoding='ISO-8859-1') as file:
            subdirs = file.read().splitlines()
    except FileNotFoundError:
        results.append(f"Error: The file '{wordlist_file}' was not found.")
        if callback:
            callback("\n".join(results))
        return results
    except UnicodeDecodeError:
        # Try with UTF-8 if ISO-8859-1 fails
        try:
            with open(wordlist_file, 'r', encoding='utf-8') as file:
                subdirs = file.read().splitlines()
        except UnicodeDecodeError:
            results.append(f"Error: The file '{wordlist_file}' contains invalid characters.")
            if callback:
                callback("\n".join(results))
            return results

    results.append(f"Starting directory scan on: {url}\n")
    if callback:
        callback("\n".join(results))

    # Check each subdirectory in the wordlist
    found_count = 0
    for subdir in subdirs:
        if stopInstance and not stopInstance.scan:
            print('end thread')
            break
        if not subdir.strip():  # Skip empty lines
            continue
            
        full_url = f"{url}{subdir}"
        try:
            # Don't follow redirects automatically to check for them
            response = requests.get(full_url, timeout=5, allow_redirects=False)
            status_code = response.status_code
            
            # Check for found directories (200 OK)
            if status_code == 200:
                found_count += 1
                results.append(f"Found: {full_url} [Status: 200 OK]")
                if callback and found_count % 5 == 0:  # Update UI every 5 findings
                    callback("\n".join(results))
            # Check for redirects (3xx status codes)
            elif 300 <= status_code < 400:
                found_count += 1
                redirect_url = response.headers.get('Location', 'Unknown')
                results.append(f"Found: {full_url} [Status: {status_code} Redirect → {redirect_url}]")
                if callback and found_count % 5 == 0:
                    callback("\n".join(results))
            # Other interesting status codes
            elif status_code in [401, 403, 404, 500]:
                found_count += 1
                status_text = {
                    401: "Unauthorized", 
                    403: "Forbidden", 
                    404: "Not Found",
                    500: "Server Error"
                }.get(status_code, "")
                results.append(f"Found: {full_url} [Status: {status_code} {status_text}]")
                if callback and found_count % 5 == 0:
                    callback("\n".join(results))
        except requests.RequestException as e:
            results.append(f"Error reaching {full_url}: {e}")
            if callback and found_count % 5 == 0:
                callback("\n".join(results))
    
    results.append(f"\nScan complete. Found {found_count} directories.")
    if callback:
        callback("\n".join(results))
    return results

# Host Lookup Function with vendor name detection
def nmap_scan(subnet, callback=None):
    results = []
    results.append(f"Starting host lookup on subnet: {subnet}")
    if callback:
        callback("\n".join(results))
        
    try:
        nm = nmap.PortScanner()
        # Use -sn (ping scan) with --script=broadcast-arp-discovery to get MAC and vendor info
        nm.scan(hosts=subnet, arguments='-sn')
        up_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
        
        if up_hosts:
            results.append("\nHosts found:")
            for host in up_hosts:
                # Basic host info
                host_info = f"IP: {host}"
                
                # Try to get hostname if available
                if 'hostnames' in nm[host] and nm[host]['hostnames'] and len(nm[host]['hostnames']) > 0:
                    if 'name' in nm[host]['hostnames'][0] and nm[host]['hostnames'][0]['name']:
                        host_info += f", Hostname: {nm[host]['hostnames'][0]['name']}"
                
                # Try to get MAC address and vendor if available
                if 'addresses' in nm[host]:
                    if 'mac' in nm[host]['addresses']:
                        mac = nm[host]['addresses']['mac']
                        host_info += f", MAC: {mac}"
                        
                        # Check if vendor info is available
                        if 'vendor' in nm[host] and mac in nm[host]['vendor']:
                            vendor = nm[host]['vendor'][mac]
                            host_info += f", Vendor: {vendor}"
                
                results.append(host_info)
        else:
            results.append("No hosts found.")
    except Exception as e:
        results.append(f"Error during host lookup: {str(e)}")
    
    if callback:
        callback("\n".join(results))
    return results

# Port Scanner Function with customizable scan types
def port_scanner(port_ip, callback=None, scan_type="-A -T4"):
    results = []
    results.append(f"Starting port scan on IP: {port_ip}")
    results.append(f"Scan type: {scan_type}")
    if callback:
        callback("\n".join(results))
        
    try:
        np = nmap.PortScanner()
        np.scan(port_ip, arguments=scan_type)
        
        # Make sure the IP was scanned successfully
        if port_ip not in np.all_hosts():
            results.append(f"No results for {port_ip}. The host may be down or blocking scans.")
            if callback:
                callback("\n".join(results))
            return results
            
        for proto in np[port_ip].all_protocols():
            results.append(f"\nProtocol: {proto}")
            lport = sorted(np[port_ip][proto].keys())
            
            # Count open ports
            open_count = 0
            
            for port in lport:
                port_state = np[port_ip][proto][port]['state']
                if port_state == 'open':
                    open_count += 1
                    service = np[port_ip][proto][port].get('name', 'unknown')
                    product = np[port_ip][proto][port].get('product', '')
                    version = np[port_ip][proto][port].get('version', '')
                    extrainfo = np[port_ip][proto][port].get('extrainfo', '')
                    
                    port_info = f"Port {port}/{proto}: open, Service: {service}"
                    
                    # Add product, version and extra info if available
                    if product:
                        port_info += f", Product: {product}"
                    if version:
                        port_info += f", Version: {version}"
                    if extrainfo and extrainfo != '':
                        port_info += f" ({extrainfo})"
                        
                    results.append(port_info)
            
            if open_count == 0:
                results.append(f"No open {proto} ports found.")
        
        # Try to get OS info if available
        if 'osmatch' in np[port_ip] and np[port_ip]['osmatch']:
            results.append("\nOS Detection:")
            for os in np[port_ip]['osmatch'][:3]:  # Show top 3 OS matches
                accuracy = os['accuracy']
                name = os['name']
                results.append(f"OS: {name} (Accuracy: {accuracy}%)")
                
        # Check if MAC address and vendor are available
        if 'addresses' in np[port_ip]:
            if 'mac' in np[port_ip]['addresses']:
                mac = np[port_ip]['addresses']['mac']
                results.append(f"\nMAC Address: {mac}")
                
                # Try to get vendor information
                if 'vendor' in np[port_ip] and mac in np[port_ip]['vendor']:
                    vendor = np[port_ip]['vendor'][mac]
                    results.append(f"Hardware Vendor: {vendor}")
            
    except Exception as e:
        results.append(f"Error during port scan: {str(e)}")
    
    if callback:
        callback("\n".join(results))
    return results

if __name__ == "__main__":
    print("Cybersecurity Tools")

    while True:
        print("\nSelect a tool:")
        print("1. Host Lookup")
        print("2. Port Scanner")
        print("3. Subdirectory Scanner")
        print("4. Exit")

        choice = input("Enter choice (1/2/3/4): ")

        if choice == "1":
            subnet = input("Enter IP Subnet (e.g., 192.168.1.0/24): ")
            print("\n".join(nmap_scan(subnet)))

        elif choice == "2":
            port_ip = input("Enter IP Address for Port Scan: ")
            print("\n".join(port_scanner(port_ip)))

        elif choice == "3":
            url = input("Enter the base URL (e.g., https://example.com): ")
            wordlist_file = input("Enter the path to your wordlist file: ")
            print("\n".join(find_subdirectories(url, wordlist_file)))

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.") # type: ignore