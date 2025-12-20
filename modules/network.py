import subprocess
import xml.etree.ElementTree as ET
import os

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

def _parse_nmap_xml(xml_file):
    """Parses the XML output from Nmap and returns structured data."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError):
        return []

    open_ports = []
    for host in root.findall('host'):
        ip_address = host.find('address').get('addr')
        for port in host.findall('.//port'):
            if port.find('state').get('state') == 'open':
                port_info = {
                    'ip_address': ip_address,
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'service': port.find('service').get('name') if port.find('service') is not None else 'unknown',
                    'product': port.find('service').get('product') if port.find('service') is not None and 'product' in port.find('service').attrib else '',
                    'version': port.find('service').get('version') if port.find('service') is not None and 'version' in port.find('service').attrib else '',
                }
                open_ports.append(port_info)
    return open_ports

def run_network_scan(target, ports=None):
    """
    Runs an Nmap scan and returns a dictionary with the findings.
    """
    if ports is None:
        ports = DEFAULT_PORTS
    
    port_str = ",".join(map(str, ports))
    xml_output_file = 'nmap_scan_results.xml'

    print(f"[*] Running Nmap service scan on {target} for ports: {port_str}")
    
    try:
        # Run nmap as a subprocess
        subprocess.run(
            ["nmap", "-sV", "-T4", "-p", port_str, target, "-oX", xml_output_file],
            check=True, capture_output=True, text=True
        )
    except FileNotFoundError:
        print("[!] Error: 'nmap' command not found. Please ensure nmap is installed and in your PATH.")
        return {"target": target, "scan_type": "Network Scan", "open_ports": []}
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running nmap scan: {e.stderr}")
        return {"target": target, "scan_type": "Network Scan", "open_ports": []}

    # Parse the XML and prepare results
    open_ports = _parse_nmap_xml(xml_output_file)
    
    # Clean up the temporary XML file
    if os.path.exists(xml_output_file):
        os.remove(xml_output_file)

    scan_results = {
        "target": target,
        "scan_type": "Network Scan",
        "open_ports": open_ports
    }

    # Console reporting
    if not open_ports:
        print("\n[+] No open ports found.")
    else:
        print(f"\n[!] Scan complete. Found {len(open_ports)} open port(s).")
        for port in open_ports:
            service_info = f"{port['service']} ({port['product']} {port['version']})".strip()
            print(f"  [!] Open port found on {port['ip_address']}:{port['port']}/{port['protocol']}")
            print(f"    - Service: {service_info}")
            print("-" * 20)

    return scan_results