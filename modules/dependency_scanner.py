import requests
import json

# OSV API endpoint for querying vulnerabilities
OSV_API_URL = "https://api.osv.dev/v1/query"

def parse_requirements(file_path):
    """
    Parses a requirements.txt file to extract package names and versions.
    Handles lines with '==', '>=', '<=', '>', '<'.
    """
    packages = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                for op in ['==', '>=', '<=', '>', '<']:
                    if op in line:
                        name, version = line.split(op, 1)
                        packages.append({"name": name.strip(), "version": version.strip()})
                        break
                else:
                    packages.append({"name": line.strip(), "version": None})

    except FileNotFoundError:
        print(f"[!] Error: The file '{file_path}' was not found.")
        return None
    return packages

def query_osv_api(package_name, version):
    """
    Queries the OSV API for vulnerabilities for a specific package and version.
    """
    query = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        }
    }
    try:
        response = requests.post(OSV_API_URL, data=json.dumps(query))
        if response.status_code == 200 and response.content:
            return response.json()
        else:
            return None
    except requests.RequestException as e:
        print(f"[!] API request failed for {package_name}=={version}: {e}")
        return None

def scan_dependencies(file_path):
    """
    Scans a dependency file and returns a dictionary with the findings.
    """
    print(f"\n--- Dependency Vulnerability Scan ---")
    print(f"[*] Scanning file: {file_path}\n")

    packages = parse_requirements(file_path)
    if packages is None:
        return {"target": file_path, "scan_type": "Dependency Scan", "vulnerabilities": []}

    scan_results = {
        "target": file_path,
        "scan_type": "Dependency Scan",
        "vulnerabilities": []
    }

    for pkg in packages:
        if pkg['version'] is None:
            print(f"[?] Skipping '{pkg['name']}': No version specified.")
            continue

        print(f"[*] Checking {pkg['name']} version {pkg['version']}...")
        vulns = query_osv_api(pkg['name'], pkg['version'])

        if vulns and 'vulns' in vulns:
            for vuln in vulns['vulns']:
                severity = "UNKNOWN"
                # Try to find severity information
                if 'database_specific' in vuln and 'severity' in vuln['database_specific']:
                    severity = vuln['database_specific']['severity']
                
                scan_results["vulnerabilities"].append({
                    "package_name": pkg['name'],
                    "version": pkg['version'],
                    "vuln_id": vuln['id'],
                    "summary": vuln.get('summary', 'No summary available.'),
                    "details": vuln.get('details', 'No details available.'),
                    "aliases": vuln.get('aliases', []),
                    "severity": severity
                })
    
    # Console reporting
    if not scan_results["vulnerabilities"]:
        print("\n[+] No vulnerable dependencies found.")
    else:
        print(f"\n[!] Scan complete. Found vulnerabilities in {len(set(v['package_name'] for v in scan_results['vulnerabilities']))} package(s).")
        for vuln in scan_results["vulnerabilities"]:
             print(f"  [!] VULNERABILITY FOUND for {vuln['package_name']}=={vuln['version']}:")
             print(f"    - ID: {vuln['vuln_id']}")
             print(f"    - Severity: {vuln['severity']}")
             print(f"    - Summary: {vuln['summary']}")
             print("-" * 20)


    return scan_results