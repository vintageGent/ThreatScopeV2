import re
import os

# Dictionary of regex patterns for finding secrets
# Each key is the type of secret, and the value is the regex pattern.
SECRET_PATTERNS = {
    "Generic API Key": r"[aA][pP][iI]_?[kK][eE][yY].*['|\"]([a-zA-Z0-9\\-_.]{32,})['|\"]",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"[a-zA-Z0-9/+=]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Private Key": r"-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY-----",
}

def scan_file_for_secrets(filepath):
    """Scans a single file for hardcoded secrets."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for secret_type, pattern in SECRET_PATTERNS.items():
                    match = re.search(pattern, line)
                    if match:
                        findings.append({
                            "file_path": filepath,
                            "line": line_num,
                            "type": secret_type,
                            "match": match.group(0) # Store the matched string
                        })
    except Exception as e:
        print(f"[!] Could not read file {filepath}: {e}")
    return findings

def scan_secrets(path):
    """
    Scans a file or directory for hardcoded secrets and returns the findings.
    """
    print(f"\n--- Secrets Scan ---")
    print(f"[*] Scanning target: {path}\n")
    
    all_findings = []
    if os.path.isfile(path):
        all_findings.extend(scan_file_for_secrets(path))
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                filepath = os.path.join(root, file)
                print(f"[*] Scanning file: {filepath}")
                all_findings.extend(scan_file_for_secrets(filepath))
    else:
        print(f"[!] Error: Path '{path}' is not a valid file or directory.")
        return {"target": path, "scan_type": "Secrets Scan", "secrets": []}

    scan_results = {
        "target": path,
        "scan_type": "Secrets Scan",
        "secrets": all_findings
    }

    # Console reporting
    if not all_findings:
        print("\n[+] No secrets found.")
    else:
        print(f"\n[!] Scan complete. Found {len(all_findings)} potential secret(s).")
        for finding in all_findings:
            print(f"  [!] POTENTIAL SECRET FOUND in {finding['file_path']} (Line {finding['line']}):")
            print(f"    - Type: {finding['type']}")
            print(f"    - Match: {finding['match'].strip()}")
            print("-" * 20)
            
    return scan_results
