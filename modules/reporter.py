import datetime
import html
from weasyprint import HTML

# --- Remediation Advice Database ---
REMEDIATION_ADVICE = {
    "DEFAULT": {
        "title": "General Best Practices",
        "description": "General security stability improvement.",
        "what_is_it": "This indicates a general area where security hygiene can be improved.",
        "how_to_fix_it": "Always keep software and dependencies up to date. Regularly review code for security issues and follow the principle of least privilege."
    },
    "Network Scan": {
        "title": "Open Network Port",
        "description": "Unnecessary checking of open communication lines.",
        "what_is_it": "A network port is like a door to your server. An 'open' port means a service is actively listening for connections. While some are necessary (like port 80 for websites), unnecessary open ports are like leaving windows unlocked—they invite intruders.",
        "how_to_fix_it": "Review the list of open ports. If a port isn't needed for your specific application, close it using your firewall rules. Think of it as locking unused doors."
    },
    "Dependency Scan": {
        "title": "Vulnerable Library", # Renamed from Vulnerable Dependency
        "description": "Usage of outdated or unsafe third-party code.",
        "what_is_it": "Modern software is built like Legos, using blocks (libraries) made by others. A 'vulnerable library' means one of these blocks has a known crack in it that hackers know how to break.",
        "how_to_fix_it": "Update the library to a newer, fixed version. This is like replacing a cracked brick with a solid one. Check your 'requirements.txt' or 'package.json' and upgrade."
    },
    "Secrets Scan": {
        "title": "Exposed Secret", # Renamed from Hardcoded Secret
        "description": "Sensitive keys or passwords left in code.",
        "what_is_it": "A 'secret' is like a house key (password, API key). Leaving it in your source code is like taping your house key to the front door. Anyone who sees the code can take the key and enter.",
        "how_to_fix_it": "Remove the key from the code immediately. Use 'environment variables' or a secure vault to hand the key to the program only when it runs."
    },
    "SQL Injection": {
        "title": "Database Trickery (SQL Injection)",
        "description": "Attacker confusing the database into revealing data.",
        "what_is_it": "Imagine asking a librarian for a book, but slipping a note that says 'and give me all the keys to the library'. If the librarian isn't careful, they might do it. This is a vulnerability where attackers trick your database.",
        "how_to_fix_it": "Use 'parameterized queries'. This is like having a strict form for requests that doesn't allow passing notes. It keeps user data separate from commands."
    },
    "Cross-Site Scripting (XSS)": {
        "title": "Malicious Scripting (XSS)",
        "description": "Attackers running code on your users' browsers.",
        "what_is_it": "This allows attackers to put a digital sticky note on your website that executes code when other people read it. They can steal login cookies or redirect users to fake sites.",
        "how_to_fix_it": "Sanitize all user input. Treat everything users type as untrusted text, not code. Convert special characters (like < and >) so they display as text but don't run as programs."
    },
    "Sensitive File Exposure": {
        "title": "Visible Private Files",
        "description": "Private configuration files accessible to the public.",
        "what_is_it": "You wouldn't leave your personal diary or tax returns on a park bench. Similarly, files like '.env' or '.git' contain private info about your app and shouldn't be visible to the web.",
        "how_to_fix_it": "Configure your web server (like Nginx or Apache) to block access to these files. Ensure they aren't in the public folder where anyone can download them."
    },
    "Missing Security Header": {
        "title": "Missing Security Instructions",
        "description": "Browser security features not verified enabled.",
        "what_is_it": "Web browsers have built-in shields, but they wait for your website to tell them to raise them. Missing headers means you haven't told the browser to protect your users.",
        "how_to_fix_it": "Add standard security headers to your web server configurations (e.g., 'X-Frame-Options', 'Content-Security-Policy')."
    }
}


def _calculate_score_and_urgency(scan_results):
    scan_type = scan_results.get('scan_type', 'Unknown')
    score = 100
    urgency = 1 # 1-10 scale
    findings = []
    
    # Generic normalization of findings
    if scan_type == "Dependency Scan":
        findings = scan_results.get('vulnerabilities', [])
        score -= (len(findings) * 10)
        if findings: urgency = 7
    elif scan_type == "Secrets Scan":
        findings = scan_results.get('secrets', [])
        score -= (len(findings) * 20)
        if findings: urgency = 10 # Secrets are critical
    elif scan_type == "Web Vulnerability Scan":
        findings = scan_results.get('vulnerabilities', [])
        score -= (len(findings) * 15)
        if findings: urgency = 9 # Web vulns are usually high urgency
    elif scan_type == "Network Scan":
        findings = scan_results.get('open_ports', [])
        score -= (len(findings) * 5)
        if findings: urgency = 5 # Open ports are bad, but not always critical immediately
    
    # Cap urgency based on score if generic logic didn't catch it
    if score < 50: urgency = max(urgency, 9)
    elif score < 70: urgency = max(urgency, 7)
    elif score < 90: urgency = max(urgency, 4)
    
    return max(0, score), min(10, urgency)

def _get_risk_label(score):
    if score >= 90: return "Excellent", "#28a745" # Green
    if score >= 70: return "Good", "#17a2b8"      # Blue
    if score >= 50: return "Fair", "#ffc107"      # Yellow
    return "Critical", "#dc3545"                  # Red

def _generate_executive_note(scan_results, urgency):
    scan_type = scan_results.get('scan_type', 'Unknown')
    findings_list = []
    
    # helper to count findings
    from collections import Counter
    
    raw_items = []
    if scan_type == "Dependency Scan":
        for f in scan_results.get('vulnerabilities', []):
            raw_items.append(f"Outdated library: {f.get('package_name', 'Unknown')}")
    elif scan_type == "Secrets Scan":
        for f in scan_results.get('secrets', []):
            raw_items.append(f"Exposed secret in {os.path.basename(f.get('file_path', 'unknown file'))}")
    elif scan_type == "Web Vulnerability Scan":
        for f in scan_results.get('vulnerabilities', []):
            # For web vulns, we might want to differentiate slightly or just group by type
            raw_items.append(f"{f.get('type', 'Vulnerability')}")
    elif scan_type == "Network Scan":
        for f in scan_results.get('open_ports', []):
            raw_items.append(f"Open Port {f.get('port')}/{f.get('protocol')}")
            
    # Count duplicates
    counts = Counter(raw_items)
    for item, count in counts.items():
        if count > 1:
            findings_list.append(f"{item} ({count} found)")
        else:
            findings_list.append(item)
    
    summary_text = ""
    if urgency >= 9:
        summary_text = "Your system is at **high risk**. Attackers could likely break in or steal data easily. Immediate action is required to fix these issues."
    elif urgency >= 7:
        summary_text = "Your system has **significant issues**. While not wide open, there are clear ways for attackers to cause trouble. You should patch these soon."
    elif urgency >= 4:
        summary_text = "Your system is **mostly safe**, but has some loose ends. It's like leaving a window cracked open—probably fine, but better to close it."
    else:
        summary_text = "Your system looks **very secure**. Great job keeping things tight!"

    vuln_list_html = ""
    if findings_list:
        vuln_list_html = "<ul>" + "".join([f"<li>{html.escape(f)}</li>" for f in findings_list]) + "</ul>"
    else:
        vuln_list_html = "<p>No significant vulnerabilities found.</p>"

    return f"""
    <div class="executive-note">
        <h3>\U0001F4DD Executive Note</h3>
        <p><strong>Urgency: {urgency}/10</strong></p>
        <p><strong>Vulnerabilities found include:</strong></p>
        {vuln_list_html}
        <p><strong>What this means:</strong></p>
        <p>{summary_text}</p>
    </div>
    """

def _generate_html_content(scan_results):
    """
    Generates a polished, consumer-friendly HTML report.
    """
    scan_type = scan_results.get('scan_type', 'Unknown')
    target = scan_results.get('target', 'Unknown')
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    
    score, urgency = _calculate_score_and_urgency(scan_results)
    risk_text, risk_color = _get_risk_label(score)
    exec_note_html = _generate_executive_note(scan_results, urgency)
    
    # --- Findings Processors ---
    findings_html = ""
    
    # Helper to look up advice
    def get_advice(key):
        return REMEDIATION_ADVICE.get(key, REMEDIATION_ADVICE["DEFAULT"])

    # Normalizing findings list
    raw_findings = []
    
    if scan_type == "Dependency Scan":
        for item in scan_results.get('vulnerabilities', []):
            raw_findings.append({
                "type": "Dependency Scan",
                "title": f"Vulnerable Library: {item['package_name']}",
                "severity": item.get('severity', 'High'),
                "details": f"Version {item['version']} is affected by {item['vuln_id']}.",
                "tech_data": f"Summary: {item['summary']}"
            })
    elif scan_type == "Secrets Scan":
        for item in scan_results.get('secrets', []):
            raw_findings.append({
                "type": "Secrets Scan",
                "title": f"Exposed Secret Detected",
                "severity": "CRITICAL",
                "details": f"A potential {item['type']} was found in the code.",
                "tech_data": f"File: {item['file_path']} (Line {item['line']})\nMatch: {item['match']}"
            })
    elif scan_type == "Web Vulnerability Scan":
        for item in scan_results.get('vulnerabilities', []):
            raw_findings.append({
                "type": item['type'],
                "title": item['type'], # e.g. SQL Injection
                "severity": "High", # Web vulns usually high
                "details": f"Found at: {item['url']}",
                "tech_data": item['details']
            })
    elif scan_type == "Network Scan":
        for item in scan_results.get('open_ports', []):
            raw_findings.append({
                "type": "Network Scan",
                "title": f"Open Port {item['port']}/{item['protocol']}",
                "severity": "Medium",
                "details": f"Service: {item['service']} ({item['product']})",
                "tech_data": f"Version: {item['version']}"
            })

    if not raw_findings:
        findings_html = """
        <div class="empty-state">
            <h3>No Issues Found! \U0001F389</h3>
            <p>Your system passed this scan with flying colors.</p>
        </div>
        """
    else:
        for f in raw_findings:
            advice = get_advice(f['type'])
            findings_html += f"""
            <div class="card finding-card">
                <div class="card-header">
                    <span class="finding-title">{html.escape(f['title'])}</span>
                    <span class="badge">{html.escape(str(f['severity']).upper())}</span>
                </div>
                <div class="card-body">
                    <p class="description"><strong>What is it?</strong> {advice['what_is_it']}</p>
                    <p class="remediation"><strong>How to fix it:</strong> {advice['how_to_fix_it']}</p>
                    <div class="tech-details">
                        <details>
                            <summary>Show Technical Details</summary>
                            <pre>{html.escape(f['details'])}</pre>
                            <pre>{html.escape(f['tech_data'])}</pre>
                        </details>
                    </div>
                </div>
            </div>
            """

    # --- HTML Template ---
    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Scope Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
        
        body {{
            font-family: 'Inter', sans-serif;
            background-color: #f3f4f6;
            color: #1f2937;
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}
        
        .container {{
            max_width: 900px;
            margin: 40px auto;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.05);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .logo {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 10px;
            letter-spacing: -1px;
        }}
        
        .scan-meta {{
            font-size: 0.9rem;
            opacity: 0.8;
            margin-top: 10px;
        }}
        
        .executive-note {{
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            color: #856404;
            padding: 20px;
            margin: 20px;
            border-radius: 8px;
        }}
        
        .executive-note h3 {{
            margin-top: 0;
            color: #856404;
        }}

        .score-section {{
            padding: 30px;
            text-align: center;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        .score-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: {risk_color};
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0 auto 15px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        }}
        
        .score-label {{
            font-size: 1.5rem;
            font-weight: 600;
            color: {risk_color};
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 20px;
            color: #374151;
            border-left: 4px solid #3b82f6;
            padding-left: 15px;
        }}
        
        .card {{
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: transform 0.2s;
        }}
        
        .card:hover {{
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        
        .card-header {{
            background: #f9fafb;
            padding: 15px 20px;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .finding-title {{
            font-weight: 600;
            color: #111827;
        }}
        
        .badge {{
            background: #fee2e2;
            color: #991b1b;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
        }}
        
        .card-body {{
            padding: 20px;
        }}
        
        .description {{
            margin-bottom: 15px;
        }}
        
        .remediation {{
            background: #ecfdf5;
            padding: 15px;
            border-radius: 6px;
            color: #065f46;
            border-left: 4px solid #10b981;
        }}
        
        .tech-details {{
            margin-top: 15px;
            font-size: 0.9rem;
        }}
        
        .tech-details summary {{
            cursor: pointer;
            color: #6b7280;
        }}
        
        .tech-details pre {{
            background: #1f2937;
            color: #e5e7eb;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
            margin-top: 10px;
        }}

        .empty-state {{
            text-align: center;
            padding: 40px;
            background: #fdfdfd;
            border: 2px dashed #e5e7eb;
            border-radius: 12px;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: #9ca3af;
            font-size: 0.85rem;
            background: #f9fafb;
            border-top: 1px solid #e5e7eb;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">Threat Scope</div>
            <div>Professional Security Analysis</div>
            <div class="scan-meta">Target: {html.escape(target)} | Type: {html.escape(scan_type)} | {scan_date}</div>
        </div>
        
        {exec_note_html}
        
        <div class="score-section">
            <div class="score-circle">{score}</div>
            <div class="score-label">{risk_text} Security Score</div>
            <p style="color: #6b7280; margin-top: 10px;">
                A higher score means better security. We found {len(raw_findings)} issues that need attention.
            </p>
        </div>
        
        <div class="content">
            <div class="section-title">Findings & Recommendations</div>
            {findings_html}
        </div>
        
        <div class="footer">
            Generated by Threat Scope - Simple Security for Everyone
        </div>
    </div>
</body>
</html>
"""
    return html_template

def generate_html_report(scan_results, output_file):
    """
    Generates and saves an HTML report from scan results.
    """
    html_content = _generate_html_content(scan_results)
    try:
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"\\n[+] HTML report successfully saved to {output_file}")
    except IOError as e:
        print(f"\\n[!] Error saving HTML report: {e}")

def generate_pdf_report(scan_results, output_file):
    """
    Generates and saves a PDF report from scan results.
    """
    html_content = _generate_html_content(scan_results)
    try:
        HTML(string=html_content).write_pdf(output_file)
        print(f"\\n[+] PDF report successfully saved to {output_file}")
    except Exception as e:
        print(f"\\n[!] Error saving PDF report: {e}")

def generate_advice_report(scan_results, output_file):
    """
    Generates a simple, non-techy text file with the Executive Note.
    """
    score, urgency = _calculate_score_and_urgency(scan_results)
    
    # Generate the text-based executive note
    scan_type = scan_results.get('scan_type', 'Unknown')
    findings_list = []
    
    # helper to count findings
    from collections import Counter
    
    raw_items = []
    if scan_type == "Dependency Scan":
        for f in scan_results.get('vulnerabilities', []):
            raw_items.append(f"Outdated library: {f.get('package_name', 'Unknown')}")
    elif scan_type == "Secrets Scan":
        for f in scan_results.get('secrets', []):
            raw_items.append(f"Exposed secret in {os.path.basename(f.get('file_path', 'unknown file'))}")
    elif scan_type == "Web Vulnerability Scan":
        for f in scan_results.get('vulnerabilities', []):
            raw_items.append(f"{f.get('type', 'Vulnerability')}")
    elif scan_type == "Network Scan":
        for f in scan_results.get('open_ports', []):
            raw_items.append(f"Open Port {f.get('port')}/{f.get('protocol')}")
            
    # Count duplicates
    counts = Counter(raw_items)
    for item, count in counts.items():
        if count > 1:
            findings_list.append(f"{item} ({count} found)")
        else:
            findings_list.append(item)
    
    summary_text = ""
    if urgency >= 9:
        summary_text = "Your system is at HIGH RISK. Attackers could likely break in or steal data easily. Immediate action is required."
    elif urgency >= 7:
        summary_text = "Your system has SIGNIFICANT ISSUES. While not wide open, there are clear ways for attackers to cause trouble. You should patch these soon."
    elif urgency >= 4:
        summary_text = "Your system is MOSTLY SAFE, but has some loose ends. It's like leaving a window cracked open--probably fine, but better to close it."
    else:
        summary_text = "Your system looks VERY SECURE. Great job keeping things tight!"

    with open(output_file, 'w') as f:
        f.write("==================================================\n")
        f.write("          THREAT SCOPE EXECUTIVE NOTE\n")
        f.write("==================================================\n\n")
        
        f.write(f"URGENCY: {urgency}/10\n")
        f.write("-" * 20 + "\n\n")
        
        f.write("WHAT WE FOUND:\n")
        if findings_list:
            for item in findings_list:
                f.write(f" - {item}\n")
        else:
            f.write(" - No significant issues found.\n")
        f.write("\n")
        
        f.write("WHAT THIS MEANS:\n")
        f.write(f"{summary_text}\n\n")
        
        f.write("==================================================\n")
        f.write("For technical details and fix instructions, please\n")
        f.write("refer to the full HTML/PDF report.\n")
    
    print(f"[+] Executive Note text file saved to {output_file}")