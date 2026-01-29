# ThreatScopeV2

**Welcome to ThreatScope!**

This tool is your personal security assistant. I built it to help automate the tedious parts of security reconnaissance—like scanning networks, checking websites for vulnerabilities, and auditing code for secrets.

It's designed to be **simple, modular, and effective**.

## 🚀 Quick Start (Easiest Way)

You don't need to memorize long commands. ThreatScope now has a user-friendly **Interactive Menu**.

1.  **Run the tool:**
    ```bash
    python3 threatscope.py
    ```

2.  **Choose an option:**
    You'll see a menu like this:
    ```
    1. Network Scan (netscan)
    2. Web Vulnerability Scan (vulnscan)
    3. Dependency Scan (dep_scan)
    4. Secret Scan (secret_scan)
    5. Help / Usage Guide
    6. Exit
    ```

3.  **Follow the prompts:**
    - Enter your target (IP, URL, or file path).
    - Sit back and let ThreatScope do the work.
    - When finished, you can choose to save the report to your **Desktop**, **Downloads**, or any custom folder.

---

## 🛠 Features

-   **Network Scan**: Find open ports and identifying services on a target IP.
-   **Web Scan**: Check websites for common flaws like SQL Injection and XSS.
-   **Dependency Scan**: Check your `requirements.txt` for vulnerable Python libraries.
-   **Secret Scan**: Find accidental API keys and passwords in your code.
-   **Flexible Reporting**: Save reports as PDF, HTML, or Text where *you* want them.

---

## 📦 Installation

1.  **Get the code:**
    ```bash
    git clone <repository-url>
    cd ThreatScopeV2
    ```

2.  **Set up your environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3.  **Run it!**
    ```bash
    python3 threatscope.py
    ```

---

## 🤓 Advanced / CLI Usage

For power users who prefer one-liners or automation, you can still use command-line arguments.

**Scan a website:**
```bash
python3 threatscope.py vulnscan http://example.com --pdf report.pdf
```

**Scan a network:**
```bash
python3 threatscope.py netscan 192.168.1.1 --ports 80,443
```

**Scan for secrets:**
```bash
python3 threatscope.py secret_scan /path/to/project
```

---

## 💡 About the Project

**ThreatScopeV2** was born from the frustration of maintaining "spaghetti code." My first version was a single, giant script that was hard to fix. V2 is completely rebuilt with a **modular architecture**—meaning each scanner is a separate plugin. This makes it stable, easy to expand, and robust.

Enjoy exploring!
