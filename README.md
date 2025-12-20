# ThreatScopeV2: A Focused Security Scanner

**ThreatScopeV2** is a command-line toolkit designed for security professionals and developers to perform targeted security scans. It provides a suite of modules for network discovery, vulnerability analysis, dependency checking, and secrets detection.

This tool is built to be straightforward and extensible, providing clear, actionable results in multiple formats.

## Core Features

*   **Network Scanner (`netscan`):** Uses `nmap` to discover open ports and identify running services on a target host or network range.
*   **Web Vulnerability Scanner (`vulnscan`):** Performs basic checks for common web vulnerabilities, including SQL Injection, Cross-Site Scripting (XSS), sensitive file exposure, and missing security headers.
*   **Dependency Scanner (`dep_scan`):** Scans dependency files (like `requirements.txt`) for packages with known vulnerabilities by checking against the OSV (Open Source Vulnerability) database.
*   **Secrets Scanner (`secret_scan`):** Scans files or directories for hardcoded secrets like API keys and private keys using a set of common regex patterns.

## Multi-Format Reporting

ThreatScopeV2 provides clear and professional reports in several formats:

*   **Console:** Immediate, color-coded output directly in your terminal.
*   **HTML:** A clean, easy-to-read report file perfect for viewing in a browser.
*   **PDF:** A portable, shareable PDF version of the report.
*   **Advice File:** A simple text file containing easy-to-understand explanations of the findings and actionable remediation advice.

## Getting Started

### Prerequisites

*   Python 3.x
*   `nmap` must be installed and in your system's PATH for the `netscan` command to work.

### Installation

The project includes a virtual environment (`venv`) with all necessary Python packages.

1.  **Navigate to the project directory:**
    ```bash
    cd ThreatScopeV2
    ```

2.  **Activate the virtual environment:**
    *   On Linux/macOS:
        ```bash
        source venv/bin/activate
        ```
    *   On Windows:
        ```bash
        .\venv\Scripts\activate
        ```

## Usage

All commands are run through the main `threatscope.py` script.

**General Format:**
```bash
./threatscope.py <command> <target> [options]
```

**Reporting Flags (can be used with any command):**
*   `--html <filename.html>`: Generate an HTML report.
*   `--pdf <filename.pdf>`: Generate a PDF report.
*   `--advice <filename.txt>`: Generate a text file with remediation advice.

### `netscan`

**Usage:**
```bash
./threatscope.py netscan <ip_or_hostname> [--ports <port1,port2>]
```
**Example:**
```bash
./threatscope.py netscan 127.0.0.1 --ports 80,443,8080 --pdf scan_report.pdf
```

### `vulnscan`

**Usage:**
```bash
./threatscope.py vulnscan <url>
```
**Example:**
```bash
./threatscope.py vulnscan "http://example.com/page.php?id=1" --html vuln_report.html
```

### `dep_scan`

**Usage:**
```bash
./threatscope.py dep_scan <path_to_file>
```
**Example:**
```bash
./threatscope.py dep_scan requirements.txt --advice advice.txt
```

### `secret_scan`

**Usage:**
```bash
./threatscope.py secret_scan <file_or_directory_path>
```
**Example:**
```bash
./threatscope.py secret_scan . --html secrets.html --pdf secrets.pdf
```
