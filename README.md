# ThreatScopeV2

A modular, multi-function security scanner for network, web, and code analysis.

## Overview

ThreatScopeV2 is a command-line tool designed to help developers and security enthusiasts identify potential security risks in their projects and networks. It is organized into several modules, each targeting a specific area of security.

-   **`netscan`**: Performs a network scan on a target IP or range to find open ports and identify services.
-   **`vulnscan`**: Scans a web URL for common vulnerabilities like SQL Injection, XSS, sensitive file exposure, and insecure headers.
-   **`dep_scan`**: Scans a Python dependency file (`requirements.txt`) for packages with known vulnerabilities by querying the OSV.dev database.
-   **`secret_scan`**: Scans a directory or file for hardcoded secrets like API keys and passwords.

---

## Step-by-Step Installation and Usage Guide

This guide will walk you through setting up and using ThreatScopeV2.

### Step 1: Prerequisites

Before you begin, ensure you have the following installed on your system:
-   Python 3.x
-   `pip` (The Python package installer)
-   `git` (For cloning the project)
-   A stable internet connection (required for installation and for the `dep_scan` feature)

### Step 2: Get the Code

Clone the project repository to your local machine.

```bash
git clone <your-repository-url>
cd ThreatScopeV2
```
*(Replace `<your-repository-url>` with the actual URL of the repository.)*

### Step 3: Set Up the Virtual Environment

It is crucial to run this tool in a dedicated virtual environment. This prevents conflicts with other Python projects or your system's Python installation.

```bash
# Create the virtual environment (this creates a 'venv' folder)
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate
```
After running the `source` command, your terminal prompt should change to show `(venv)` at the beginning.

### Step 4: Install Dependencies

Install the Python libraries that ThreatScopeV2 itself needs to run. These are listed in the `requirements.txt` file.

```bash
# Make sure you are inside the ThreatScopeV2 directory with your virtual environment active
pip install -r requirements.txt
```
**Note:** If this step fails due to network errors (`SSLError`, `ReadTimeoutError`), you will need to troubleshoot your machine's network configuration. The tool cannot be installed without a stable connection to the Python Package Index (pypi.org).

### Step 5: Run a Scan

You can now use the tool. The general command format is `python3 threatscope.py <command> [arguments]`.

#### Example 1: Scan a `requirements.txt` file

Let's say you have another project at `/home/user/my_other_project` which has a `requirements.txt` file.

```bash
python3 threatscope.py dep_scan /home/user/my_other_project/requirements.txt --html dependency_report.html
```
This command will:
-   Run the dependency scanner (`dep_scan`).
-   Analyze the specified `requirements.txt` file.
-   Save the results in a file named `dependency_report.html`.

#### Example 2: Scan a directory for secrets

```bash
python3 threatscope.py secret_scan /home/user/my_other_project --html secrets_report.html
```
This command will:
-   Run the secret scanner (`secret_scan`).
-   Scan all files within `/home/user/my_other_project`.
-   Save the findings in `secrets_report.html`.

#### Example 3: Scan a website for vulnerabilities

```bash
python3 threatscope.py vulnscan http://example.com --pdf web_report.pdf
```
This command will:
-   Run the web vulnerability scanner (`vulnscan`).
-   Test `http://example.com` for common vulnerabilities.
-   Save the report as `web_report.pdf`.

---

## Technical Note: Project Architecture

This project was refactored to solve a critical architectural flaw.

-   **The Problem:** The tool was originally trying to run using the same outdated and vulnerable libraries that it was designed to detect. This created a circular dependency and caused the tool to crash with a `ModuleNotFoundError` related to its own dependencies.

-   **The Solution:** The project has been re-architected to run in its own stable, isolated environment (the `venv` you created). The `dep_scan` module now works by parsing the target `requirements.txt` as a text file and checking the versions against a public vulnerability database. It no longer attempts to install or use the packages it is scanning. This makes the tool itself stable and reliable.