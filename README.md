# ThreatScopeV2

Hey there, fellow seeker! I'm Mwithiga.

My journey into technology has always been tied to a deep interest in cybersecurity—both the offensive (Red Team) and defensive (Blue Team) sides. I wanted to move beyond theory and build a practical tool that could help automate some of the reconnaissance and analysis tasks that security professionals perform.

Thus, **ThreatScope** was born. This project is my custom-built toolkit for security analysis. It's a command-line application designed to integrate various scanning and enumeration techniques into a single, cohesive framework. This is my personal project to both sharpen my Python skills and create something functional for my own security research.

## Overview

ThreatScopeV2 is a modular, multi-function security scanner for network, web, and code analysis. It is organized into several commands, each targeting a specific area of security.

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

## The Development Journey

Building a tool like ThreatScope is a great lesson in software architecture. Here are some of the core challenges that shaped the design of V2.

### Problem 1: The "Spaghetti Code" of V1

My first attempt at this tool, which I call V1, was a single, massive Python script. It worked, but it was a nightmare to maintain. If I wanted to add a new feature, like a different type of network scan, I risked breaking everything else. It was classic "spaghetti code," and I knew it wasn't a sustainable way to build software.

**Solution:** This frustration was the catalyst for V2. I made the tough decision to start over with a clear goal: build it properly with a **modular architecture**. This meant throwing away my old code and designing a better system from scratch.

### Problem 2: Designing a True "Module" System

The next big challenge was designing the module system itself. How does a "port scanner" module talk to a "subdomain finder" module? How do they share results? How can I run them independently or chain them together in a logical sequence?

**Solution:** I spent a lot of time designing a simple "plugin" interface. Each module is now a Python class that follows a specific pattern. It has a `run()` method that performs the scan and a standard way of returning its results. The main program is now just a simple "engine" that discovers and runs these modules. This design means adding a new capability, like a new vulnerability check, is as simple as creating a new file with the correct class structure, without modifying the core engine.

### Problem 3: Managing External Tools

A real-world security workflow uses many different command-line tools (like Nmap, Amass, etc.). Each tool has different arguments and produces output in a different format. My tool needed to manage this complexity seamlessly.

**Solution:** For each external tool, I wrote a "wrapper" inside its module. This wrapper is responsible for building the correct command-line arguments and, more importantly, parsing the tool's unique output into a standardized Python object. This way, the rest of my program doesn't care if the data came from Nmap or another tool; it just sees a clean, consistent data structure. This was a huge step in making the project more powerful and maintainable.

---

## Technical Note: Project Architecture

This project was refactored to solve a critical architectural flaw.

-   **The Problem:** The tool was originally trying to run using the same outdated and vulnerable libraries that it was designed to detect. This created a circular dependency and caused the tool to crash with a `ModuleNotFoundError` related to its own dependencies.

-   **The Solution:** The project has been re-architected to run in its own stable, isolated environment (the `venv` you created). The `dep_scan` module now works by parsing the target `requirements.txt` as a text file and checking the versions against a public vulnerability database. It no longer attempts to install or use the packages it is scanning. This makes the tool itself stable and reliable.
