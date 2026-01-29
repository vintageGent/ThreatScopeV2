# ThreatScopeV2

Hey there, fellow seeker! I'm Mwithiga.

My journey into cybersecurity has always been driven by a fascination with the unseen layers of technology. Whether it is scanning for vulnerabilities or securing a network, I have always believed that powerful tools should be accessible to those who seek to understand them.

ThreatScope is my attempt at bridging that gap. It is a security analysis toolkit designed to automate reconnaissance and vulnerability assessment, turning complex procedures into a streamlined, guided experience.

## The Development Journey

When I first started building ThreatScope, I focused entirely on functionality. The early version was a reflection of my growth as a developer—it worked, but it was complex. It relied on a series of command-line arguments that felt natural to me but proved prohibitive for others. I realized that my tool was becoming part of the problem it was meant to solve: the barrier to entry in security research.

This realization led to a complete architectural shift. I moved away from the "spaghetti code" of the first iteration and embraced a modular design. This not only made the tool more stable and easier to maintain but also allowed me to prioritize the user experience.

The biggest breakthrough was the transition to an interactive interface. By consolidating the various scanning modules—Network, Web, Dependency, and Secrets—into a single, guided menu, I simplified the process without sacrificing power. I wanted to ensure that anyone, regardless of their technical depth, could use ThreatScope to gain meaningful insights.

## Project Architecture

ThreatScope is built on a modular plugin system. Each scanner operates as an independent module, communicating with a central engine that handles reporting and user interaction.

- **Network Analysis**: A wrapper around Nmap that identifies open ports and services with precision.
- **Web Vulnerability Assessment**: Custom checks for common flaws like SQL Injection and XSS.
- **Dependency Auditing**: An isolated scanner that checks requirements files against global vulnerability databases without installing the packages locally.
- **Secret Detection**: A pattern-matching engine designed to find accidental exposure of sensitive credentials in source code.

This modular approach ensures that ThreatScope can grow alongside my own skills, allowing for new capabilities to be added without disturbing the core logic.

## Getting Started

To explore the tools within ThreatScope, you can set up a local instance by following these steps.

### Prerequisites

Ensure you have Python 3 and a virtual environment tool installed.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/vintageGent/ThreatScopeV2.git
   cd ThreatScopeV2
   ```

2. Set up the environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Usage

The simplest way to use ThreatScope is to run the main script and follow the interactive prompts:

```bash
python3 threatscope.py
```

From the menu, you can select your scan type, enter your target, and choose where to save your findings—whether it be your Desktop, Downloads, or a custom directory. For those who prefer direct command-line interaction, the tool still supports standard arguments.

## A Personal Connection

Building ThreatScope has been a masterclass in software design and security principles. It represents my commitment to creating tools that are as refined as they are powerful. If you are a seeker like me, I hope this project helps you uncover the insights you are looking for.
