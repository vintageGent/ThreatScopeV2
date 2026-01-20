# ThreatScope V2

Hey there, fellow seeker! I'm Mwithiga.

My journey into technology has always been tied to a deep interest in cybersecurity—both the offensive (Red Team) and defensive (Blue Team) sides. I wanted to move beyond theory and build a practical tool that could help automate some of the reconnaissance and analysis tasks that security professionals perform.

Thus, **ThreatScope** was born. This project is my custom-built toolkit for security analysis. It's a command-line application designed to integrate various scanning and enumeration techniques into a single, cohesive framework. This is my personal project to both sharpen my Python skills and create something functional for my own security research.

## Features

- **Modular Design:** Easily extendable with new scanning modules.
- **Command-Line Interface:** Built for efficiency and integration into automated workflows.
- _(More features to be documented as the project evolves)_

## Getting Started

_(Setup and usage instructions will be added as the project matures.)_

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
