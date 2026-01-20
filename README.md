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

The main challenge in building a tool like ThreatScope is not just writing the code, but architecting it in a way that is both powerful and easy to expand.

My first version of this tool was a single, monolithic script. It worked, but it was difficult to add new features without breaking existing ones. For V2, I made a critical design decision to rebuild it from the ground up with a **modular architecture**.

Each piece of functionality—like subdomain enumeration, port scanning, or vulnerability analysis—is now designed as a separate "module." This was a significant challenge that forced me to think more deeply about object-oriented design and how to create clean interfaces between different parts of the application. While it was more work upfront, this modular approach means I can now add new scanning capabilities far more easily in the future. This project has been an incredible learning experience in building more mature and maintainable software.