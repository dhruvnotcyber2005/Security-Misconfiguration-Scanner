# SentinelScan

**SentinelScan** is a modular **Security Misconfiguration Scanner** written in Python. It performs passive security configuration analysis of web applications by identifying common security misconfigurations without actively exploiting vulnerabilities.

The project was built to strengthen practical knowledge of **Application Security (AppSec)**, **Cybersecurity**, **Python**, and **Software Engineering** while following clean architecture and object-oriented design principles.

---

# Features

* Modular scanner architecture
* Passive web security configuration analysis
* HTTP Security Headers Scanner
* TLS Certificate Scanner
* HTTP Methods Scanner
* Server Banner Scanner
* Structured scan reporting
* Centralized scan engine
* Comprehensive logging
* Extensible architecture for future scanner modules

---

# Architecture

```text
                   Target
                      │
                      ▼
                Scan Engine
                      │
      ┌───────────────┼────────────────┐
      ▼               ▼                ▼
 Header Scanner   TLS Scanner   HTTP Methods Scanner
                      │
                      ▼
              Server Banner Scanner
                      │
                      ▼
              list[ScanResult]
                      │
                      ▼
             Report Generator
                 │         │
                 ▼         ▼
          Console Report  report.txt
```

---

# Project Structure

```text
SentinelScan/

├── app.py
├── requirements.txt
├── README.md
│
├── scanner/
│   ├── core/
│   │   ├── engine.py
│   │   ├── scanner.py
│   │   └── target.py
│   │
│   ├── modules/
│   │   ├── headers.py
│   │   ├── tls.py
│   │   ├── methods.py
│   │   └── server.py
│   │
│   ├── reporting/
│   │   ├── reporting_models.py
│   │   └── report_generator.py
│   │
│   └── utils/
│       └── logger.py
│
├── templates/
├── static/
└── tests/
```

---

# Scanner Modules

| Module                | Description                                                              |
| --------------------- | ------------------------------------------------------------------------ |
| HTTP Security Headers | Detects missing recommended HTTP security headers.                       |
| TLS Certificate       | Validates TLS certificates and detects expired or expiring certificates. |
| HTTP Methods          | Identifies potentially risky HTTP methods exposed by the server.         |
| Server Banner         | Detects exposed server banners that may reveal implementation details.   |

---

# Installation

Clone the repository:

```bash
git clone https://github.com/dhruvnotcyber2005/SentinelScan.git
```

Move into the project directory:

```bash
cd SentinelScan
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the virtual environment.

**Windows**

```bash
.venv\Scripts\activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

Run the application:

```bash
python app.py
```

After the scan completes:

* A formatted report is displayed in the console.
* A text report is generated as `report.txt`.

---

# Sample Output

```text
============================================================
SentinelScan Report
============================================================

Target: https://example.com
Modules Scanned: 4

------------------------------------------------------------
Module: HTTP Security Headers
Execution Time: 0.5234 seconds

Severity: Medium
Title: Missing Content-Security-Policy

Description:
The Content-Security-Policy header is missing.

Recommendation:
Configure a Content-Security-Policy header.

...

============================================================
Summary
============================================================

Modules Scanned: 4
Total Findings: 5

Critical: 0
High: 0
Medium: 4
Low: 1
Informational: 0
```

---

# Technologies Used

* Python 3
* Flask
* requests
* BeautifulSoup4
* cryptography

---

# Software Engineering Principles

SentinelScan was designed with maintainability and extensibility in mind.

The project incorporates:

* Object-Oriented Programming (OOP)
* SOLID Principles
* Single Responsibility Principle (SRP)
* Dependency Injection
* Abstraction using Abstract Base Classes
* Modular Architecture
* Structured Logging
* Exception Handling
* Dataclasses
* Separation of Concerns
* Readable and maintainable code

---

# Version 1 Modules

* HTTP Security Headers Scanner
* TLS Certificate Scanner
* HTTP Methods Scanner
* Server Banner Scanner
* Scan Engine
* Report Generator

---

# Version 2 Roadmap

Planned scanner modules include:

* Cookies Scanner
* Git Exposure Scanner
* Environment File Exposure Scanner
* Backup File Scanner
* Directory Listing Scanner
* robots.txt Analysis
* security.txt Analysis

Additional planned features:

* Flask Web Interface
* HTML Report Generation
* Risk Scoring
* JSON Report Export
* Improved Dashboard
* Enhanced Reporting

---

# Learning Objectives

This project was built to gain practical experience in:

* Application Security (AppSec)
* Web Security
* Python Programming
* Secure Coding Practices
* Software Engineering
* Object-Oriented Design
* Designing Modular Security Tools

---

# Disclaimer

SentinelScan is an educational and defensive security tool intended for authorized security assessments only.

Always obtain permission before scanning systems you do not own or administer.

---

# License

This project is licensed under the MIT License.
