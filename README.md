# 🛡️ CyberSentinel

CyberSentinel is a unified cybersecurity monitoring and security assessment platform built with Python and Flask.

It combines multiple defensive security tools into a single web dashboard for authorized security testing and security assessment.

## 🚀 Features

### 🌐 WebShield
Analyzes website security configuration including:

- HTTPS usage
- Security headers
- Cookie security attributes
- Basic security configuration
- Security score

### 🔗 Malicious URL Detector

Uses heuristic analysis to identify suspicious URLs based on:

- HTTPS usage
- Direct IP addresses
- Suspicious URL patterns
- Sensitive keywords
- URL length
- Potentially suspicious TLDs

### 🔍 Vulnerability Scanner

Integrates Nmap to perform authorized network/service discovery.

It can identify:

- Open ports
- Services
- Basic host information

### ☁️ Cloud Security Analyzer

Provides a demonstration security assessment for common AWS configuration issues such as:

- Public storage exposure
- Excessive IAM permissions
- Unused resources

> Cloud findings in the current version are demonstration findings and do not represent a live AWS account scan.

## 🛠️ Technology Stack

- Python
- Flask
- HTML
- CSS
- Requests
- BeautifulSoup
- Boto3
- Nmap

## 📂 Project Structure

```text
CyberSentinel/
│
├── app.py
├── scanner.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── templates/
    └── index.html