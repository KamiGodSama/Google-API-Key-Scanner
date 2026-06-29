# 🔐 Google API Key Scanner

A comprehensive Python-based security auditing tool to determine which Google Cloud Platform (GCP) and Google APIs a given API key has access to. Designed for bug bounty hunters, penetration testers, and security professionals to demonstrate the impact of exposed credentials during authorized assessments.

> ⚠️ **DISCLAIMER**: This tool is intended for **authorized security assessments and educational purposes only**. Use it only on systems, projects, and API keys you own or have explicit written permission to test. The author is not responsible for any misuse, billing charges, or legal consequences incurred by running this tool.

---

## ✨ Features

- **Comprehensive Coverage**: Tests **30+ Google services** across multiple categories.
- **Proof-of-Concept Generation**: Automatically generates working `curl` commands and URLs to demonstrate unauthorized access.
- **Cost Awareness**: Displays estimated billing costs per 1,000 requests for each vulnerable service.
- **Service Account Detection**: Automatically detects Google Cloud Service Account JSON files and provides `gcloud` commands for manual validation.
- **Zero Configuration**: Run it with a single command—no complex setup required.

---

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/google-api-key-scanner.git
   cd google-api-key-scanner
