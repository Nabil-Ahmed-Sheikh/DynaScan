# RP Dyna Scan

## Introduction

RP Dyna Scan is a CLI tool designed for scanning various security vulnerabilities in web applications. It helps identify vulnerabilities such as broken authentication, SQL injection, XSS, and more.

## Optional: Set Up a Python Virtual Environment

Using a virtual environment is recommended to manage dependencies and avoid conflicts.

### For Linux/Mac

1. Navigate to your project directory:
   ```bash
   cd rptodo_project/
   ```
2. Create a virtual environment:
   ```bash
   python -m venv ./venv
   ```
3. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```

### For Windows

1. Create a virtual environment:
   ```bash
   python -m venv venv
   ```
2. Activate the virtual environment:
   ```bash
   venv\Scripts\activate.bat
   ```

## Installation

1. Install the package in editable mode:
   ```bash
   pip install -e .
   ```

## Usage

You can run various commands to scan for different types of vulnerabilities. Below is an example for scanning broken authentication:

### Example Command

To scan for broken authentication vulnerabilities:

```bash
rpdynascan scan_broken_authentication "https://example.com/login" --params "{\"username\": \"test_user\", \"password\": \"test_pass\"}"
```

## Alternatively, you can use the module directly with Python:

```bash
python -m rpdynascan scan_broken_authentication "https://example.com/login" --params "{\"username\": \"test_user\", \"password\": \"test_pass\"}"
```
