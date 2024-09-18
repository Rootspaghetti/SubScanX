### SubScanX

**SubScanX** is a powerful command-line tool designed for finding subdomains and checking their status using HTTPX. It combines subdomain enumeration with HTTP request validation and additional features such as screenshot capture, WHOIS lookup, and vulnerability scanning to provide a comprehensive analysis of your target domain.

## Features

- **Subdomain Enumeration:** Uses `subfinder` to discover subdomains of the target domain.
- **HTTP Status Check:** Validates each subdomain using HTTPX with customizable request types (GET, POST, HEAD).
- **Concurrency:** Supports concurrent requests to speed up the checking process.
- **Customizable Timeout:** Set a timeout for each HTTP request.
- **Screenshot Capture:** Takes screenshots of subdomains based on HTTP status codes.
- **WHOIS Lookup:** Optionally performs a WHOIS lookup before starting subdomain scanning.
- **Vulnerability Scan:** Performs a vulnerability scan using Nikto.
- **Output Formats:** Saves results in a text file with sorted HTTP status codes.

## Installation

Ensure you have Python 3.8 or later installed. Install the required libraries by running:

```bash
git clone https://github.com/Rootspaghetti/SubScanX.git
cd SubScanX
pip install -r requirements.txt
```

## Basic Usage

To run SubScanX, use the following command structure:

```bash
python3 SubScanX.py domain [options]
```

## Required Argument

- `<domain>`: The target domain you want to scan for subdomains (e.g., example.com).

## Options

- `-r`, `--request_type`: Specifies the type of HTTP request to send to each subdomain. Options include:
  - `GET` (default): Sends a GET request.
  - `POST`: Sends a POST request.
  - `HEAD`: Sends a HEAD request.

- `-t`, `--timeout`: Sets the timeout for each HTTP request in seconds. Default is 10 seconds.

- `-m`, `--max_concurrent_tasks`: Controls the maximum number of concurrent HTTP requests. Default is 10.

- `-s`, `--screenshot_status`: Specifies the HTTP status code that will trigger a screenshot capture of the subdomain.

- `-p`, `--ports`: Specifies ports to scan (comma separated).

- `--whois`: Performs a WHOIS lookup before starting the subdomain scan.

- `--whois_json`: Saves WHOIS information as a JSON file.

- `--whois_csv`: Saves WHOIS information as a CSV file.

- `--vuln-scan`: Performs a vulnerability scan with Nikto. Note that this may take a long time.

## Example Commands

- **Basic Subdomain Scan:**

  ```bash
  python3 SubScanX.py example.com
  ```

  This command discovers subdomains of `example.com` and checks their HTTP status using GET requests, saving results to `example.com.txt`.

- **Custom Request Type and Timeout:**

  ```bash
  python3 SubScanX.py example.com -r POST -t 5.0
  ```

  This command sends POST requests to subdomains of `example.com` with a 5-second timeout for each request.

- **Increased Concurrency:**

  ```bash
  python3 SubScanX.py example.com -m 200
  ```

  This command allows up to 200 concurrent HTTP requests, speeding up the scanning process.

- **Screenshot on Specific Status Code:**

  ```bash
  python3 SubScanX.py example.com -s 404
  ```

  This command will take screenshots of subdomains that return a 404 HTTP status code.

- **Perform WHOIS Lookup:**

  ```bash
  python3 SubScanX.py example.com --whois
  ```

  This command performs a WHOIS lookup for the domain before starting the subdomain scan.

- **Save WHOIS Information as JSON:**

  ```bash
  python3 SubScanX.py example.com --whois_json
  ```

  This command saves the WHOIS information in a JSON file.

- **Save WHOIS Information as CSV:**

  ```bash
  python3 SubScanX.py example.com --whois_csv
  ```

  This command saves the WHOIS information in a CSV file.

- **Perform Vulnerability Scan:**

  ```bash
  python3 SubScanX.py example.com --vuln-scan
  ```

  This command performs a vulnerability scan with Nikto. Note that this may take a long time.

## Output

The results of the scan are saved in a file named after the target domain (e.g., `example.com.txt`). This file contains each discovered subdomain and its corresponding HTTP status code, sorted by status codes from highest to lowest.

## Author

By: Root@spaghetti

To report suggestions and bugs, email: rootspaghetti@gmail.com
```