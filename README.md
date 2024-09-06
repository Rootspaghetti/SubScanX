### SubScanX

**SubScanX** is a powerful command-line tool designed for finding subdomains and checking their status using HTTPX. It combines subdomain enumeration with HTTP request validation and additional features such as screenshot capture, WHOIS lookup, and technology detection to provide a comprehensive analysis of your target domain.

## Features

- **Subdomain Enumeration:** Uses `subfinder` to discover subdomains of the target domain.
- **HTTP Status Check:** Validates each subdomain using HTTPX with customizable request types (GET, POST, HEAD).
- **Concurrency:** Supports concurrent requests to speed up the checking process.
- **Customizable Timeout:** Set a timeout for each HTTP request.
- **Progress Tracking:** Displays real-time progress and allows users to check status by pressing Enter.
- **Screenshot Capture:** Takes screenshots of subdomains based on HTTP status codes.
- **WHOIS Lookup:** Optionally performs a WHOIS lookup before starting subdomain scanning.
- **Technology Detection:** Identifies technologies used by subdomains using Wappalyzer.
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

- `-r`, `--request-type`: Specifies the type of HTTP request to send to each subdomain. Options include:
  - `GET` (default): Sends a GET request.
  - `POST`: Sends a POST request.
  - `HEAD`: Sends a HEAD request.

- `-t`, `--timeout`: Sets the timeout for each HTTP request in seconds. Default is 3.0 seconds.

- `-c`, `--concurrency`: Controls the maximum number of concurrent HTTP requests. The default value is 100.

- `-o`, `--output`: Specifies the output file name. If not provided, the results will be saved in a file named `<domain>.txt`.

- `-f`, `--format`: Defines the output file format. Options include:
  - `csv`: Saves results as a CSV file.
  - `json`: Saves results as a JSON file.
  - `txt` (default): Saves results in a plain text format.

- `-ss`, `--screenshot-status`: Specifies the HTTP status code that will trigger a screenshot capture of the subdomain.

- `--whois`: Performs a WHOIS lookup before starting the subdomain scan.

- `--detect-tech`: Detects technologies used by the subdomains after checking their HTTP status.

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
  python3 SubScanX.py example.com -c 200
  ```

  This command allows up to 200 concurrent HTTP requests, speeding up the scanning process.

- **Save as JSON:**

  ```bash
  python3 SubScanX.py example.com -f json
  ```

  This command saves the results in a JSON file named `example.com.json`.

- **Screenshot on Specific Status Code:**

  ```bash
  python3 SubScanX.py example.com -ss 404
  ```

  This command will take screenshots of subdomains that return a 404 HTTP status code.

- **Perform WHOIS Lookup:**

  ```bash
  python3 SubScanX.py example.com --whois
  ```

  This command performs a WHOIS lookup for the domain before starting the subdomain scan.

- **Detect Technologies:**

  ```bash
  python3 SubScanX.py example.com --detect-tech
  ```

  This command detects technologies used by subdomains after checking their HTTP status.

## Output

The results of the scan are saved in a file named after the target domain (e.g., `example.com.txt`). This file contains each discovered subdomain and its corresponding HTTP status code, sorted by status codes from highest to lowest.

## Author

By: Root@spaghetti

To report suggestions and bugs, email: rootspaghetti@gmail.com