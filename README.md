# SubScanX

**SubScanX** is a powerful command-line tool designed for finding subdomains and checking their status using HTTPX. It combines subdomain enumeration with HTTP request validation to provide a comprehensive analysis of your target domain.

## Features

- **Subdomain Enumeration**: Uses `subfinder` to discover subdomains of the target domain.
- **HTTP Status Check**: Validates each subdomain using HTTPX with customizable request types (GET, POST, HEAD).
- **Concurrency**: Supports concurrent requests to speed up the checking process.
- **Customizable Timeout**: Set a timeout for each HTTP request.
- **Progress Tracking**: Displays real-time progress and allows users to check status by pressing Enter.
- **Output Formats**: Saves results in a text file with sorted HTTP status codes.

## Installation

Ensure you have Python 3.8 or later installed. Install the required libraries by running:

`git clone https://github.com/Rootspaghetti/SubScanX.git`

`cd SubScanX`

`pip install -r requirements.txt`

`python3 SubScanX.py`

## Basic UsageTo run SubScanX, use the following command structure:
          

python3 SubScanX.py domain [options]
## Required Argument

<domain>:The target domain you want to scan for subdomains (e.g., example.com).

                                        
-r,--request-type: Specifies the type of HTTP request to send to each subdomain. Options include:
  
   GET (default): Sends a GET request.
   
   POST: Sends a POST request.
   
   HEAD: Sends a HEAD request.

-t, --timeout: Sets the timeout for each HTTP request in seconds. Default is 3.0 seconds.

-c, --concurrency: Controls the maximum number of concurrent HTTP requests. The default value is 100.

-o, --output: Specifies the output file name. If not provided, the results will be saved in a file named <domain>.txt.

-f, --format: Defines the output file format. Options include:

   csv: Saves results as a CSV file.
   
   json: Saves results as a JSON file.Default is txt, saving results in a plain text format.
   
## Example Commands
        Basic Subdomain Scan:            
        python3 SubScanX.py example.com 
This command discovers subdomains of example.com and checks their HTTP status using GET requests, saving results to example.com.txt.

                                        Custom Request Type and Timeout:
    python3 SubScanX.py example.com -r POST -t 5.0
This command sends POST requests to subdomains of example.com with a 5-second timeout for each request.
Increased Concurrency:python subscanx.py example.com -c 200This command allows up to 200 concurrent HTTP requests, speeding up the scanning process.

                                        Save as JSON:
        python3 SubScanX.py example.com -f json
        
This command saves the results in a JSON file named example.com.json.

  ## Output
The results of the scan are saved in a file named after the target domain (e.g., example.com.txt). This file contains each discovered subdomain and its corresponding HTTP status code, sorted by status codes from highest to lowest.

## Author

By:Root@spaghetti

to report suggestions and bugs 
rootspaghetti@gmail.com
