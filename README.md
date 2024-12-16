# SubScanX

SubScanX is an automated reconnaissance tool for bug bounty hunters and penetration testers. It simplifies the process of gathering subdomains, identifying vulnerabilities, and exploiting common web security issues.

## Features
- Subdomain discovery
- HTTP probing with status codes
- CORS vulnerability scanning
- Nuclei vulnerability scans
- Parameter discovery with Arjun
- URL collection with Gau and Waybackurls
- File type filtering (JS, PNG, PDF, etc.)
- SQL injection testing with SQLMap
- XSS detection with Dalfox
- Directory brute-forcing with Feroxbuster
- Nmap vulnerability scans
- Social hijacking detection with SocialHunter
- Bypass testing for 403/401 errors

## Installation
Clone the repository and set up the tool by running the following commands:

```bash
git clone https://github.com/Rootspaghetti/SubScanX.git
cd SubScanX
chmod +x installer.sh
chmod +x subscanx.sh
bash installer.sh
```

The installer.sh script will install all necessary dependencies.

Usage

To start the tool, run:

```bash
bash subscanx.sh
```

Follow the on-screen prompts to perform reconnaissance on your target domain. The results will be saved in a directory named after the domain.

Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized usage against systems without explicit permission is illegal. The developer is not responsible for any misuse.


---

Happy Hunting!
