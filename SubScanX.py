import subprocess
import asyncio
import httpx
import argparse
import os
from rich.console import Console
from rich.table import Table
from rich.text import Text
from pyfiglet import Figlet
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from webdriver_manager.firefox import GeckoDriverManager
from selenium.common.exceptions import WebDriverException
import whois
import json
import csv
from Wappalyzer import Wappalyzer, WebPage
import requests
import nmap
from datetime import datetime

console = Console()

def display_banner():
    figlet = Figlet(font='starwars')
    banner = figlet.renderText("SubScanX")
    neon_banner = Text(banner, style="bold bright_cyan on black", justify="center")
    subtitle = Text("by: Root@spaghetti", style="bold white on black", justify="center")
    console.print(neon_banner)
    console.print(subtitle)
    console.print("\n" * 2)

def run_subfinder(domain):
    result = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    subdomains = result.stdout.splitlines()
    return subdomains

async def check_httpx(subdomain, request_type, timeout, retries=3):
    async with httpx.AsyncClient(http2=True) as client:
        for attempt in range(retries):
            try:
                url = f"http://{subdomain}"
                if request_type == "GET":
                    response = await client.get(url, timeout=timeout)
                elif request_type == "POST":
                    response = await client.post(url, timeout=timeout)
                elif request_type == "HEAD":
                    response = await client.head(url, timeout=timeout)
                return subdomain, response.status_code
            except httpx.RequestError:
                if attempt < retries - 1:
                    console.print(f"[yellow]Retrying {subdomain} ({attempt + 1}/{retries})...[/yellow]")
                    await asyncio.sleep(1)
                else:
                    try:
                        url = f"https://{subdomain}"
                        if request_type == "GET":
                            response = await client.get(url, timeout=timeout)
                        elif request_type == "POST":
                            response = await client.post(url, timeout=timeout)
                        elif request_type == "HEAD":
                            response = await client.head(url, timeout=timeout)
                        return subdomain, response.status_code
                    except httpx.RequestError:
                        return subdomain, "Connection Error"
                    except httpx.TimeoutException:
                        return subdomain, "Timeout"
            except httpx.TimeoutException:
                return subdomain, "Timeout"

async def take_screenshot(subdomain, output_dir="screenshots"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    options = Options()
    options.headless = True
    driver_path = GeckoDriverManager().install()
    driver = webdriver.Firefox(executable_path=driver_path, options=options)

    try:
        url = f"http://{subdomain}"
        driver.get(url)
        screenshot_path = os.path.join(output_dir, f"{subdomain}.png")
        driver.save_screenshot(screenshot_path)
        console.print(f"[bold green]Screenshot saved:[/bold green] {screenshot_path}")
        return screenshot_path
    except WebDriverException as e:
        console.print(f"[bold red]Error taking screenshot for {subdomain}:[/bold red] {e}")
    finally:
        driver.quit()

def detect_technology(subdomain):
    try:
        url = f"http://{subdomain}"
        response = requests.get(url)
        if response.status_code == 200:
            webpage = WebPage.new_from_response(response)
            wappalyzer = Wappalyzer.latest()
            technologies = wappalyzer.analyze(webpage)
            return technologies
        else:
            return f"Failed to connect to {subdomain}"
    except requests.exceptions.RequestException as e:
        return f"Error detecting technology for {subdomain}: {e}"

async def process_subdomains(subdomains, request_type, timeout, max_concurrent_tasks, progress, screenshot_status):
    semaphore = asyncio.Semaphore(max_concurrent_tasks)

    async def sem_task(subdomain):
        async with semaphore:
            subdomain, status_code = await check_httpx(subdomain, request_type, timeout)
            progress.append((subdomain, status_code))
            if screenshot_status and str(status_code) == screenshot_status:
                await take_screenshot(subdomain)
            return subdomain, status_code

    tasks = [sem_task(subdomain) for subdomain in subdomains]
    results = await asyncio.gather(*tasks)
    return results

async def detect_technologies_for_subdomains(subdomains):
    for subdomain in subdomains:
        technologies = detect_technology(subdomain)
        console.print(f"[bold magenta]Technologies for {subdomain}:[/bold magenta] {technologies}")

async def display_progress(progress, total_subdomains):
    while len(progress) < total_subdomains:
        await asyncio.sleep(1)
        console.print(f"[bold yellow]Processed:[/bold yellow] {len(progress)} / {total_subdomains}")

    console.print("[bold green]All subdomains processed.[/bold green]")

def save_results_to_txt(results, filename):
    sorted_results = sorted(results, key=lambda x: (isinstance(x[1], int), x[1]), reverse=True)
    with open(filename, mode='w') as file:
        for subdomain, status in sorted_results:
            file.write(f"{subdomain}, {status}\n")

def display_results(results):
    sorted_results = sorted(results, key=lambda x: (isinstance(x[1], int), x[1]), reverse=True)

    table = Table(title="HTTPX Results")
    table.add_column("Subdomain", justify="left", style="cyan", no_wrap=True)
    table.add_column("Status Code", justify="center", style="green")

    for subdomain, status in sorted_results:
        table.add_row(subdomain, str(status))

    console.print(table)

def perform_whois(domain, save_json=False, save_csv=False):
    try:
        whois_info = whois.whois(domain)
        console.print(f"[bold blue]WHOIS Information for {domain}:[/bold blue]")

        if 'domain_name' in whois_info:
            console.print(f"[bold cyan]Domain Name:[/bold cyan] {', '.join(whois_info['domain_name'])}")
        if 'registrar' in whois_info:
            console.print(f"[bold cyan]Registrar:[/bold cyan] {whois_info['registrar']}")
        if 'creation_date' in whois_info:
            console.print(f"[bold cyan]Creation Date:[/bold cyan] {whois_info['creation_date']}")
        if 'updated_date' in whois_info:
            console.print(f"[bold cyan]Updated Date:[/bold cyan] {whois_info['updated_date']}")
        if 'expiration_date' in whois_info:
            console.print(f"[bold cyan]Expiration Date:[/bold cyan] {whois_info['expiration_date']}")
        if 'name_servers' in whois_info:
            console.print(f"[bold cyan]Name Servers:[/bold cyan] {', '.join(whois_info['name_servers'])}")

        analyze_whois_info(whois_info)
        analyze_whois_privacy(whois_info)

        if save_json:
            save_whois_to_json(whois_info, f"{domain}_whois.json")
        if save_csv:
            save_whois_to_csv(whois_info, f"{domain}_whois.csv")
    except Exception as e:
        console.print(f"[bold red]WHOIS lookup failed for {domain}: {str(e)}[/bold red]")

def save_whois_to_json(whois_info, filename):
    with open(filename, mode='w') as file:
        json.dump(whois_info, file, indent=4)

def save_whois_to_csv(whois_info, filename):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        for key, value in whois_info.items():
            if isinstance(value, list):
                value = ', '.join(value)
            writer.writerow([key, value])

def analyze_whois_info(whois_info):
    today = datetime.now()

    if 'expiration_date' in whois_info and whois_info['expiration_date']:
        expiration_date = whois_info['expiration_date']
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if isinstance(expiration_date, datetime):
            days_until_expiration = (expiration_date - today).days
            console.print(f"[bold cyan]Domain Expiration Date:[/bold cyan] {expiration_date} ({days_until_expiration} days remaining)")
        else:
            console.print(f"[bold cyan]Domain Expiration Date:[/bold cyan] {expiration_date}")

    if 'registrar' in whois_info:
        registrar = whois_info['registrar']
        console.print(f"[bold cyan]Registrar:[/bold cyan] {registrar}")

def analyze_whois_privacy(whois_info):
    if 'registrant_email' in whois_info:
        console.print(f"[bold cyan]Registrant Email:[/bold cyan] {whois_info['registrant_email']}")
    if 'registrant_name' in whois_info:
        console.print(f"[bold cyan]Registrant Name:[/bold cyan] {whois_info['registrant_name']}")
    if 'admin_email' in whois_info:
        console.print(f"[bold cyan]Admin Email:[/bold cyan] {whois_info['admin_email']}")
    if 'tech_email' in whois_info:
        console.print(f"[bold cyan]Tech Email:[/bold cyan] {whois_info['tech_email']}")

def perform_bulk_whois(domains, save_json=False, save_csv=False):
    for domain in domains:
        perform_whois(domain, save_json, save_csv)

async def scan_ports(subdomain, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=subdomain, arguments=f'-p {ports}')
    open_ports = [port for port in nm[subdomain]['tcp'] if nm[subdomain]['tcp'][port]['state'] == 'open']
    return open_ports

async def process_ports_for_subdomains(subdomains, ports):
    results = {}
    for subdomain in subdomains:
        try:
            open_ports = await scan_ports(subdomain, ports)
            results[subdomain] = open_ports
        except KeyError:
            console.print(f"[bold red]No scan results for {subdomain}. It may not be reachable.[/bold red]")
    return results

async def main():
    parser = argparse.ArgumentParser(description="Subdomain scanner with various features.")
    parser.add_argument("-d", "--domain", required=True, help="The domain to scan.")
    parser.add_argument("-r", "--request_type", choices=["GET", "POST", "HEAD"], default="GET", help="Type of HTTP request to make.")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout for HTTP requests.")
    parser.add_argument("-m", "--max_concurrent_tasks", type=int, default=10, help="Max concurrent HTTP requests.")
    parser.add_argument("-s", "--screenshot_status", type=str, help="Status code to trigger screenshot.")
    parser.add_argument("-p", "--ports", type=str, help="Ports to scan (comma separated).")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup.")
    parser.add_argument("--whois_json", action="store_true", help="Save WHOIS info as JSON.")
    parser.add_argument("--whois_csv", action="store_true", help="Save WHOIS info as CSV.")
    args = parser.parse_args()

    display_banner()

    subdomains = run_subfinder(args.domain)

    progress = []
    if args.screenshot_status:
        await process_subdomains(subdomains, args.request_type, args.timeout, args.max_concurrent_tasks, progress, args.screenshot_status)
    else:
        await process_subdomains(subdomains, args.request_type, args.timeout, args.max_concurrent_tasks, progress, None)

    await detect_technologies_for_subdomains(subdomains)

    if args.ports:
        port_results = await process_ports_for_subdomains(subdomains, args.ports)
        console.print(f"[bold blue]Port Scan Results:[/bold blue]")
        for subdomain, open_ports in port_results.items():
            console.print(f"{subdomain}: {', '.join(map(str, open_ports))}")

    display_results(progress)
    save_results_to_txt(progress, "httpx_results.txt")

    if args.whois:
        perform_bulk_whois(subdomains, args.whois_json, args.whois_csv)

if __name__ == "__main__":
    asyncio.run(main())