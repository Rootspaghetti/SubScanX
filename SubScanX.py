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

async def display_progress(progress, total_subdomains):
    while len(progress) < total_subdomains:
        await asyncio.sleep(1)
        console.print(f"[bold yellow]Processed:[/bold yellow] {len(progress)} / {total_subdomains} subdomains")
    
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

def perform_whois(domain):
    try:
        whois_info = whois.whois(domain)
        console.print(f"[bold blue]WHOIS Information for {domain}:[/bold blue]")

        for key, value in whois_info.items():
            console.print(f"[bold cyan]{key}:[/bold cyan] {value}")

    except Exception as e:
        console.print(f"[bold red]WHOIS lookup failed for {domain}: {str(e)}[/bold red]")

async def main():
    display_banner()

    parser = argparse.ArgumentParser(description="Subfinder + HTTPX CLI tool with extended features")
    parser.add_argument("domain", help="Domain to find subdomains for")
    parser.add_argument("-r", "--request-type", choices=["GET", "POST", "HEAD"], default="GET", help="Type of HTTP request to make (default: GET)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Timeout for each request (in seconds, default: 3.0)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Max number of concurrent requests (default: 100)")
    parser.add_argument("-ss", "--screenshot-status", type=str, help="HTTP status code to trigger screenshot capture")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup before starting subdomain scanning")
    args = parser.parse_args()

    if args.whois:
        perform_whois(args.domain)

    console.print(f"[bold green]Finding subdomains for:[/bold green] {args.domain}")
    subdomains = run_subfinder(args.domain)
    total_subdomains = len(subdomains)

    progress = []

    console.print(f"[bold green]Checking subdomains with HTTPX ({args.request_type} requests)...[/bold green]")

    progress_task = asyncio.create_task(display_progress(progress, total_subdomains))

    results = await process_subdomains(subdomains, args.request_type, args.timeout, args.concurrency, progress, args.screenshot_status)

    await progress_task

    display_results(results)

    output_filename = f"{args.domain}.txt"
    save_results_to_txt(results, output_filename)

    console.print(f"[bold green]Results saved to:[/bold green] {output_filename}")

if __name__ == "__main__":
    asyncio.run(main())