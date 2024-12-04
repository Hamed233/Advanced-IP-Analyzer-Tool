#!/usr/bin/env python3
import sys
import os
import json
import socket
import logging
import asyncio
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
import dns.resolver
import whois
import requests
from rich.console import Console
from rich.table import Table
from rich.logging import RichHandler
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import aiohttp
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
from tabulate import tabulate
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
console = Console()

class IPAnalyzer:
    def __init__(self, ip: str, verbose: bool = False, export_format: str = None):
        """
        Initialize the IP Analyzer with optional verbose mode and export format.
        
        Args:
            ip (str): IP address to analyze
            verbose (bool): Enable verbose logging
            export_format (str): Export format (csv, json, html, or None)
        """
        self.ip = ip
        self.verbose = verbose
        self.export_format = export_format
        load_dotenv()
        self.abuse_ip_key = os.getenv('ABUSEIPDB_API_KEY')
        self.shodan_key = os.getenv('SHODAN_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.results_history = []

    async def analyze(self) -> Dict[str, Any]:
        """Analyze the IP address and return results."""
        if self.verbose:
            logger.info(f"Starting analysis for IP: {self.ip}")

        async with aiohttp.ClientSession() as session:
            try:
                tasks = [
                    self._get_basic_info(),
                    self._get_geolocation(session),
                    self._get_dns_info(),
                    self._get_whois_info(),
                    self._check_security(session)
                ]
                
                results_list = await asyncio.gather(*tasks)
                
                results = {
                    "Basic Info": results_list[0],
                    "Geolocation": results_list[1],
                    "DNS Information": results_list[2],
                    "WHOIS Information": results_list[3],
                    "Security Information": results_list[4]
                }

                if self.export_format:
                    self._export_results(results)
                
                self.results_history.append({
                    "ip": self.ip,
                    "timestamp": datetime.now(),
                    "results": results
                })
                
                if self.verbose:
                    logger.info("Analysis completed successfully")
                
                return results
                
            except Exception as e:
                logger.error(f"An error occurred: {e}")
                return {"Error": str(e)}

    async def _get_geolocation(self, session: aiohttp.ClientSession) -> Dict[str, str]:
        """Get geolocation information about the IP address."""
        try:
            async with session.get(f"http://ip-api.com/json/{self.ip}") as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "Country": data.get("country", "Unknown"),
                        "City": data.get("city", "Unknown"),
                        "Region": data.get("regionName", "Unknown"),
                        "ISP": data.get("isp", "Unknown"),
                        "Timezone": data.get("timezone", "Unknown"),
                        "Coordinates": f"{data.get('lat', 'Unknown')}, {data.get('lon', 'Unknown')}",
                        "Organization": data.get("org", "Unknown"),
                        "AS": data.get("as", "Unknown")
                    }
        except Exception as e:
            if self.verbose:
                logger.error(f"Error fetching geolocation data: {e}")
        return {"Error": "Could not fetch geolocation data"}

    async def _get_basic_info(self) -> Dict[str, str]:
        """Get basic information about the IP address."""
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:
            hostname = "Not found"
            if self.verbose:
                logger.warning(f"Could not resolve hostname for {self.ip}")
        
        return {
            "IP": self.ip,
            "Hostname": hostname,
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    async def _check_ssl_cert(self) -> Dict[str, Any]:
        """Check SSL certificate information for the IP."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.ip, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.ip) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "Subject": dict(x[0] for x in cert['subject']),
                        "Issuer": dict(x[0] for x in cert['issuer']),
                        "Version": cert['version'],
                        "Serial Number": cert['serialNumber'],
                        "Not Before": cert['notBefore'],
                        "Not After": cert['notAfter']
                    }
        except Exception as e:
            if self.verbose:
                logger.error(f"Error checking SSL certificate: {e}")
            return {"Error": "Could not check SSL certificate"}

    async def _check_virustotal(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Check IP reputation on VirusTotal."""
        if not self.virustotal_key:
            return {"Error": "VirusTotal API key not configured"}

        try:
            headers = {'x-apikey': self.virustotal_key}
            async with session.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip}",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "Malicious": data['data']['attributes']['last_analysis_stats']['malicious'],
                        "Suspicious": data['data']['attributes']['last_analysis_stats']['suspicious'],
                        "Harmless": data['data']['attributes']['last_analysis_stats']['harmless'],
                        "Reputation": data['data']['attributes']['reputation'],
                        "Country": data['data']['attributes']['country']
                    }
        except Exception as e:
            if self.verbose:
                logger.error(f"Error checking VirusTotal: {e}")
            return {"Error": "Could not check VirusTotal"}

    async def _trace_route(self) -> Dict[str, Any]:
        """Perform traceroute to the IP."""
        try:
            process = await asyncio.create_subprocess_exec(
                'traceroute', self.ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if stdout:
                hops = []
                for line in stdout.decode().split('\n')[1:]:  # Skip first line
                    if line.strip():
                        hops.append(line.strip())
                return {"Hops": hops}
            return {"Error": "No traceroute output"}
        except Exception as e:
            if self.verbose:
                logger.error(f"Error performing traceroute: {e}")
            return {"Error": "Could not perform traceroute"}

    async def _check_reputation(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Check IP reputation across multiple sources."""
        reputation_sources = {
            "Blocklist.de": f"http://api.blocklist.de/api/check.php?ip={self.ip}",
            "IBM X-Force": f"https://exchange.xforce.ibmcloud.com/api/ipr/{self.ip}",
            "Spamhaus": f"https://www.spamhaus.org/query/ip/{self.ip}"
        }
        
        results = {}
        for source, url in reputation_sources.items():
            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        results[source] = "Listed" if "yes" in (await response.text()).lower() else "Clean"
            except Exception:
                results[source] = "Check failed"
        
        return results

    async def _get_dns_info(self) -> Dict[str, List[str]]:
        """Get DNS information about the IP address."""
        dns_info = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'PTR', 'SOA']
        
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            for record_type in record_types:
                try:
                    answers = await asyncio.get_event_loop().run_in_executor(
                        None, 
                        lambda: dns.resolver.resolve(hostname, record_type)
                    )
                    dns_info[record_type] = [str(rdata) for rdata in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    dns_info[record_type] = []
                except Exception as e:
                    if self.verbose:
                        logger.error(f"Error fetching {record_type} records: {e}")
                    dns_info[record_type] = []
        except socket.herror:
            if self.verbose:
                logger.warning(f"Could not resolve hostname for {self.ip}")
            dns_info["Error"] = "Could not resolve hostname"
        
        return dns_info

    async def _get_whois_info(self) -> Dict[str, Any]:
        """Get WHOIS information about the IP address."""
        try:
            w = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: whois.whois(self.ip)
            )
            return {
                "Registrar": w.registrar,
                "Creation Date": str(w.creation_date),
                "Expiration Date": str(w.expiration_date),
                "Name Servers": w.name_servers,
                "Organization": w.org,
                "Emails": w.emails
            }
        except Exception as e:
            if self.verbose:
                logger.error(f"Error fetching WHOIS information: {e}")
            return {"Error": "Could not fetch WHOIS information"}

    async def _check_security(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Check security information about the IP address."""
        security_info = {}
        
        # Check AbuseIPDB if API key is available
        abuse_api_key = os.getenv('ABUSEIPDB_API_KEY')
        if abuse_api_key:
            try:
                headers = {
                    'Accept': 'application/json',
                    'Key': abuse_api_key
                }
                params = {
                    'ipAddress': self.ip,
                    'maxAgeInDays': '90',
                    'verbose': True
                }
                async with session.get('https://api.abuseipdb.com/api/v2/check', 
                                     headers=headers, 
                                     params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        security_info['AbuseIPDB'] = data.get('data', {})
                    else:
                        security_info['AbuseIPDB'] = {"Error": f"API returned status code {response.status}"}
            except Exception as e:
                if self.verbose:
                    logger.error(f"Error checking AbuseIPDB: {e}")
                security_info['AbuseIPDB'] = {"Error": str(e)}
        
        # Check VirusTotal if API key is available
        vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if vt_api_key:
            try:
                headers = {'x-apikey': vt_api_key}
                async with session.get(f'https://www.virustotal.com/api/v3/ip_addresses/{self.ip}',
                                     headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        security_info['VirusTotal'] = data.get('data', {})
                    else:
                        security_info['VirusTotal'] = {"Error": f"API returned status code {response.status}"}
            except Exception as e:
                if self.verbose:
                    logger.error(f"Error checking VirusTotal: {e}")
                security_info['VirusTotal'] = {"Error": str(e)}
        
        # Check Shodan if API key is available
        shodan_api_key = os.getenv('SHODAN_API_KEY')
        if shodan_api_key:
            try:
                async with session.get(f'https://api.shodan.io/shodan/host/{self.ip}?key={shodan_api_key}') as response:
                    if response.status == 200:
                        data = await response.json()
                        security_info['Shodan'] = data
                    else:
                        security_info['Shodan'] = {"Error": f"API returned status code {response.status}"}
            except Exception as e:
                if self.verbose:
                    logger.error(f"Error checking Shodan: {e}")
                security_info['Shodan'] = {"Error": str(e)}
        
        return security_info

    def _export_results(self, results: Dict[str, Any]) -> None:
        """Export results in the specified format."""
        if not self.export_format:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ip_analysis_{self.ip}_{timestamp}"

        if self.export_format == 'csv':
            df = pd.json_normalize(results)
            df.to_csv(f"{filename}.csv", index=False)
        elif self.export_format == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(results, f, indent=2)
        elif self.export_format == 'html':
            df = pd.json_normalize(results)
            df.to_html(f"{filename}.html")

    def generate_report(self) -> None:
        """Generate a comprehensive HTML report with visualizations."""
        if not self.results_history:
            return

        # Create visualizations
        plt.figure(figsize=(10, 6))
        timestamps = [r["timestamp"] for r in self.results_history]
        ips = [r["ip"] for r in self.results_history]
        plt.plot(timestamps, ips, marker='o')
        plt.title("IP Analysis Timeline")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("ip_analysis_timeline.png")

        # Generate HTML report
        report = f"""
        <html>
        <head>
            <title>IP Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .section {{ margin-bottom: 30px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>IP Analysis Report</h1>
                <div class="section">
                    <h2>Analysis Timeline</h2>
                    <img src="ip_analysis_timeline.png" alt="Analysis Timeline">
                </div>
                <div class="section">
                    <h2>Analysis History</h2>
                    {pd.DataFrame(self.results_history).to_html()}
                </div>
            </div>
        </body>
        </html>
        """
        
        with open("ip_analysis_report.html", 'w') as f:
            f.write(report)

def main():
    parser = argparse.ArgumentParser(description='Advanced IP Address Analyzer')
    parser.add_argument('ip', help='IP address to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-r', '--report', action='store_true', help='Generate detailed report')
    parser.add_argument('-e', '--export', choices=['json', 'csv', 'html'], help='Export results in specified format')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[RichHandler()]
    )
    
    analyzer = IPAnalyzer(args.ip, args.verbose, args.export)
    
    try:
        # Run the analysis
        results = asyncio.run(analyzer.analyze())
        
        # Print results in a nice format using Rich
        console = Console()
        
        if args.report:
            console.print("\n[bold blue]IP Analysis Report[/bold blue]")
            console.print("=" * 50)
            
            # Basic Info
            if "Basic Info" in results:
                console.print("\n[bold cyan]Basic Information[/bold cyan]")
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Property")
                table.add_column("Value")
                for key, value in results["Basic Info"].items():
                    table.add_row(key, str(value))
                console.print(table)
            
            # Geolocation
            if "Geolocation" in results:
                console.print("\n[bold cyan]Geolocation Information[/bold cyan]")
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Property")
                table.add_column("Value")
                for key, value in results["Geolocation"].items():
                    table.add_row(key, str(value))
                console.print(table)
            
            # DNS Information
            if "DNS Information" in results:
                console.print("\n[bold cyan]DNS Information[/bold cyan]")
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Record Type")
                table.add_column("Values")
                for record_type, values in results["DNS Information"].items():
                    table.add_row(record_type, str(values))
                console.print(table)
            
            # WHOIS Information
            if "WHOIS Information" in results:
                console.print("\n[bold cyan]WHOIS Information[/bold cyan]")
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Property")
                table.add_column("Value")
                for key, value in results["WHOIS Information"].items():
                    table.add_row(key, str(value))
                console.print(table)
            
            # Security Information
            if "Security Information" in results:
                console.print("\n[bold cyan]Security Information[/bold cyan]")
                for source, info in results["Security Information"].items():
                    console.print(f"\n[bold yellow]{source}[/bold yellow]")
                    if isinstance(info, dict) and "Error" not in info:
                        table = Table(show_header=True, header_style="bold magenta")
                        table.add_column("Property")
                        table.add_column("Value")
                        for key, value in info.items():
                            table.add_row(str(key), str(value))
                        console.print(table)
                    else:
                        console.print(str(info))
        
        else:
            # Simple output format
            console.print_json(data=results)
        
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
