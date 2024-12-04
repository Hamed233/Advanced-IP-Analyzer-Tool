# Advanced IP Analyzer Tool 🔍

A powerful, asynchronous IP analysis tool that provides comprehensive information about IP addresses, including geolocation, DNS records, WHOIS data, and security intelligence from multiple sources.

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Author](https://img.shields.io/badge/author-Hamed%20Esam-blue.svg)](https://twitter.com/Hamed__Esam)

## Features 🚀

- 📍 **Geolocation Analysis**: Country, city, region, timezone, and coordinates
- 🔍 **DNS Record Retrieval**: A, AAAA, MX, NS, TXT, PTR, and SOA records
- 📋 **WHOIS Information**: Registration details, nameservers, and organization info
- 🛡️ **Security Checks**: Integration with AbuseIPDB, VirusTotal, and Shodan
- 📊 **Rich Console Output**: Beautiful, formatted console display
- 📑 **Multiple Export Formats**: JSON, CSV, and HTML reports
- ⚡ **Asynchronous Operations**: Fast, concurrent data gathering
- 🎯 **Detailed Reporting**: Comprehensive analysis with visualizations

## Installation 📦

1. Clone the repository:
```bash
git clone https://github.com/Hamed233/Advanced-IP-Analyzer-Tool.git
cd Advanced-IP-Analyzer-Tool
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file from the template:
```bash
cp .env.example .env
```

4. Add your API keys to the `.env` file:
```env
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
```

## Usage 💻

### Basic Usage
```bash
python ip_analyzer.py 8.8.8.8
```

### With Verbose Output and HTML Report
```bash
python ip_analyzer.py 8.8.8.8 -v -r -e html
```

### Command Line Options
- `-v, --verbose`: Enable verbose output
- `-r, --report`: Generate detailed report
- `-e, --export {json,csv,html}`: Export results in specified format

## Example Output 📝

Here's an example analysis of an IP address:

```
IP Analysis Report
==================================================

Basic Information
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property  ┃ Value                          ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ IP        │ 197.46.103.160                 │
│ Hostname  │ host-197.46.103.160.tedata.net │
│ Timestamp │ 2024-12-04 22:54:19            │
└───────────┴────────────────────────────────┘

Geolocation Information
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ Property     ┃ Value             ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ Country      │ Egypt             │
│ City         │ Cairo             │
│ Region       │ Cairo Governorate │
│ ISP          │ TE Data           │
│ Timezone     │ Africa/Cairo      │
│ Coordinates  │ 30.0588, 31.2268  │
│ Organization │ TE-AS             │
│ AS           │ AS8452            │
└──────────────┴───────────────────┘

WHOIS Information
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property        ┃ Value                                ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Registrar       │ GoDaddy.com, LLC                     │
│ Name Servers    │ ['NS1.TEDATA.NET', 'NS2.TEDATA.NET'] │
│ Organization    │ Domains By Proxy, LLC                │
│ Emails          │ abuse@godaddy.com                    │
└─────────────────┴──────────────────────────────────────┘
```

## Dependencies 📚

Core dependencies:
- `requests`: HTTP requests
- `python-whois`: WHOIS lookups
- `dnspython`: DNS queries
- `aiohttp`: Async HTTP
- `rich`: Console formatting
- See `requirements.txt` for full list

## API Keys 🔑

For full functionality, obtain API keys from:
- [AbuseIPDB](https://www.abuseipdb.com/api)
- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [Shodan](https://account.shodan.io/register)

## Contributing 🤝

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Author 👨‍💻

**Hamed Esam**
- Twitter: [@Hamed__Esam](https://x.com/hamedesam_dev)
- Website: [albashmoparmeg.com](https://albashmoparmeg.com)
- GitHub: [@Hamed233](https://github.com/Hamed233)

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments 🙏

- Thanks to all the API providers
- Community contributors and feedback
- Python async community
