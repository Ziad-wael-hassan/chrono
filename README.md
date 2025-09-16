# Chrono

**Chrono** is a fast, asynchronous URL enumerator designed to discover archived and historical URLs for a given domain. It queries multiple public sources, including The Wayback Machine, Common Crawl, and VirusTotal, to build a comprehensive list of associated URLs.

This tool was created by **nullz**.

## Features

- **Multiple Sources**: Gathers URLs from The Wayback Machine, Common Crawl, and VirusTotal.
- **Asynchronous & Fast**: Built with Python's `asyncio` to perform concurrent lookups for high speed.
- **Date Filtering**: Filter Wayback Machine results by a `from` and `to` date (`YYYYMMDD` ).
- **Subdomain Control**: Option to include or exclude subdomains.
- **Flexible Input**: Accepts domains as command-line arguments or piped from `stdin`.
- **User-Friendly**: Includes a progress bar and robust error handling with automatic retries.
- **Customizable Output**: Output URLs only or include timestamps.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/chrono.git
    cd chrono
    ```

2.  **Install dependencies:**
    It's recommended to use a Python virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3.  **Make the script executable:**
    ```bash
    chmod +x chrono.py
    ```

## Usage
./chrono.py [domains...] [options]

### Options

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| ` ` | `domains` | One or more domains to enumerate. |
| `-o` | `--output` | Output file to save results. |
| `-ns`| `--no-subs` | Exclude subdomains from the results. |
| `-fd`| `--from` | From date for Wayback Machine (Format: YYYYMMDD ). |
| `-td`| `--to` | To date for Wayback Machine (Format: YYYYMMDD). |
| `-vt`| `--virustotal` | Enable querying the VirusTotal API. |
| ` ` | `--vt-key` | VirusTotal API key (or set `VT_API_KEY` env var). |
| `-u` | `--urls-only` | Output only URLs without timestamps. |
| `-c` | `--concurrency`| Number of concurrent requests per host. |
| `-t` | `--timeout` | Request timeout in seconds. |
| `-v` | `--verbose` | Enable verbose logging for debugging. |
| `-s` | `--silent` | Suppress all non-error logging. |

### Examples

**1. Enumerate a single domain and save to a file:**
```bash
./chrono.py example.com -o example_urls.txt

2. Enumerate multiple domains, excluding subdomains:
Bash
./chrono.py example.com anotherexample.org --no-subs
3. Read domains from a file (domains.txt) and query VirusTotal:
(Requires VT_API_KEY environment variable to be set)
Bash
cat domains.txt | ./chrono.py --virustotal --urls-only
4. Find URLs for a domain created between 2020 and 2022:
Bash
./chrono.py example.com --from 2020:01:01 --to 2022:12:31