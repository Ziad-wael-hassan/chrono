import argparse
import asyncio
import dataclasses
import datetime
import logging
import os
import sys
from typing import AsyncGenerator, List, Optional, Set

import aiohttp
from tqdm.asyncio import tqdm

try:
    import orjson as json
except ImportError:
    import json

# --- Configuration ---
USER_AGENT = "manus-url-enumerator/1.0"
CONCURRENT_REQUESTS = 10
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 1

# --- Models ---
@dataclasses.dataclass
class URLResult:
    url: str
    source: str
    timestamp: Optional[str] = None
    
    def formatted_timestamp(self) -> str:
        """Convert timestamp to human-readable format if possible."""
        if not self.timestamp or len(self.timestamp) != 14:
            return self.timestamp or ""
        
        try:
            # Parse: YYYYMMDDhhmmss
            dt = datetime.datetime(
                year=int(self.timestamp[0:4]),
                month=int(self.timestamp[4:6]),
                day=int(self.timestamp[6:8]),
                hour=int(self.timestamp[8:10]),
                minute=int(self.timestamp[10:12]),
                second=int(self.timestamp[12:14])
            )
            return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} UTC"
        except (ValueError, TypeError):
            return self.timestamp or ""

# --- Helper Functions ---
def setup_logging(verbose: bool = False, silent: bool = False) -> None:
    """Configure logging based on verbosity settings."""
    level = logging.DEBUG if verbose else (logging.ERROR if silent else logging.INFO)
    logging.basicConfig(
        level=level,
        format="[%(asctime)s %(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

def validate_date(date_str: str) -> bool:
    """Validate date format (YYYYMMDD)."""
    if len(date_str) != 8:
        return False
    try:
        datetime.datetime.strptime(date_str, "%Y%m%d")
        return True
    except ValueError:
        return False

def should_include_url(url: str, domain: str, exclude_subs: bool) -> bool:
    """Determine if a URL should be included based on domain filters."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
            
        if exclude_subs and parsed.netloc != domain:
            # Check if it's a subdomain
            if parsed.netloc.endswith(domain) and parsed.netloc != domain:
                return False
        return True
    except Exception:
        return False

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, retries: int = MAX_RETRIES) -> Optional[dict]:
    """Fetch JSON data with retry logic."""
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT) as resp:
                if resp.status == 200:
                    return await resp.json(loads=json.loads)
                elif resp.status == 429:
                    logging.warning(f"Rate limited on {url}, attempt {attempt + 1}/{retries}")
                    if attempt < retries - 1:
                        await asyncio.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                else:
                    logging.debug(f"HTTP {resp.status} for {url}")
                    return None
        except asyncio.TimeoutError:
            logging.debug(f"Timeout on {url}, attempt {attempt + 1}/{retries}")
            if attempt < retries - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
        except Exception as e:
            logging.debug(f"Error fetching {url}: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
    return None

# --- Fetchers ---
async def wayback_fetch(domain: str, from_date: Optional[str], to_date: Optional[str], 
                        exclude_subs: bool) -> AsyncGenerator[URLResult, None]:
    """Fetch URLs from Wayback Machine."""
    if from_date and not validate_date(from_date):
        logging.error(f"Invalid from_date format: {from_date}. Expected YYYYMMDD.")
        return
    if to_date and not validate_date(to_date):
        logging.error(f"Invalid to_date format: {to_date}. Expected YYYYMMDD.")
        return
        
    base = "http://web.archive.org/cdx/search/cdx"
    params = f"?url={domain}/*&output=json&fl=timestamp,original&collapse=urlkey"
    if from_date:
        params += f"&from={from_date}"
    if to_date:
        params += f"&to={to_date}"
    url = base + params

    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        data = await fetch_with_retry(session, url)
        if not data or len(data) < 2:
            logging.debug(f"No data returned from Wayback Machine for {domain}")
            return
            
        for row in data[1:]:  # Skip header row
            if len(row) >= 2 and should_include_url(row[1], domain, exclude_subs):
                yield URLResult(url=row[1], source="wayback", timestamp=row[0])

async def commoncrawl_fetch(domain: str, exclude_subs: bool) -> AsyncGenerator[URLResult, None]:
    """Fetch URLs from Common Crawl."""
    index_url = "https://index.commoncrawl.org/collinfo.json"
    
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        indexes = await fetch_with_retry(session, index_url)
        if not indexes:
            logging.debug("Failed to fetch Common Crawl indexes")
            return
            
        for idx in indexes:
            api_url = f"{idx['cdx-api']}?url={domain}/*&output=json"
            data = await fetch_with_retry(session, api_url)
            if not data:
                continue
                
            for item in data:
                if isinstance(item, dict) and should_include_url(item.get("url", ""), domain, exclude_subs):
                    yield URLResult(
                        url=item.get("url", ""), 
                        source="commoncrawl", 
                        timestamp=item.get("timestamp")
                    )

async def virustotal_fetch(domain: str, api_key: Optional[str], exclude_subs: bool) -> AsyncGenerator[URLResult, None]:
    """Fetch URLs from VirusTotal (if API key is provided)."""
    if not api_key:
        logging.warning("VirusTotal API key not provided. Skipping VirusTotal.")
        return
        
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/urls"
    headers = {
        "User-Agent": USER_AGENT,
        "x-apikey": api_key
    }
    
    async with aiohttp.ClientSession(headers=headers) as session:
        data = await fetch_with_retry(session, url)
        if not data or "data" not in data:
            logging.debug(f"No data returned from VirusTotal for {domain}")
            return
            
        for item in data.get("data", []):
            attributes = item.get("attributes", {})
            url = attributes.get("url")
            if url and should_include_url(url, domain, exclude_subs):
                yield URLResult(
                    url=url,
                    source="virustotal",
                    timestamp=attributes.get("last_modification_date")
                )

# --- Main Logic ---
async def gather_results(domains: List[str], from_date: Optional[str], to_date: Optional[str], 
                        use_vt: bool, vt_api_key: Optional[str], exclude_subs: bool) -> List[URLResult]:
    """Gather results from all sources."""
    seen_urls: Set[str] = set()
    results: List[URLResult] = []
    
    # Create all tasks
    tasks = []
    for domain in domains:
        tasks.append(wayback_fetch(domain, from_date, to_date, exclude_subs))
        tasks.append(commoncrawl_fetch(domain, exclude_subs))
        if use_vt:
            tasks.append(virustotal_fetch(domain, vt_api_key, exclude_subs))

    # Process results with progress bar
    with tqdm(total=len(tasks), desc="Fetching URLs", unit="source") as pbar:
        for task in tasks:
            async for result in task:
                # Deduplicate URLs
                if result.url not in seen_urls:
                    seen_urls.add(result.url)
                    results.append(result)
            pbar.update(1)
            
    return results

# --- Output Handling ---
def write_results(results: List[URLResult], output_file: Optional[str], urls_only: bool) -> None:
    """Write results to file or stdout."""
    lines = []
    for result in results:
        if urls_only:
            lines.append(result.url)
        else:
            readable_date = result.formatted_timestamp()
            lines.append(f"{readable_date} {result.url}")
    
    output = "\n".join(lines)
    
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output + "\n")
            logging.info(f"Results written to {output_file}")
        except IOError as e:
            logging.error(f"Failed to write to {output_file}: {e}")
            print(output)
    else:
        print(output)

# --- CLI ---
def parse_args():
    parser = argparse.ArgumentParser(description="Enumerate archived URLs for given domains")
    parser.add_argument("domains", nargs="+", help="Domain(s) to enumerate")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("--no-subs", "-ns", action="store_true", help="Exclude subdomains")
    parser.add_argument("--from", "-fd", dest="from_date", help="From date (YYYYMMDD)")
    parser.add_argument("--to", "-td", dest="to_date", help="To date (YYYYMMDD)")
    parser.add_argument("--virustotal", "-vt", action="store_true", help="Use VirusTotal")
    parser.add_argument("--vt-key", help="VirusTotal API key (or set VT_API_KEY environment variable)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--silent", "-s", action="store_true", help="Silent output")
    parser.add_argument("--urls-only", "-u", action="store_true", help="Output only URLs without dates")
    parser.add_argument("--concurrency", "-c", type=int, default=CONCURRENT_REQUESTS, 
                       help=f"Number of concurrent requests (default: {CONCURRENT_REQUESTS})")
    parser.add_argument("--timeout", "-t", type=int, default=REQUEST_TIMEOUT,
                       help=f"Request timeout in seconds (default: {REQUEST_TIMEOUT})")
    return parser.parse_args()

async def main_async():
    args = parse_args()
    setup_logging(args.verbose, args.silent)
    
    # Validate dates
    if args.from_date and not validate_date(args.from_date):
        logging.error("Invalid from_date format. Expected YYYYMMDD.")
        return
        
    if args.to_date and not validate_date(args.to_date):
        logging.error("Invalid to_date format. Expected YYYYMMDD.")
        return
        
    # Get VirusTotal API key
    vt_api_key = args.vt_key or os.environ.get("VT_API_KEY")
    if args.virustotal and not vt_api_key:
        logging.warning("VirusTotal requested but no API key provided. Use --vt-key or set VT_API_KEY environment variable.")
        
    logging.info(f"Starting URL enumeration for {len(args.domains)} domain(s)")
    
    try:
        results = await gather_results(
            args.domains, 
            args.from_date, 
            args.to_date, 
            args.virustotal, 
            vt_api_key,
            args.no_subs
        )
        
        logging.info(f"Found {len(results)} unique URLs")
        write_results(results, args.output, args.urls_only)
        
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        if args.verbose:
            logging.exception("Detailed error traceback:")
        sys.exit(1)

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()