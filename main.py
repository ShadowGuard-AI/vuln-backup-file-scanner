import argparse
import requests
import logging
import os
import sys
from urllib.parse import urlparse, urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of common backup file extensions to scan for
BACKUP_EXTENSIONS = ['.bak', '.old', '.swp', '.tmp', '~', '.backup', '.orig', '.inc']

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans a website for common backup file extensions to identify potential information leakage.")
    parser.add_argument("url", help="The URL of the website to scan.")
    parser.add_argument("-o", "--output", help="The output file to save the results to (optional).", default=None)  # Allow specifying an output file
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("--timeout", type=float, default=10, help="Timeout in seconds for each request. Default: 10")
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates if the provided URL is a valid URL.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # Check for scheme (e.g., http, https) and network location (e.g., example.com)
    except:
        return False

def fetch_probe(session, url, timeout):
    """Fetch a probe URL. Returns (status, body) or None when no response arrived."""
    try:
        response = session.get(url, allow_redirects=True, timeout=timeout)
        return response.status_code, response.content
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking {url}: {e}")
        return None

def scan_for_backup_files(base_url, timeout=10):
    """
    Scans a website for common backup file extensions.

    Args:
        base_url (str): The base URL of the website to scan.
        timeout (float): Timeout in seconds for each request.

    Returns:
        tuple: (found_files, probes_reached). Raises RuntimeError when the
        base URL itself cannot be fetched, so no verdict is printed for a
        target that was not reached.
    """
    found_files = []
    session = requests.Session()  # Use a session for connection pooling

    try:
        response = session.get(base_url, allow_redirects=True, timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Error fetching base URL {base_url}: {e}")

    # Build probes from the parsed base path only, on the operator named host.
    parsed = urlparse(base_url)
    url_path = parsed.path or "/"
    if url_path.endswith('/'):
        directory = url_path
        filename = "index.html"
    else:
        directory = url_path.rsplit('/', 1)[0] + '/'
        filename = os.path.basename(url_path)
    dir_url = f"{parsed.scheme}://{parsed.netloc}{directory}"

    # Baseline: a path that is certainly absent. A probe whose final status
    # and body match the baseline is a catchall answer, not a backup file.
    baseline_url = urljoin(dir_url, "definitely-absent-baseline-9f3k.bak")
    baseline = fetch_probe(session, baseline_url, timeout)

    probes_reached = 0
    for ext in BACKUP_EXTENSIONS:
        backup_url = urljoin(dir_url, filename + ext)
        result = fetch_probe(session, backup_url, timeout)
        if result is None:
            continue
        probes_reached += 1
        status, body = result
        if status != 200:
            logging.debug(f"URL {backup_url} returned status code: {status}")
            continue
        if baseline is not None and baseline[0] == 200 and baseline[1] == body:
            logging.debug(f"URL {backup_url} matches the catchall baseline; not a finding.")
            continue
        logging.info(f"Found backup file: {backup_url}")
        found_files.append(backup_url)

    return found_files, probes_reached


def main():
    """
    Main function to execute the backup file scanner.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    logging.info(f"Scanning for backup files at: {args.url}")
    try:
        found_files, probes_reached = scan_for_backup_files(args.url, timeout=args.timeout)
    except RuntimeError as e:
        logging.error(str(e))
        logging.error("Scan not performed; no verdict is available.")
        sys.exit(1)

    if probes_reached == 0:
        logging.error("No probe reached the target. Scan not performed; no verdict is available.")
        sys.exit(1)

    if found_files:
        logging.info("Found the following backup files:")
        for file in found_files:
            logging.info(file)

        if args.output:
            try:
                with open(args.output, "w") as f:
                    for file in found_files:
                        f.write(file + "\n")
                logging.info(f"Results saved to: {args.output}")
            except IOError as e:
                logging.error(f"Error writing to file: {e}")
    else:
        logging.info("No backup files found.")

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Basic scan: python vuln_backup_file_scanner.py https://www.example.com
# 2. Scan with verbose output: python vuln_backup_file_scanner.py https://www.example.com -v
# 3. Scan and save results to a file: python vuln_backup_file_scanner.py https://www.example.com -o results.txt
# 4. If target url is a file: python vuln_backup_file_scanner.py https://www.example.com/file.html