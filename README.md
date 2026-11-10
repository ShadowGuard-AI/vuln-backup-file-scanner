# vuln-Backup-File-Scanner
Scans a website for common backup file extensions (e.g., .bak, .old, .swp) to identify potential information leakage. Probes are built from the parsed path of the target URL, in the same directory as the target file, on the host the operator named. Before reporting, the scanner fetches a baseline path that is certainly absent: a probe whose response matches that catchall baseline is not reported as a backup file. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-backup-file-scanner`

## Usage
`python3 main.py <url> [options]`

Example: `python3 main.py http://127.0.0.1:8080/app/page.html -o results.txt`

## Parameters
- `-h`: Show help message and exit
- `url`: The URL of the website to scan (positional, required, http:// or https:// only)
- `-o`: The output file to save the results to (optional).
- `-v`: Enable verbose output (debug logging).
- `--timeout`: Timeout in seconds for each request. Default: 10

## Behavior
- If the target URL is invalid (only http:// and https:// are accepted), the timeout is not positive, or the base URL cannot be fetched, the run exits non-zero and prints no verdict.
- When `-o` is given, the output file is written on every completed scan, including a clean scan with no findings (the file is then empty). If the output file cannot be written, the run exits non-zero.
- For a directory target such as `http://host/app/`, probes look for `index.html` plus each backup extension inside that directory.
- For a file target such as `http://host/app/page.html`, probes look for `page.html` plus each backup extension in the same directory.

## License
MIT (see LICENSE)
