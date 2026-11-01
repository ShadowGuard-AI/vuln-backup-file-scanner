# vuln-Backup-File-Scanner
Scans a website for common backup file extensions (e.g., .bak, .old, .swp) to identify potential information leakage. Probes are built from the parsed path of the target URL, in the same directory as the target file, on the host the operator named. Before reporting, the scanner fetches a baseline path that is certainly absent: a probe whose response matches that catchall baseline is not reported as a backup file. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-backup-file-scanner`

## Usage
`./vuln-backup-file-scanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: The output file to save the results to (optional).
- `-v`: Enable verbose output (debug logging).
- `--timeout`: Timeout in seconds for each request. Default: 10

## Behavior
- If the target URL is invalid or the base URL cannot be fetched, the run exits non-zero and prints no verdict.
- For a directory target such as `http://host/app/`, probes look for `index.html` plus each backup extension inside that directory.
- For a file target such as `http://host/app/page.html`, probes look for `page.html` plus each backup extension in the same directory.

## License
Copyright (c) ShadowStrikeHQ
