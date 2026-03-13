import json
from urllib.parse import urlparse, parse_qs
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# 1) Testing for query parameters

def normalize_katana_entry(katana_entry: dict) -> dict | None:
    """
    Normalize a single Katana JSON entry into a minimal sqlmap-ready object.
    Returns None if no query parameters are found.
    """

    try:
        method = katana_entry["request"]["method"]
        endpoint = katana_entry["request"]["endpoint"]
    except KeyError:
        return None  # malformed entry

    parsed_url = urlparse(endpoint)

    if not parsed_url.query:
        return None

    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

    query_params = parse_qs(parsed_url.query)
    param_names = list(query_params.keys())

    normalized = {
        "method": method,
        "base_url": base_url,
        "params": param_names
    }

    return normalized

def normalize_file(katana_jsonl_path: str, output_path: str) -> None:
    seen = set()

    with open(katana_jsonl_path, "r", encoding="utf-8") as infile, \
         open(output_path, "w", encoding="utf-8") as outfile:

        for line in infile:
            line = line.strip()
            if not line:
                continue

            try:
                katana_entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            normalized = normalize_katana_entry(katana_entry)
            if not normalized:
                continue

            method = normalized["method"]
            base_url = normalized["base_url"]

            # Discuss singular vs multiple parameters
            for param in normalized["params"]:
                dedup_key = (method, base_url, param)

                if dedup_key in seen:
                    continue

                seen.add(dedup_key)

                output_object = {
                    "method": method,
                    "base_url": base_url,
                    "param": param
                }

                outfile.write(json.dumps(output_object) + "\n")

def run_katana(target_url: str, output_file: str):
    command = [
        "katana",
        "-u", target_url,
        "-jc",  #JS crawling
        "-j",   #jsonl format
        "-ob",  #omit body
        "-or",  #omit raw request
        "-ef", "png,css", #filters by extension
        "-f", "qurl",
        "-o", output_file
        # optional -f qurl for endpoints with query strings
        # optional -d 3 for crawl depth=3
        # optional rate limit
    ]

    subprocess.run(command, check=True)

def run_sqlmap(target: dict):
    base_url = target["base_url"]
    param = target["param"]
    method = target["method"]

    if method == "GET":
        print(f"[*] Testing {param} on {base_url}...")

        url = f"{base_url}?{param}=test"
        command = [
            "sqlmap",
            "-u", url,
            "-p", param,
            "--batch"
        ]

    else:
        # Placeholder for POST later
        return
    
    subprocess.run(
        command,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

from datetime import datetime


def generate_report(stats: dict, report_file="scan_report.txt"):
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Count endpoints discovered
    with open(stats["katana_file"], "r", encoding="utf-8") as f:
        endpoints_discovered = sum(1 for _ in f)

    # Count endpoints with parameters / unique targets
    with open(stats["targets_file"], "r", encoding="utf-8") as f:
        endpoints_with_params = sum(1 for _ in f)

    unique_targets = endpoints_with_params

    with open(report_file, "w", encoding="utf-8") as report:

        report.write("SQL Injection Discovery Report\n")
        report.write("==============================\n\n")

        report.write(f"Target: {stats['target']}\n")
        report.write(f"Scan time: {scan_time}\n\n")

        report.write("Crawl Results\n")
        report.write("-------------\n")
        report.write(f"Endpoints discovered: {endpoints_discovered}\n")
        report.write(f"Endpoints with parameters: {endpoints_with_params}\n\n")

        report.write("Injection Targets\n")
        report.write("-----------------\n")
        report.write(f"Unique injection targets: {unique_targets}\n")

        report.write("SQL Injection Results\n")
        report.write("---------------------\n")

        """
        report.write(f"Injectable parameters found: {len(injectable_params)}\n\n")

        if injectable_params:
            report.write("Injectable parameters:\n")
            for item in injectable_params:
                report.write(f" - {item['url']} (param: {item['param']})\n")
        """

def main():
    target_url = "http://testphp.vulnweb.com/"
    katana_out = "katana_output.jsonl"
    normalized_out = "targets.jsonl"

    print("[*] Running katana...")
    run_katana(target_url, katana_out)

    print("[*] Normalizing katana output...")
    normalize_file(katana_out, normalized_out)

    print("[*] Running sqlmap...")
    targets = []

    with open(normalized_out, "r", encoding="utf-8") as f:
        for line in f:
            targets.append(json.loads(line))

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(run_sqlmap, targets)

    """
    stats = {
        "target": target_url,
        "katana_file": katana_out,
        "targets_file": normalized_out,
    }
    generate_report(stats)
    """

if __name__ == "__main__":
    main()