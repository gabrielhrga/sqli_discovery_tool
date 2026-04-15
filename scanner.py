import json
import argparse
from urllib.parse import urlparse, parse_qs, urljoin
import subprocess
from concurrent.futures import ThreadPoolExecutor
from playwright.sync_api import sync_playwright

# -----------------------------
# ARGUMENT PARSING
# -----------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        usage="scanner.py <url> [OPTIONS]",
        description="Automated SQL Injection Scanner using Katana + sqlmap",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Positional
    parser.add_argument("url", help="Target URL to scan")

    # Extraction
    extraction = parser.add_argument_group("Extraction Options")
    extraction.add_argument(
        "-m", "--mode",
        choices=["query", "path", "form", "all"],
        default="all",
        help="Extraction mode"
    )

    # Katana
    katana = parser.add_argument_group("Katana Options")
    katana.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Crawl depth"
    )

    # sqlmap
    sqlmap = parser.add_argument_group("sqlmap Options")
    sqlmap.add_argument(
        "--inject",
        action="store_true",
        help="Enable SQL injection testing"
    )
    sqlmap.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of concurrent sqlmap threads"
    )
    sqlmap.add_argument(
        "--risk",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="sqlmap risk level"
    )

    parser.epilog = """
Examples:
  scanner.py https://example.com
  scanner.py https://example.com --inject
  scanner.py https://example.com -m form --depth 3
"""

    return parser.parse_args()


# -----------------------------
# TARGET EXTRACTORS
# -----------------------------

def extract_query_targets(katana_entry: dict) -> list:
    targets = []

    try:
        endpoint = katana_entry["request"]["endpoint"]
    except KeyError:
        return targets

    parsed = urlparse(endpoint)

    if not parsed.query:
        return targets

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = parse_qs(parsed.query).keys()

    for param in params:
        targets.append({
            "type": "query",
            "method": "GET",
            "url": base_url,
            "param": param,
            "data": None
        })

    return targets


def extract_path_targets(katana_entry: dict) -> list:
    targets = []

    try:
        endpoint = katana_entry["request"]["endpoint"]
    except KeyError:
        return targets

    parsed = urlparse(endpoint)
    path_segments = parsed.path.strip("/").split("/")

    for segment in path_segments:
        if segment.isdigit():
            targets.append({
                "type": "path",
                "method": "GET",
                "url": endpoint,
                "param": segment,
                "data": None
            })

    return targets


def extract_form_targets(page, url: str) -> list:
    targets = []

    try:
        page.goto(url, wait_until="networkidle", timeout=15000)

        try:
            page.wait_for_selector("form, input", timeout=5000)
        except:
            return []

        page.wait_for_timeout(2000)

        forms = page.query_selector_all("form")

        for form in forms:
            method = form.get_attribute("method")
            action = form.get_attribute("action")

            method = method.upper() if method else "GET"
            form_url = urljoin(url, action) if action else url

            inputs = form.query_selector_all("input, textarea, select")

            param_values = {}

            for inp in inputs:
                name = inp.get_attribute("name") or inp.get_attribute("id")
                if not name:
                    continue

                input_type = inp.get_attribute("type") or ""
                if input_type in ["submit", "button"]:
                    continue

                value = inp.get_attribute("value") or "1"

                if "csrf" in name.lower():
                    continue

                param_values[name] = value

            if not param_values:
                continue

            if len(param_values) == 1:
                continue

            print(f"[+] Form found on {form_url} with params: {list(param_values.keys())}")

            if method == "GET":
                query = "&".join([f"{k}={v}" for k, v in param_values.items()])
                full_url = f"{form_url}?{query}"

                targets.append({
                    "type": "form",
                    "method": "GET",
                    "url": full_url,
                    "param": ",".join(param_values.keys()),
                    "data": None
                })

            else:
                data = "&".join([f"{k}={v}" for k, v in param_values.items()])

                targets.append({
                    "type": "form",
                    "method": "POST",
                    "url": form_url,
                    "param": ",".join(param_values.keys()),
                    "data": data
                })

    except Exception as e:
        print(f"[ERROR] {url}: {e}")

    return targets


# -----------------------------
# CORE PIPELINE
# -----------------------------

def collect_targets(katana_file: str, mode: str) -> list:
    targets = []
    unique_urls = set()

    with open(katana_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
            except:
                continue

            if mode in ["query", "all"]:
                targets.extend(extract_query_targets(entry))

            if mode in ["path", "all"]:
                targets.extend(extract_path_targets(entry))

            try:
                endpoint = entry["request"]["endpoint"]
                parsed = urlparse(endpoint)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                if any(base_url.lower().endswith(ext) for ext in [
                    ".png", ".jpg", ".jpeg", ".gif", ".css", ".js",
                    ".svg", ".woff", ".ico", ".pdf"
                ]):
                    continue

                unique_urls.add(base_url)

            except:
                pass

    if mode in ["form", "all"]:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            for url in unique_urls:
                page = browser.new_page()
                targets.extend(extract_form_targets(page, url))
                page.close()

            browser.close()

    return targets


def deduplicate_targets(targets: list) -> list:
    seen = set()
    unique = []

    for t in targets:
        key = (t["type"], t["method"], t["url"], t.get("data"))

        if key in seen:
            continue

        seen.add(key)
        unique.append(t)

    return unique


def save_targets(targets: list, output_file: str):
    with open(output_file, "w", encoding="utf-8") as f:
        for t in targets:
            f.write(json.dumps(t) + "\n")


# -----------------------------
# EXECUTION
# -----------------------------

def run_katana(target_url: str, output_file: str, depth: int):
    command = [
        "katana",
        "-u", target_url,
        "-d", str(depth),
        "-jc",
        "-j",
        "-ob",
        "-or",
        "-o", output_file
    ]

    subprocess.run(command, check=True)


def run_sqlmap(target: dict, args):
    if target["type"] == "query":
        url = f"{target['url']}?{target['param']}=test"
        command = ["sqlmap", "-u", url, "-p", target["param"], "--batch", "--risk", str(args.risk)]

    elif target["type"] == "path":
        url = target["url"].replace(target["param"], "1")
        command = ["sqlmap", "-u", url, "--batch", "--risk", str(args.risk)]

    elif target["type"] == "form":
        if target["method"] == "GET":
            command = ["sqlmap", "-u", target["url"], "-p", target["param"], "--batch", "--risk", str(args.risk)]
        else:
            if not target["data"]:
                return
            command = ["sqlmap", "-u", target["url"], "--data", target["data"], "-p", target["param"], "--batch", "--risk", str(args.risk)]
    else:
        return

    subprocess.run(command)
    #subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# -----------------------------
# MAIN
# -----------------------------

def main():
    args = parse_arguments()

    katana_out = "katana_output.jsonl"
    targets_out = "targets.jsonl"

    print("[*] Running katana...")
    run_katana(args.url, katana_out, args.depth)

    print("[*] Collecting targets...")
    targets = collect_targets(katana_out, args.mode)

    print("[*] Deduplicating targets...")
    targets = deduplicate_targets(targets)

    print(f"[*] Total targets: {len(targets)}")

    print("[*] Saving targets...")
    save_targets(targets, targets_out)

    if args.inject:
        print("[*] Running sqlmap...")
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            executor.map(lambda t: run_sqlmap(t, args), targets)

if __name__ == "__main__":
    main()