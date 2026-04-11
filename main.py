import json
from urllib.parse import urlparse, parse_qs
import subprocess
from concurrent.futures import ThreadPoolExecutor
from playwright.sync_api import sync_playwright
from urllib.parse import urljoin

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


def extract_form_targets(url: str) -> list:
    targets = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(url, timeout=10000)

            forms = page.query_selector_all("form")

            for form in forms:
                method = form.get_attribute("method")
                action = form.get_attribute("action")

                method = method.upper() if method else "GET"

                # Resolve action URL
                if action:
                    form_url = urljoin(url, action)
                else:
                    form_url = url  # fallback

                inputs = form.query_selector_all("input, textarea, select")

                param_names = []

                for inp in inputs:
                    name = inp.get_attribute("name")
                    if name:
                        param_names.append(name)

                # Skip empty forms
                if not param_names:
                    continue

                # Build POST data string
                data = "&".join([f"{p}=test" for p in param_names])

                # Create ONE target per parameter
                for param in param_names:
                    targets.append({
                        "type": "form",
                        "method": method,
                        "url": form_url,
                        "param": param,
                        "data": data
                    })

            browser.close()

    except Exception:
        return []

    return targets


# -----------------------------
# CORE PIPELINE
# -----------------------------

def collect_targets(katana_file: str) -> list:
    targets = []
    unique_urls = set()

    with open(katana_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                entry = json.loads(line)
            except:
                continue

            targets.extend(extract_query_targets(entry))
            targets.extend(extract_path_targets(entry))

            # Collect base URLs for form extraction
            try:
                endpoint = entry["request"]["endpoint"]
                parsed = urlparse(endpoint)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                unique_urls.add(base_url)
            except:
                pass

    # Form extraction (future Playwright integration)
    for url in unique_urls:
        targets.extend(extract_form_targets(url))

    return targets


def deduplicate_targets(targets: list) -> list:
    seen = set()
    unique = []

    for t in targets:
        key = (t["type"], t["method"], t["url"], t["param"])

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

def run_katana(target_url: str, output_file: str):
    command = [
        "katana",
        "-u", target_url,
        "-jc",
        "-j",
        "-ob",
        "-or",
        "-ef", "png,css",
        "-o", output_file
    ]

    subprocess.run(command, check=True)


def run_sqlmap(target: dict):
    if target["type"] == "query":
        url = f"{target['url']}?{target['param']}=test"
        command = [
            "sqlmap",
            "-u", url,
            "-p", target["param"],
            "--batch"
        ]

    elif target["type"] == "path":
        url = target["url"].replace(target["param"], "1")
        command = [
            "sqlmap",
            "-u", url,
            "--batch"
        ]

    elif target["type"] == "form":
        command = [
            "sqlmap",
            "-u", target["url"],
            "--data", target["data"],
            "-p", target["param"],
            "--batch"
        ]

    else:
        return

    subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


# -----------------------------
# MAIN
# -----------------------------

def main():
    target_url = "https://pentest-ground.com:4280/vulnerabilities/sqli/"
    katana_out = "katana_output.jsonl"
    targets_out = "targets.jsonl"

    print("[*] Running katana...")
    run_katana(target_url, katana_out)

    print("[*] Collecting targets...")
    targets = collect_targets(katana_out)

    print("[*] Deduplicating targets...")
    targets = deduplicate_targets(targets)

    print(f"[*] Total targets: {len(targets)}")

    print("[*] Saving targets...")
    save_targets(targets, targets_out)

    print("[*] Running sqlmap...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(run_sqlmap, targets)


if __name__ == "__main__":
    main()