# SQL Injection Scanner

An automated SQL injection detection tool that integrates crawling, dynamic form extraction, and vulnerability testing into a single pipeline.

The scanner combines Katana for crawling, Playwright for handling dynamic web content, and sqlmap for detecting SQL injection vulnerabilities.

---

## Features

* Web crawling using Katana
* Extraction of potential injection points:

  * Query parameters
  * Path-based parameters
  * HTML forms (including dynamically rendered forms)
* Deduplication of targets to reduce redundant testing
* Optional automated SQL injection testing using sqlmap
* Configurable scanning modes (`query`, `path`, `form`, `all`)
* Adjustable performance and scan depth settings

---

## Setup and Requirements

### Requirements

Make sure the following are installed:

* Python 3.8+
* Katana (ProjectDiscovery)
* sqlmap
* Playwright (Python)

---

### Installation

#### 1. Clone the repository

```bash
git clone https://github.com/gabrielhrga/sqli_discovery_tool.git
```

---

#### 2. Install Python dependencies

```bash
pip install playwright
```

---

#### 3. Install Playwright browsers and dependencies

```bash
playwright install --with-deps
```

---

#### 4. Install Katana

Follow official instructions from ProjectDiscovery or:

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

Make sure it is in your PATH:

```bash
katana -h
```

---

#### 5. Install sqlmap

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap
```

Or ensure it is globally available:

```bash
sqlmap -h
```

---

## Usage

```bash
python scanner.py <url> [OPTIONS]
```

---

### Arguments

#### Required

* `<url>` – Target URL to scan

---

#### Optional

| Option         | Description                                     | Default |
| -------------- | ----------------------------------------------- | ------- |
| `-m`, `--mode` | Extraction mode: `query`, `path`, `form`, `all` | `all`   |
| `--depth`      | Crawling depth for Katana                       | `2`     |
| `--inject`     | Enable SQL injection testing                    | OFF     |
| `--threads`    | Number of concurrent sqlmap threads             | `5`     |
| `--risk`       | sqlmap risk level (1–3)                         | `1`     |

---

### Examples

#### Basic scan (no injection)

```bash
python scanner.py https://example.com
```

---

#### Scan only forms

```bash
python scanner.py https://example.com -m form
```

---

#### Enable SQL injection testing

```bash
python scanner.py https://example.com --inject
```

---

#### Advanced scan

```bash
python scanner.py https://example.com --inject --threads 10 --risk 2 --depth 3
```
