# HTTP Security Header Scanner

A lightweight, Python-based CLI tool designed to analyze HTTP response headers for critical web application security controls, clickjacking protections, and Content Security Policies (CSP).

---

## Features

* **Core Header Verification:** Evaluates key security headers including HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
* **Smart Clickjacking Detection:** Inspects both `X-Frame-Options` and CSP `frame-ancestors` directives to accurately identify framing protections.
* **Redirect Support:** Automatically follows HTTP redirects (`301`/`302`) to audit final landing endpoints.
* **Authenticated Scanning:** Supports custom session cookies via CLI flags for auditing authenticated pages.
* **Automated Scoring & Export:** Calculates a security percentage score and exports detailed results to JSON.

---

## Installation

No external dependencies are required. The script relies entirely on standard Python standard library modules (`urllib`, `ssl`, `json`, `argparse`).

```bash
git clone [https://github.com/CyberReya/header-scanner.git](https://github.com/CyberReya/header-scanner.git)
cd header-scanner
