import argparse
import json
import urllib.request
import ssl

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (Protects against MITM attacks)",
    "Content-Security-Policy": "Prevents Cross-Site Scripting (XSS) and data injection",
    "X-Frame-Options": "Protects against Clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-sniffing vulnerabilities",
    "Referrer-Policy": "Controls how much referrer information is sent with requests",
    "Permissions-Policy": "Restricts browser features (camera, microphone, geolocation)"
}

def scan_headers(url, cookie=None):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n[*] Scanning HTTP Security Headers for: {url}\n")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPRedirectHandler()
    )

    req = urllib.request.Request(
        url, 
        headers={"User-Agent": "Mozilla/5.0 (Header-Security-Checker/1.0)"}
    )

    # ADDED: Inject session cookie if provided
    if cookie:
        req.add_header("Cookie", cookie)

    try:
        with opener.open(req, timeout=5) as response:
            final_url = response.geturl()
            if final_url != url:
                print(f"  [i] Followed redirect -> {final_url}\n")

            headers = {k: v for k, v in response.info().items()}
            
            present_headers = {}
            missing_headers = {}

            csp_key = next((k for k in headers if k.lower() == "content-security-policy"), None)
            csp_val = headers[csp_key] if csp_key else ""

            for header, description in SECURITY_HEADERS.items():
                matched_key = next((k for k in headers if k.lower() == header.lower()), None)
                
                if header == "X-Frame-Options" and not matched_key and "frame-ancestors" in csp_val.lower():
                    present_headers["X-Frame-Options (via CSP frame-ancestors)"] = {
                        "value": "Defined in CSP",
                        "description": description
                    }
                    print(f"  [+] PRESENT : X-Frame-Options            -> Covered via CSP frame-ancestors")
                elif matched_key:
                    present_headers[header] = {
                        "value": headers[matched_key],
                        "description": description
                    }
                    print(f"  [+] PRESENT : {header:<28} -> {headers[matched_key][:40]}")
                else:
                    missing_headers[header] = description
                    print(f"  [-] MISSING : {header:<28} -> {description}")

            score = (len(present_headers) / len(SECURITY_HEADERS)) * 100
            print(f"\n[✓] Security Score: {score:.1f}% ({len(present_headers)}/{len(SECURITY_HEADERS)} headers present)")

            return {
                "target_url": final_url,
                "security_score_percent": round(score, 1),
                "present_headers": present_headers,
                "missing_headers": missing_headers
            }

    except Exception as e:
        print(f"[!] Error scanning {url}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Web Header Security Scanner")
    parser.add_argument("-u", "--url", default="https://google.com", help="Target URL")
    parser.add_argument("-c", "--cookie", default=None, help="Session cookie string for authenticated endpoints")
    parser.add_argument("-o", "--output", default="header_results.json", help="JSON output path")
    args = parser.parse_args()

    results = scan_headers(args.url, args.cookie)

    if results:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[✓] Results exported to '{args.output}'")

if __name__ == "__main__":
    main()
