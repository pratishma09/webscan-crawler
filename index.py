import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

visited = set()

SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Strict-Transport-Security"
]

OUTDATED_SOFTWARE = {
    "Apache": "2.4.6",
    "nginx": "1.14.0"
}

vulnerabilities = {
    "missing_headers": set(),
    "outdated_software": set(),
    "insecure_forms": set()
}

def check_security_headers(headers):
    for header in SECURITY_HEADERS:
        if header not in headers:
            vulnerabilities["missing_headers"].add(header)

def check_outdated_software(headers):
    for field in ["Server", "X-Powered-By"]:
        if field in headers:
            value = headers[field].lower()
            for tech, version in OUTDATED_SOFTWARE.items():
                if tech.lower() in value and version in value:
                    vulnerabilities["outdated_software"].add(f"{tech} {version}")

def check_insecure_forms(soup, page_url):
    for form in soup.find_all("form"):
        method = form.get("method", "").lower()
        action = form.get("action")
        if not action or method == "get":
            path = urlparse(page_url).path or "/"
            vulnerabilities["insecure_forms"].add(path)

MAX_PAGES = 10
pages_scanned = 0

def crawl(url, base_domain):
    global pages_scanned
    if len(visited) >= MAX_PAGES or pages_scanned >= MAX_PAGES:
        return
    if url in visited or not url.startswith(base_domain):
        return

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        visited.add(url)
        pages_scanned += 1

        soup = BeautifulSoup(response.text, "html.parser")

        check_security_headers(response.headers)
        check_outdated_software(response.headers)
        check_insecure_forms(soup, url)

        for a in soup.find_all("a", href=True):
            next_url = urljoin(url, a['href']).split("#")[0]
            crawl(next_url, base_domain)

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")

def generate_report(domain):
    print(f"\nVULNERABILITY SCAN REPORT FOR {domain.upper()}:")

    for h in vulnerabilities["missing_headers"]:
        print(f"- MISSING HTTP SECURITY HEADER: {h}")

    for software in vulnerabilities["outdated_software"]:
        print(f"- OUTDATED SOFTWARE VERSION DETECTED: {software}")

    for form_path in vulnerabilities["insecure_forms"]:
        print(f"- FORM WITHOUT PROPER METHOD ATTRIBUTE: {form_path}")

if __name__ == "__main__":
    start_url = input("Enter URL to scan (e.g., https://example.com): ").strip()
    parsed_url = urlparse(start_url)

    if not parsed_url.scheme or not parsed_url.netloc:
        print("Invalid URL format. Please include https:// or http://")
    else:
        base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        print(f"Starting scan on {base_domain}...\n")
        crawl(start_url, base_domain)

        if pages_scanned > 0:
            generate_report(base_domain)
        else:
            print(f"\nScan could not be completed. The site {base_domain} is unreachable or invalid.")
