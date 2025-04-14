import re
import email
from email import policy
from urllib.parse import urlparse

# List of suspicious keywords often used in phishing
SUSPICIOUS_KEYWORDS = [
    "verify your account", "urgent action required", "click here", "login now", "security alert"
]

# List of known trusted domains (you can expand this)
TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "github.com"
]

def is_domain_trusted(domain):
    return any(domain.endswith(td) for td in TRUSTED_DOMAINS)

def extract_links(text):
    return re.findall(r'https?://\S+', text)

def analyze_email(raw_email):
    msg = email.message_from_string(raw_email, policy=policy.default)
    analysis_report = {
        "from": msg['From'],
        "subject": msg['Subject'],
        "suspicious_links": [],
        "suspicious_keywords": [],
        "is_spoofed_domain": False,
        "verdict": "Legitimate"
    }

    # Extract domain
    if msg['From']:
        match = re.search(r'@([^\s>]+)', msg['From'])
        if match:
            domain = match.group(1).lower()
            if not is_domain_trusted(domain):
                analysis_report["is_spoofed_domain"] = True

    # Check content for keywords and links
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
    else:
        body = msg.get_content()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in body.lower():
            analysis_report["suspicious_keywords"].append(keyword)

    for link in extract_links(body):
        parsed = urlparse(link)
        domain = parsed.netloc.lower()
        if not is_domain_trusted(domain):
            analysis_report["suspicious_links"].append(link)

    # Determine verdict
    if analysis_report["suspicious_links"] or analysis_report["suspicious_keywords"] or analysis_report["is_spoofed_domain"]:
        analysis_report["verdict"] = "Suspicious"

    return analysis_report

# Example usage
if __name__ == "__main__":
    with open("sample_email.txt", "r") as f:
        raw_email = f.read()
        report = analyze_email(raw_email)
        for k, v in report.items():
            print(f"{k}: {v}")
