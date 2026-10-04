import requests
import re
import subprocess
import shutil
from urllib.parse import urlparse


# ==========================================
# WEBSHIELD - WEB SECURITY ANALYZER
# ==========================================

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]


def webshield_scan(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "target": url,
        "score": 100,
        "issues": [],
        "headers": {},
        "status": None,
        "final_url": url,
        "server": "Unknown",
        "https": url.startswith("https://")
    }

    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "CyberSentinel/1.0"
            }
        )

        result["status"] = response.status_code
        result["final_url"] = response.url
        result["server"] = response.headers.get(
            "Server",
            "Not disclosed"
        )

        # ==================================
        # HTTPS CHECK
        # ==================================

        if response.url.startswith("https://"):
            result["https"] = True
        else:
            result["https"] = False
            result["score"] -= 20

            result["issues"].append(
                "Website is not using HTTPS."
            )

        # ==================================
        # SECURITY HEADER CHECK
        # ==================================

        for header in SECURITY_HEADERS:

            present = header in response.headers

            result["headers"][header] = present

            if not present:

                result["score"] -= 5

                result["issues"].append(
                    f"Missing security header: {header}"
                )

        # ==================================
        # COOKIE CHECK
        # ==================================

        cookie = response.headers.get(
            "Set-Cookie",
            ""
        )

        if cookie:

            if "Secure" not in cookie:

                result["score"] -= 5

                result["issues"].append(
                    "Cookie may be missing Secure attribute."
                )

            if "HttpOnly" not in cookie:

                result["score"] -= 5

                result["issues"].append(
                    "Cookie may be missing HttpOnly attribute."
                )

        result["score"] = max(
            0,
            min(result["score"], 100)
        )

        return result

    except Exception as e:

        # IMPORTANT:
        # Keep the same dictionary structure even
        # when the website cannot be reached.

        result["score"] = 0

        result["issues"].append(
            f"Unable to analyze the website: {str(e)}"
        )

        return result


# ==========================================
# MALICIOUS URL DETECTOR
# ==========================================

def url_detector(url):

    score = 0
    reasons = []

    parsed = urlparse(url)

    # ==================================
    # HTTPS CHECK
    # ==================================

    if parsed.scheme != "https":

        score += 20

        reasons.append(
            "URL does not use HTTPS."
        )

    # ==================================
    # IP ADDRESS CHECK
    # ==================================

    if parsed.hostname:

        if re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            parsed.hostname
        ):

            score += 30

            reasons.append(
                "URL uses a direct IP address."
            )

    # ==================================
    # @ SYMBOL CHECK
    # ==================================

    if "@" in url:

        score += 25

        reasons.append(
            "URL contains '@', which can be used in deceptive URLs."
        )

    # ==================================
    # LONG URL CHECK
    # ==================================

    if len(url) > 100:

        score += 10

        reasons.append(
            "URL is unusually long."
        )

    # ==================================
    # SUSPICIOUS KEYWORDS
    # ==================================

    keywords = [
        "login",
        "verify",
        "account",
        "password",
        "signin",
        "bank",
        "secure",
        "update"
    ]

    found = [
        word
        for word in keywords
        if word in url.lower()
    ]

    if len(found) >= 2:

        score += 15

        reasons.append(
            "Multiple sensitive keywords detected."
        )

    # ==================================
    # SUSPICIOUS TLD
    # ==================================

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".ml",
        ".ga"
    ]

    if parsed.hostname:

        if any(
            parsed.hostname.endswith(tld)
            for tld in suspicious_tlds
        ):

            score += 15

            reasons.append(
                "Domain uses a potentially suspicious TLD."
            )

    score = min(score, 100)

    # ==================================
    # CLASSIFICATION
    # ==================================

    if score >= 60:

        classification = "HIGH RISK"

    elif score >= 30:

        classification = "SUSPICIOUS"

    else:

        classification = "LOW RISK"

    return {
        "score": score,
        "classification": classification,
        "reasons": reasons
    }


# ==========================================
# NMAP VULNERABILITY SCANNER
# ==========================================

def nmap_scan(target):

    try:

        # Find Nmap automatically.
        # Works better across different systems.

        nmap_path = shutil.which("nmap")

        # Windows fallback
        if not nmap_path:

            windows_paths = [
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\Program Files (x86)\Nmap\nmap.exe"
            ]

            for path in windows_paths:

                if shutil.which(path):

                    nmap_path = path
                    break

        if not nmap_path:

            return {
                "success": False,
                "output": (
                    "Nmap is not installed or not available "
                    "on this server."
                )
            }

        command = [
            nmap_path,
            "-F",
            target
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60
        )

        return {
            "success": process.returncode == 0,
            "output": process.stdout
            if process.stdout
            else process.stderr
        }

    except Exception as e:

        return {
            "success": False,
            "output": str(e)
        }


# ==========================================
# CLOUD SECURITY DEMO
# ==========================================

def cloud_security_demo():

    return {

        "score": 78,

        "findings": [

            {
                "severity": "HIGH",
                "issue":
                    "Public S3 bucket configuration detected."
            },

            {
                "severity": "MEDIUM",
                "issue":
                    "IAM policy may contain excessive permissions."
            },

            {
                "severity": "LOW",
                "issue":
                    "Unused cloud resource detected."
            }

        ]
    }