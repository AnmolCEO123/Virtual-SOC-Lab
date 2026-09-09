from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

import os
import ipaddress
import base64
import requests
from urllib.parse import urlparse

# =========================================================
# CONFIG
# =========================================================

load_dotenv()

app = Flask(__name__)
CORS(app)

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

VT_HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}


# =========================================================
# BASIC ROUTES
# =========================================================


@app.route("/")
def home():
    return jsonify(
        {"status": "online", "service": "Virtual SOC Lab API", "version": "2.0"}
    )


@app.route("/api/health")
def health():
    return jsonify({"status": "healthy", "service": "Virtual SOC Lab API"})


# =========================================================
# HELPER FUNCTIONS
# =========================================================


def detect_target_type(target):
    """
    Detect whether input is:
    IP / URL / DOMAIN
    """

    # -------------------------
    # IP
    # -------------------------
    try:
        ipaddress.ip_address(target)
        return "IP"
    except ValueError:
        pass

    # -------------------------
    # URL
    # -------------------------
    url_candidate = target

    if not url_candidate.startswith(("http://", "https://")):
        url_candidate = "https://" + url_candidate

    parsed = urlparse(url_candidate)

    if parsed.scheme in ("http", "https") and parsed.netloc:
        # If original input explicitly had http/https
        # OR contains a path/query, treat as URL.
        if (
            target.startswith(("http://", "https://"))
            or parsed.path not in ("", "/")
            or parsed.query
        ):
            return "URL"

    # -------------------------
    # DOMAIN
    # -------------------------
    hostname = parsed.hostname

    if hostname and "." in hostname and " " not in hostname:
        return "DOMAIN"

    return None


def get_stats(attributes):
    """
    Extract VirusTotal analysis statistics.
    """

    stats = attributes.get("last_analysis_stats", {})

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "timeout": stats.get("timeout", 0),
    }


def get_verdict(stats):
    """
    Convert VT statistics into a simple SOC verdict.
    """

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        return "HIGH RISK"

    if suspicious > 0:
        return "MEDIUM RISK"

    return "LOW RISK"


def make_headers():
    return {"x-apikey": VT_API_KEY}


# =========================================================
# IP ANALYSIS
# =========================================================


def analyze_ip(target):

    url = f"{VT_BASE_URL}/ip_addresses/{target}"

    response = requests.get(url, headers=make_headers(), timeout=15)

    if response.status_code == 404:
        return {"error": "IP report not found", "target": target}, 404

    if response.status_code == 429:
        return {"error": "VirusTotal API rate limit reached. Try again later."}, 429

    response.raise_for_status()

    data = response.json().get("data", {})
    attributes = data.get("attributes", {})

    stats = get_stats(attributes)
    verdict = get_verdict(stats)

    return {
        "target": target,
        "type": "IP",
        "verdict": verdict,
        "analysis": stats,
        "country": attributes.get("country"),
        "continent": attributes.get("continent"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "reputation": attributes.get("reputation"),
        "network": attributes.get("network"),
        "tags": attributes.get("tags", []),
    }, 200


# =========================================================
# DOMAIN ANALYSIS
# =========================================================


def analyze_domain(target):

    url = f"{VT_BASE_URL}/domains/{target}"

    response = requests.get(url, headers=make_headers(), timeout=15)

    if response.status_code == 404:
        return {"error": "Domain report not found", "target": target}, 404

    if response.status_code == 429:
        return {"error": "VirusTotal API rate limit reached. Try again later."}, 429

    response.raise_for_status()

    data = response.json().get("data", {})
    attributes = data.get("attributes", {})

    stats = get_stats(attributes)
    verdict = get_verdict(stats)

    return {
        "target": target,
        "type": "DOMAIN",
        "verdict": verdict,
        "analysis": stats,
        "reputation": attributes.get("reputation"),
        "registrar": attributes.get("registrar"),
        "creation_date": attributes.get("creation_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "tags": attributes.get("tags", []),
        "categories": attributes.get("categories", {}),
        "whois_date": attributes.get("whois_date"),
    }, 200


# =========================================================
# URL ANALYSIS
# =========================================================


def analyze_url(target):

    # Make sure URL has scheme
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # VirusTotal accepts URL-safe base64 without "=" padding
    url_id = (
        base64.urlsafe_b64encode(target.encode("utf-8")).decode("utf-8").rstrip("=")
    )

    url = f"{VT_BASE_URL}/urls/{url_id}"

    response = requests.get(url, headers=make_headers(), timeout=15)

    # Existing URL report
    if response.status_code == 200:

        data = response.json().get("data", {})
        attributes = data.get("attributes", {})

        stats = get_stats(attributes)
        verdict = get_verdict(stats)

        return {
            "target": target,
            "type": "URL",
            "verdict": verdict,
            "analysis": stats,
            "reputation": attributes.get("reputation"),
            "title": attributes.get("title"),
            "last_final_url": attributes.get("last_final_url"),
            "http_response_code": attributes.get("last_http_response_code"),
            "times_submitted": attributes.get("times_submitted"),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", []),
        }, 200

    # Rate limit
    if response.status_code == 429:
        return {"error": "VirusTotal API rate limit reached. Try again later."}, 429

    # -----------------------------------------------------
    # URL not already available
    # Try submitting it for scanning
    # -----------------------------------------------------

    scan_response = requests.post(
        f"{VT_BASE_URL}/urls", headers=make_headers(), data={"url": target}, timeout=20
    )

    if scan_response.status_code == 429:
        return {"error": "VirusTotal API rate limit reached. Try again later."}, 429

    if scan_response.status_code >= 400:

        try:
            details = scan_response.json()
        except Exception:
            details = None

        return {
            "error": "VirusTotal could not scan this URL",
            "target": target,
            "details": details,
        }, scan_response.status_code

    analysis_data = scan_response.json().get("data", {})

    return {
        "target": target,
        "type": "URL",
        "verdict": "ANALYSIS SUBMITTED",
        "analysis": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "timeout": 0,
        },
        "analysis_id": analysis_data.get("id"),
        "message": (
            "URL was submitted to VirusTotal. "
            "Run the analysis again after a short wait "
            "to retrieve the completed report."
        ),
    }, 202


# =========================================================
# MAIN ANALYZER API
# =========================================================


@app.route("/api/analyze")
def analyze():

    target = request.args.get("target", "").strip()

    # -------------------------
    # Empty input
    # -------------------------

    if not target:
        return jsonify({"error": "Please provide an IP address, domain or URL."}), 400

    # -------------------------
    # API key check
    # -------------------------

    if not VT_API_KEY:
        return jsonify({"error": "VirusTotal API key is not configured."}), 500

    # -------------------------
    # Detect type
    # -------------------------

    target_type = detect_target_type(target)

    if not target_type:
        return (
            jsonify(
                {
                    "error": (
                        "Invalid target. Enter a valid IP address, " "domain or URL."
                    ),
                    "target": target,
                }
            ),
            400,
        )

    # -------------------------
    # Analyze
    # -------------------------

    try:

        if target_type == "IP":
            result, status = analyze_ip(target)

        elif target_type == "DOMAIN":
            result, status = analyze_domain(target)

        elif target_type == "URL":
            result, status = analyze_url(target)

        else:
            return jsonify({"error": "Unsupported target type."}), 400

        return jsonify(result), status

    # -------------------------
    # VirusTotal HTTP errors
    # -------------------------

    except requests.exceptions.HTTPError as error:

        response = getattr(error, "response", None)

        if response is not None:

            if response.status_code == 401:
                return (
                    jsonify({"error": "VirusTotal API key is invalid or expired."}),
                    401,
                )

            if response.status_code == 403:
                return jsonify({"error": "VirusTotal API access is forbidden."}), 403

            if response.status_code == 404:
                return (
                    jsonify(
                        {
                            "error": "VirusTotal report not found.",
                            "target": target,
                            "type": target_type,
                        }
                    ),
                    404,
                )

            if response.status_code == 429:
                return (
                    jsonify(
                        {
                            "error": (
                                "VirusTotal API rate limit reached. " "Try again later."
                            )
                        }
                    ),
                    429,
                )

        return (
            jsonify({"error": "VirusTotal API request failed.", "details": str(error)}),
            502,
        )

    # -------------------------
    # Connection errors
    # -------------------------

    except requests.exceptions.RequestException as error:

        return (
            jsonify(
                {"error": "Unable to connect to VirusTotal.", "details": str(error)}
            ),
            502,
        )

    # -------------------------
    # Unexpected errors
    # -------------------------

    except Exception as error:

        return (
            jsonify({"error": "Unexpected server error.", "details": str(error)}),
            500,
        )


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000, debug=True)
