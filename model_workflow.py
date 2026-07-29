import json
from datetime import datetime, timezone
from pathlib import Path

# Automatically locates the root 'threat-intel-mvp' folder relative to this script
BASE_DIR = Path(__file__).resolve().parent.parent
STIX_PATH = BASE_DIR / "feed" / "stix.json"
SUMMARY_PATH = BASE_DIR / "summary.md"

def load_stix():
    with open(STIX_PATH, "r") as f:
        return json.load(f)

def enrich_stix(stix_obj):
    pattern = stix_obj["pattern"]
    indicators = pattern.split(" OR ")

    enrichment = []
    for ind in indicators:
        if "ipv4-addr" in ind:
            enrichment.append("The IPv4 address is likely part of malicious infrastructure used for hosting payloads.")
        elif "domain-name" in ind:
            enrichment.append("The domain may be used for phishing, fake updates, or malware distribution.")
        elif "SHA-256" in ind:
            enrichment.append("The SHA-256 hash corresponds to a malware sample, likely a downloader or payload.")
        elif "url:value" in ind:
            enrichment.append("The URL is serving a malicious executable, indicating active distribution.")
        elif "email-addr" in ind:
            enrichment.append("The email address is likely used in phishing or social engineering campaigns.")

    return enrichment

def validate_stix(stix_obj):
    required_fields = [
        "type", "spec_version", "id", "created",
        "modified", "pattern", "pattern_type",
        "valid_from", "confidence", "labels"
    ]

    missing = [field for field in required_fields if field not in stix_obj]

    if missing:
        return False, missing
    return True, []

def generate_flash_report(stix_obj, enrichment):
    created = stix_obj["created"]
    pattern = stix_obj["pattern"]

    enrichment_section = "\n".join([f"- {item}" for item in enrichment])

    report = f"""# Threat Intelligence Flash Report

**Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

---

## STIX Indicator Summary

**Created:** {created}  
**Pattern:** `{pattern}`

## Enrichment Analysis
{enrichment_section}
"""
    return report

def main():
    print("[*] Loading STIX data...")
    stix_data = load_stix()

    print("[*] Validating STIX schema...")
    is_valid, missing_fields = validate_stix(stix_data)
    
    if not is_valid:
        print(f"[!] Validation failed. Missing required fields: {missing_fields}")
        return

    print("[*] Enriching indicators...")
    enrichment = enrich_stix(stix_data)

    print("[*] Generating flash report...")
    report = generate_flash_report(stix_data, enrichment)

    with open(SUMMARY_PATH, "w") as f:
        f.write(report)

    print(f"[+] Flash report successfully written to {SUMMARY_PATH}")

if __name__ == "__main__":
    main()


 
