import json
import uuid
from datetime import datetime, timezone

# Paths
RAW_PATH = "../feed/indicators_raw.json"
STIX_PATH = "../feed/stix.json"

def load_raw_indicators():
    with open(RAW_PATH, "r") as f:
        data = json.load(f)
    return data["indicators"]

def build_stix_indicator(indicators):
    # Build STIX pattern string
    pattern_parts = []

    for item in indicators:
        if item["type"] == "ipv4":
            pattern_parts.append(f"[ipv4-addr:value = '{item['value']}']")
        elif item["type"] == "domain":
            pattern_parts.append(f"[domain-name:value = '{item['value']}']")
        elif item["type"] == "sha256":
            pattern_parts.append(
                f"[file:hashes.'SHA-256' = '{item['value']}']"
            )
        elif item["type"] == "url":
            pattern_parts.append(f"[url:value = '{item['value']}']")
        elif item["type"] == "email":
            pattern_parts.append(f"[email-addr:value = '{item['value']}']")

    pattern = " OR ".join(pattern_parts)

    # Windows-compatible timezone-aware UTC timestamp
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    stix_indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "confidence": 75,
        "labels": ["malware", "infrastructure", "osint"]
    }

    return stix_indicator

def save_stix(stix_obj):
    with open(STIX_PATH, "w") as f:
        json.dump(stix_obj, f, indent=4)

def main():
    indicators = load_raw_indicators()
    stix_obj = build_stix_indicator(indicators)
    save_stix(stix_obj)
    print("STIX indicator created successfully.")

if __name__ == "__main__":
    main()




