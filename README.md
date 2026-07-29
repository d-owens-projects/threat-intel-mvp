## Threat Intel MVP – Automated STIX, Sigma, YARA & AI Flash Reporting Pipeline ##

A fully automated Threat Intelligence Processing Pipeline that ingests raw indicators, normalizes them into STIX 2.1, generates Sigma & YARA detections, enriches the intel using an AI‑assisted workflow, and produces a clean Markdown Flash Report — all executed through a single command.

## FEATURES ##

STIX 2.1 Normalization: Raw indicators (IP, domain, hash, URL, email) are converted into a valid STIX Indicator object with
1. Pattern
2. Pattern_type
3. valid_from
4. confidence
5. labels
6. timestamps and UUIDs

## Sigma Rule Generation ##

Automatically builds a Sigma rule mapping indicators to log fields
1. DestinationIp
2. QueryName
3. Url
4. Sender Address
5. File Hash

## YARA Rule Geneartion ##

Creates a Yara rule with conditions based on
1. IP addresses
2. Domains
3. URLs
4. SHA-256 hashes
5. Email addresses

## AI-Assited Flash Report ##

Generates a Markdown report summarizing
1. STIX indicator contents
2. Enrichment analysis
3. Confidence level
4. Labels
5. Human-readable context

## End-to-End Pipeline Execution ##

Run the entire workflow with one command:python run_pipeline.py

## Project Structure ##

threat-intel-mvp/
│
├── pipeline/
│   ├── normalize.py
│   ├── generate_detections.py
│   ├── model_workflow.py
│   └── run_pipeline.py
│
├── feed/
│   ├── indicators_raw.json
│   └── stix.json
│
├── detections/
│   ├── sigma.yml
│   └── yara.yar
│
└── summary.md

## How it Works ##

1. Normalize Raw Indicators->STIX: python pipeline/normalize.py
2. Generate Sigma + YARA: python pipeline/generate_detections.py
3. Generate AI Flash Report: python pipeline/model_workflow.py
4. Run everything: python pipeline/run_pipeline.py

## AI Enrichment Logic ##

The enrichment engine adds human-readable context such as
1. IP used for malicious infrastructure
2. Domain used for phising or fake updates
3. Hash tied to malware payload
4. URL distributing malicious executables
5. Email used in phishing campaigns

## Example Output ##

# Threat Intelligence Flash Report

Generated: 2026-07-29 19:22:29 UTC

## STIX Indicator Summary
Created: 2026-07-29T18:13:08Z
Pattern: [ipv4-addr:value = '185.244.25.123'] OR ...

## Enrichment Analysis
- The IPv4 address is likely part of malicious infrastructure.
- The domain may be used for phishing or malware distribution.
- The SHA-256 hash corresponds to a malware payload.
- The URL is serving a malicious executable.
- The email address is likely used in phishing campaigns.

## Skills Demonstrated ##

Threat Intelligence Engineering

STIX 2.1 Data Modeling

Detection Engineering (Sigma + YARA)

Python Automation

AI‑Assisted Enrichment Workflows

SOC Pipeline Design

Markdown Reporting

GitHub Project Structuring

## Future Enhancements ##

Threat actor correlation

MITRE ATT&CK tagging

Flask dashboard UI

Multi‑feed ingestion (MISP, OpenCTI, AbuseIPDB)

Export to Splunk, Sentinel, Elastic

## Author ##

Denarius-SOC Automation & THreat Intelligence Engineer

   
