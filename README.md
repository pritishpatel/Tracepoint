# Tracepoint

Tracepoint is an AI-native SecOps platform for vulnerability triage, alert investigation, remediation tracking, and audit-ready evidence generation.

## Problem

Security teams receive noisy bug bounty reports, scanner findings, cloud alerts, endpoint alerts, and credential exposure signals. Manual triage is slow, inconsistent, repetitive, and difficult to audit.

## Solution

Tracepoint automates the first layer of SecOps triage using AI-assisted classification, duplicate detection, evidence extraction, enrichment, remediation workflow tracking, SLA monitoring, and audit-ready reporting.

Tracepoint is designed to support analysts, not replace them. It helps security teams move faster while preserving human review for high-impact decisions.

## Core Capabilities

- Vulnerability intake
- Bug bounty triage
- Duplicate detection
- CWE / OWASP mapping
- Reproduction step extraction
- Mock SIEM / cloud / EDR enrichment
- Remediation checklist generation
- SLA tracking
- Audit evidence generation
- CISA KEV import and prioritization
- Source provenance extraction
- AI guardrails for prompt injection and data leakage

## Human-in-the-Loop Principle

Tracepoint assists security analysts but does not autonomously close issues, change severity, mark duplicates, or execute containment actions.

High-impact decisions remain human-controlled.

## CISA KEV Import, Provenance, and Prioritization Workflow

Tracepoint supports importing records from the official CISA Known Exploited Vulnerabilities (KEV) catalog into the findings workflow.

This gives Tracepoint a realistic operational security workflow:

1. Pull exploited vulnerability records from CISA KEV.
2. Convert each KEV record into a Tracepoint finding.
3. Preserve original CISA source metadata inside the finding description.
4. Infer severity and category from vulnerability wording.
5. Preserve imported confidence values.
6. Expose parsed source provenance through the API.
7. Expose operational KEV prioritization through the API.

This turns raw public vulnerability intelligence into actionable security work items.

## Why this matters

Tracepoint is not just a CRUD-based finding tracker. The CISA KEV workflow shows that it can ingest real-world vulnerability intelligence, enrich it, preserve source provenance, expose structured evidence, and support prioritization decisions.

This is useful for:

- Security operations teams
- Vulnerability management
- Threat-informed remediation
- Compliance evidence
- Executive reporting
- Analyst workflows
- API-driven security automation

## Start from a clean local database

For local testing, remove the SQLite database and apply migrations:

```bash
rm -f tracepoint.db
alembic upgrade head