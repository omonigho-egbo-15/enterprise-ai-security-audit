# enterprise-ai-security-audit
# Enterprise AI Security Audit Dossier & Governance Telemetry Gateway

[![CI/CD Verification](https://github.com/omonigho-egbo-15/enterprise-ai-security-audit/actions/workflows/lint.yml/badge.svg)](https://github.com/omonigho-egbo-15/enterprise-ai-security-audit/actions/workflows/lint.yml)
[![Compliance: Texas TRAIGA](https://img.shields.io/badge/Compliance-Texas_TRAIGA-blue.svg)](https://capitol.texas.gov/)
[![Compliance: EU AI Act](https://img.shields.io/badge/Compliance-EU_AI_Act_2024%2F1689-indigo.svg)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
[![Security Standard: NIST AI 100-2](https://img.shields.io/badge/Standard-NIST_AI_100--2_E2025-green.svg)](https://csrc.nist.gov/publications/detail/sp/100-2/final)

## Executive Summary
This repository houses the formal Enterprise AI Security Audit Dossier and Automated Control Telemetry Gateway for multi-agent enterprise workloads. As AI systems integrate into high-consequence enterprise operations, organizations face binding regulatory mandates under the **Texas Responsible Artificial Intelligence Governance Act (TRAIGA)**, the **EU Artificial Intelligence Act (Regulation (EU) 2024/1689)**, and the **NIST AI Risk Management Framework (AI RMF 1.0 / NIST AI 100-2)**.

This project delivers an auditable, machine-readable inventory (`ai_bom.json`), CI/CD gate automation (`lint.yml`), empirical red-team validation demonstrating **≥85% adversarial threat blockage**, and a 10-slide executive and technical audit presentation.

---

## Architecture Overview
The multi-agent architecture deploys dual defensive control gates upstream and downstream of foundation models to intercept adversarial attacks without degrading production latency or availability SLAs.
