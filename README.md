# Automated Pentesting Platform – System Files Submission

This repository contains the system implementation files for an **Automated Application Pentesting Platform** developed as part of **Capstone Project 2 (CP2)**.

The contents of this repository serve as **supporting technical evidence** for the final report and document how automated **Static Application Security Testing (SAST)**, **Software Composition Analysis (SCA)**, and **Dynamic Application Security Testing (DAST)** were implemented, executed, and evaluated.

---

## Repository Overview

The repository is structured to reflect the **automated pentesting workflow** described in the project methodology and evaluation chapters.

### Directory and File Structure

- SAST execution scripts and test cases  
- SCA analysis and vulnerability validation artifacts  
- DAST scan outputs and comparison results  
- Reporting and automation scripts  

Each component directly maps to a specific phase of the automated pentesting pipeline.

---

## Pentesting Pipeline Overview

The implemented system follows a staged automated security validation flow:

Target Application / Source Code
↓
Static Application Security Testing (SAST)
↓
Software Composition Analysis (SCA)
↓
Dynamic Application Security Testing (DAST)
↓
Result Processing and Report Generation


Each stage is executed programmatically using Python scripts to simulate a CI/CD-style security pipeline.

---

## Component Descriptions

### Static Application Security Testing (SAST)

This component performs automated static analysis on HTML and application files to detect insecure coding patterns without executing the application.

Covered checks include:
- Insecure form handling
- Missing input validation
- Unsafe HTML constructs

**Relevant files:**
- `run_enhanced_sast_on_html.py`
- `vulnerable_test_cases.html`
- `sast_enhanced_report.json`

These files support the **SAST implementation and results** section of the report.

---

### Software Composition Analysis (SCA)

This component evaluates third-party dependencies to identify known vulnerabilities associated with external libraries.

The analysis simulates real-world dependency risk assessment by validating findings against vulnerability references.

Artifacts in this section demonstrate:
- Dependency risk identification
- Vulnerability validation logic
- Result normalization for reporting

This supports the **SCA methodology and evaluation** chapter.

---

### Dynamic Application Security Testing (DAST)

This component performs dynamic security testing against a running web application to identify runtime vulnerabilities.

It includes:
- Local active scanning
- Baseline versus active scan comparison
- Runtime behavior analysis

DAST artifacts demonstrate how vulnerabilities can only be detected during execution, complementing SAST and SCA findings.

---

### Reporting and Automation

This component consolidates results from all pentesting stages and converts them into human-readable formats.

Automation features include:
- JSON result processing
- PDF report generation
- Email-based report distribution

**Relevant files:**
- `convert_json_to_pdf.py`
- `email_pdf.py`

This supports the **automation and reporting** section of the project.

---

## Scope and Purpose

This repository is intended for:
- Academic assessment and demonstration
- Validation of automated pentesting workflows
- Technical reference during project presentation and evaluation

It is **not intended to replace enterprise-grade commercial pentesting tools**.

---

## Author

**See Ming Hau**  
Capstone Project 2 (CP2)  
Automated Application Pentesting
