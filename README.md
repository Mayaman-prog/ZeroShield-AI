# ZeroShield AI

ZeroShield AI is a lightweight explainable hybrid network intrusion-detection
research prototype developed for the 6CS007 Project and Professionalism module.

## Research Question

To what extent can a lightweight explainable hybrid intrusion-detection
framework distinguish known threats from previously unseen network threat
behaviour while controlling false positives and supporting human-approved
temporary containment?

## Core Architecture

ZeroShield combines:

- Suricata for signature-based known-threat detection
- XGBoost for supervised known-threat classification
- Isolation Forest for novelty detection
- Evidence correlation with detector provenance
- SHAP and anomaly evidence for explainability
- MITRE ATT&CK contextual enrichment where appropriate
- Human-approved temporary containment
- Audit logging and rollback
- Analyst dashboard

## Project Status

Current Phase: Research and Initial Design

## Repository Structure

- `docs/` — research, design and project documentation
- `data/` — dataset preparation locations
- `src/` — ZeroShield detection and response components
- `experiments/` — experimental evaluation
- `models/` — trained model artefacts
- `configs/` — project configuration
- `tests/` — unit, integration and security testing
- `frontend/` — analyst dashboard
- `backend/` — backend/API services
- `notebooks/` — exploratory research notebooks
- `scripts/` — supporting scripts

## Safety and Ethics

ZeroShield is an academic defensive cybersecurity research prototype.

All practical testing is restricted to authorised datasets and isolated
laboratory environments. The project is not intended for unauthorised
testing of third-party systems or production networks.

Potentially disruptive containment actions require human approval and are
designed to be temporary, logged and reversible.

## Branch Strategy

`main` — stable project versions

`develop` — ongoing integrated development

`feature/*` — individual features and experiments