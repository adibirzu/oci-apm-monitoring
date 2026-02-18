# OCI Observability & Management: 360° Threat Visibility Demo

This project demonstrates a comprehensive, full-stack observability and security monitoring solution using Oracle Cloud Infrastructure (OCI). It showcases the power of correlating data across **Application Performance Monitoring (APM)**, **Log Analytics**, and **Real User Monitoring (RUM)** to detect, analyze, and visualize advanced persistent threats (APTs).

## 🎯 Project Goal
To provide a "single pane of glass" for Security Operations and DevOps teams, enabling them to:
1.  **Detect** sophisticated web attacks (SQLi, XSS, Command Injection).
2.  **Visualize** attack campaigns using **MITRE ATT&CK** mapping.
3.  **Trace** the full kill chain from a user's browser session (RUM) down to the database query and system logs.
4.  **Correlate** signals across distributed services using OpenTelemetry standards.

## 📈 Current Status (Updated Feb 11, 2026)

The project has reached a high level of fidelity for OCI APM and Log Analytics correlation:

1.  **Full RUM-Trace Correlation**:
    *   **Unified OTLP Format**: Both browser (RUM) and server (Trace) data are now emitted as standard OTel `ResourceSpans`.
    *   **Session Linking**: Every transaction is unified by a shared `SessionId` and `traceId`, enabling the "User Session -> Frontend -> Backend -> DB" drilldown.
    *   **Trace Stitching**: Backend traces are now explicit children of RUM spans (`parentSpanId` linkage), fixing "Incomplete" trace issues.

2.  **Web App Visibility**:
    *   Added mandatory attributes (`WebApplicationName`, `PageViews`, `ApdexScore`) to all spans to ensure they populate the **Web apps** tab in Trace Explorer and the **RUM Overview** dashboard.
    *   Standardized on `SevenKingdomsApp` as the application name.

3.  **Threat Intelligence & MITRE**:
    *   Simulated attacks are tagged with **MITRE ATT&CK techniques** (T1190, T1059.003).
    *   Enriched with geospatial metadata (Country, City, Region) to drive the **Threat Sources** map.

4.  **Log Analytics Sync**:
    *   `app_logs.json` is generated with `traceId` and `spanId` fields.
    *   When uploaded to OCI Log Analytics, these logs are automatically correlated with APM traces, allowing you to pivot from a slow/malicious trace directly to the underlying application logs.

## 🛡️ MITRE ATT&CK Visualization

This demo maps detected threats to standard MITRE techniques, allowing you to use the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize your coverage.

| Attack Vector | MITRE Technique | Description |
| :--- | :--- | :--- |
| **SQL Injection** | **[T1190](https://attack.mitre.org/techniques/T1190/)** | Exploit Public-Facing Application |
| **Command Injection** | **[T1059.003](https://attack.mitre.org/techniques/T1059/003/)** | Command and Scripting Interpreter: Windows Command Shell |
| **XSS / SSRF** | **T1190** | Exploit Public-Facing Application |

## 📊 Dashboards & Drilldowns

### 1. Real User Monitoring (RUM) Overview
*   **Purpose**: Monitor user experience and global traffic patterns.
*   **Key Widgets**:
    *   *World Map*: Visualizes traffic sources.
    *   *Apdex Score*: Tracks user satisfaction.
    *   *Session Breakdown*: Correlates users with session performance.

### 2. Threat Activity Monitoring
*   **Purpose**: Security Command Center for AppSec.
*   **Key Features**:
    *   **Threat Sources Map**: Pinpoints attacking IPs.
    *   **MITRE Breakdown**: Filters by attack technique.

### 3. Log Analytics Drilldown
*   From any APM Span, use the context menu to **"View Logs"**.
*   Requires Log Analytics configured with the `Observability_Demo_App_Logs` source.

## 🚀 Deployment

The entire synthetic data generation engine is packaged as an **OCI Function**, capable of running on a schedule to keep your demo environment alive with fresh, relevant data.

### Prerequisites
*   OCI Tenancy with APM Domain and Log Analytics enabled.
*   **Private Data Key** for OpenTelemetry ingestion.
*   **Log Analytics Namespace** and Log Group OCID.

### Configuration (`.env.local`)
```bash
OCI_APM_ENDPOINT=https://<your-apm-endpoint>
OCI_APM_PRIVATE_DATAKEY=<your-private-key>
LOG_ANALYTICS_NAMESPACE=<your-namespace>
LOG_ANALYTICS_LOG_GROUP_ID=<your-log-group-ocid>
```

### Running the Generator
```bash
# Generate 1 day of data and upload immediately
python3 generate_apm_data.py --days 1 --upload
```

---
*Built with OCI Observability & Management.*
