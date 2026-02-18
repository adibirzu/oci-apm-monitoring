"""
Enhanced shared data structures with GOAD topology and CSP Region mapping.
"""

import datetime

# -- GOAD Network Topology --
# Based on adibirzu/GOADv3
GOAD_NETWORKS = {
    "sevenkingdoms.local": {
        "winterfell": {"ip": "192.168.56.11", "role": "DC01"},
        "kingslanding": {"ip": "192.168.56.10", "role": "DC02"},
        "castelblack": {"ip": "192.168.56.22", "role": "SRV02", "services": ["MSSQL", "IIS"]},
    },
    "north.sevenkingdoms.local": {
        "meereen": {"ip": "192.168.56.12", "role": "SRV03", "services": ["MSSQL", "ADCS"]},
    },
    "essos.local": {
        "braavos": {"ip": "192.168.56.23", "role": "DC03"},
    }
}

# -- CSP Regions to Geo Mapping --
# Used to drive "Real User Data Metrics" map
CSP_REGION_MAP = {
    "oci-eu-frankfurt-1": {"country": "Germany", "city": "Frankfurt", "lat": 50.11, "lon": 8.68, "ip_prefix": "130.61."},
    "oci-us-ashburn-1": {"country": "United States", "city": "Ashburn", "lat": 39.04, "lon": -77.48, "ip_prefix": "129.213."},
    "aws-us-east-1": {"country": "United States", "city": "N. Virginia", "lat": 38.13, "lon": -78.45, "ip_prefix": "54.239."},
    "azure-westeurope": {"country": "Netherlands", "city": "Amsterdam", "lat": 52.36, "lon": 4.90, "ip_prefix": "52.208."},
    "gcp-asia-east1": {"country": "Taiwan", "city": "Changhua", "lat": 24.05, "lon": 120.51, "ip_prefix": "104.199."},
}

# -- Identities (Correlated with GOAD) --
OCI_USERS = [
    ("ocid1.user.oc1..aaa1", "cersei.lannister@sevenkingdoms.local", "natv"),
    ("ocid1.user.oc1..aaa2", "tywin.lannister@sevenkingdoms.local", "natv"),
    ("ocid1.user.oc1..aaa3", "jaime.lannister@sevenkingdoms.local", "natv"),
    ("ocid1.user.oc1..aaa4", "eddard.stark@north.sevenkingdoms.local", "federation"),
    ("ocid1.user.oc1..aaa5", "arya.stark@north.sevenkingdoms.local", "federation"),
    ("ocid1.user.oc1..aaa6", "jon.snow@north.sevenkingdoms.local", "natv"),
    ("ocid1.user.oc1..aaa7", "daenerys.targaryen@essos.local", "natv"),
]

# -- OCI Infrastructure Metadata --
OCI_METADATA = {
    "tenancy_id": "ocid1.tenancy.oc1..aaaaaaaademo",
    "compartment_id": "ocid1.compartment.oc1..aaaaaaaademo",
    "services": {
        "frontend": {
            "ocid": "ocid1.instance.oc1.eu-frankfurt-1.frontend",
            "metrics_namespace": "oci_computeagent"
        },
        "auth-service": {
            "ocid": "ocid1.fn.oc1.eu-frankfurt-1.auth",
            "metrics_namespace": "oci_functions"
        }
    }
}

# -- Expanded App Pages & Use Cases --
APP_PAGES = [
    {"path": "/home", "use_case": "General Browsing"},
    {"path": "/login", "use_case": "Authentication"},
    {"path": "/profile", "use_case": "User Management"},
    {"path": "/inventory", "use_case": "Database Query", "db": "castelblack"},
    {"path": "/finance", "use_case": "Secure Transaction", "db": "meereen"},
    {"path": "/orders", "use_case": "Order History", "db": "castelblack"},
    {"path": "/search", "use_case": "Search Engine"},
]

# -- AppSec Attack Payloads --
ATTACK_PAYLOADS = {
    "SQL Injection": ["' OR '1'='1", "admin' --", "UNION SELECT 1, @@version --"],
    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "Command Injection": ["; cat /etc/passwd", "| whoami", "& ping 127.0.0.1"],
}

SUSPICIOUS_USER_AGENTS = [
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)",
    "Java/1.8.0_201",
    "python-requests/2.28.0",
    "curl/7.68.0",
    "Wget/1.21",
    "PowerShell/7.3",
]

THREAT_IPS = [
    "45.33.32.156", "185.220.101.1", "91.92.109.18", "194.5.249.7", "23.129.64.100", "80.66.88.37"
]

CORPORATE_IPS = [
    "130.61.142.234", "20.53.203.50", "54.239.26.128", "104.244.42.1"
]

RICH_CAMPAIGNS = [
    {
        "name": "Operation Crown",
        "oci_user": ("ocid1.user.oc1..aaa1", "cersei.lannister@sevenkingdoms.local", "natv"),
        "phases": [
            {"name": "brute_force", "day_start": 0, "day_end": 0.2, "targets": ["trace", "browser"]},
            {"name": "lateral_movement", "day_start": 0.2, "day_end": 0.5, "targets": ["trace"]},
        ],
    },
    {
        "name": "The Spiders Web",
        "oci_user": ("ocid1.user.oc1..aaa_lf", "petyer.baelish@sevenkingdoms.local", "natv"),
        "phases": [
            {"name": "recon", "day_start": 1, "day_end": 1.5, "targets": ["trace", "browser"]},
            {"name": "exfiltration", "day_start": 1.5, "day_end": 2.0, "targets": ["trace"]},
        ],
    }
]
