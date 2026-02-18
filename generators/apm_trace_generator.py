import json
import random
import time
import uuid
import datetime
from config.shared_data import OCI_USERS, THREAT_IPS, CORPORATE_IPS, SUSPICIOUS_USER_AGENTS, ATTACK_PAYLOADS

def generate_hex_id(length):
    return ''.join(random.choices('0123456789abcdef', k=length))

def get_current_time_nano(dt):
    return int(dt.timestamp() * 1e9)

class TraceGenerator:
    def __init__(self, service_name="frontend"):
        self.service_name = service_name
        self.resource_attributes = [
            {"key": "service.name", "value": {"stringValue": service_name}},
            {"key": "telemetry.sdk.language", "value": {"stringValue": "python"}},
            {"key": "cloud.provider", "value": {"stringValue": "oci"}},
            {"key": "WebApplicationName", "value": {"stringValue": "SevenKingdomsApp"}},
            {"key": "ApmrumWebAppName", "value": {"stringValue": "SevenKingdomsApp"}},
        ]

    def generate_hex_id(self, length):
        return ''.join(random.choices('0123456789abcdef', k=length))

    def _create_span(self, name, trace_id, parent_span_id, start_time, duration_ms, attributes):
        span_id = self.generate_hex_id(16)
        end_time = start_time + int(duration_ms * 1e6)
        
        # Mandatory for OCI visibility
        attributes["service.name"] = self.service_name
        attributes["WebApplicationName"] = "SevenKingdomsApp"

        otel_attributes = []
        for k, v in attributes.items():
            if v is None: continue
            val = {}
            if isinstance(v, bool):
                val = {"boolValue": v}
            elif isinstance(v, int):
                val = {"intValue": v}
            elif isinstance(v, float):
                val = {"doubleValue": v}
            else:
                val = {"stringValue": str(v)}
            otel_attributes.append({"key": k, "value": val})

        span = {
            "traceId": trace_id,
            "spanId": span_id,
            "name": name,
            "kind": 1, 
            "startTimeUnixNano": str(start_time),
            "endTimeUnixNano": str(end_time),
            "attributes": otel_attributes,
            "status": {"code": 1}
        }
        if parent_span_id:
            span["parentSpanId"] = parent_span_id
            
        return span

    def generate_attack_trace(self, user_tuple, timestamp, attack_type):
        trace_id = self.generate_hex_id(32)
        start_nano = get_current_time_nano(timestamp)
        user_id, user_email, _ = user_tuple
        payload = random.choice(ATTACK_PAYLOADS.get(attack_type, ["malicious_payload"]))
        ip = random.choice(THREAT_IPS)
        
        mitre_technique = "T1190" 
        if attack_type == "Command Injection": mitre_technique = "T1059.003"
        
        # Geolocation logic for Threat Map
        country = "Romania" if "89.34" in ip else "United States" if "20.53" in ip else "China" if "103.253" in ip else "Russia"
        city = "Bucharest" if country == "Romania" else "Ashburn" if country == "United States" else "Shanghai" if country == "China" else "Moscow"

        # Root Span
        root_attrs = {
            "http.method": "POST",
            "http.url": f"https://shop.sevenkingdoms.local/api/v1/data",
            "http.status_code": 200,
            "net.peer.ip": ip,
            "ClientIp": ip, # Explicitly set ClientIp
            "enduser.id": user_email,
            "ClientIpThreatConfidence": "High",
            "ClientIpThreatType": "SuspiciousIP",
            "GeoCountry": country,
            "GeoCity": city,
            "appsec.event": True,
            "appsec.threat.type": attack_type,
            "appsec.mitre.technique": mitre_technique,
        }
        
        root_span = self._create_span(f"POST /api/data", trace_id, None, start_nano, 400, root_attrs)
        root_span["kind"] = 2 # SERVER
        spans = [root_span]
        
        # DB Query (MSSQL)
        db_stmt = f"SELECT * FROM [sevenkingdoms].[dbo].[users] WHERE username = '{payload}'"
        db_span = self._create_span("MSSQL.Query", trace_id, root_span["spanId"], start_nano + 50*1000000, 200, {
            "db.system": "mssql",
            "db.statement": db_stmt,
            "DbStatement": db_stmt, # Explicitly for OCI
            "DbOracleSqlId": self.generate_hex_id(13),
            "db.name": "GOAD_DB",
            "server.address": "castelblack.sevenkingdoms.local",
            "server.ip": "192.168.56.22",
            "peer.service": "database-castelblack"
        })
        db_span["kind"] = 3
        spans.append(db_span)

        return {
            "resource": {"attributes": self.resource_attributes},
            "scopeSpans": [{"scope": {"name": "observability-demo"}, "spans": spans}]
        }

    def generate_login_trace(self, user_tuple, timestamp, is_threat=False, threat_details=None):
        trace_id = self.generate_hex_id(32)
        start_nano = get_current_time_nano(timestamp)
        user_id, user_email, _ = user_tuple
        ip = random.choice(THREAT_IPS if is_threat else CORPORATE_IPS)
        
        root_span = self._create_span("POST /login", trace_id, None, start_nano, 500, {
            "http.method": "POST",
            "net.peer.ip": ip,
            "ClientIp": ip,
            "enduser.id": user_email,
        })
        root_span["kind"] = 2
        
        auth_span = self._create_span("AuthService.LDAP_Auth", trace_id, root_span["spanId"], start_nano + 20*1000000, 150, {
            "server.address": "winterfell.sevenkingdoms.local",
            "server.ip": "192.168.56.11"
        })
        
        return {
            "resource": {"attributes": self.resource_attributes},
            "scopeSpans": [{"scope": {"name": "observability-demo"}, "spans": [root_span, auth_span]}]
        }

    def generate_ux_degradation_trace(self, user_tuple, timestamp, scenario):
        """Generate trace spans for UX degradation scenarios (UC2).

        Scenarios: slow_query, error_500, cascade_failure, timeout,
                   gc_pause, intermittent_error, bad_gateway
        """
        trace_id = self.generate_hex_id(32)
        start_nano = get_current_time_nano(timestamp)
        user_id, user_email, _ = user_tuple
        ip = random.choice(CORPORATE_IPS)

        spans = []

        if scenario == "slow_query":
            delay_ms = random.randint(5000, 30000)
            root = self._create_span("GET /app/slow-query", trace_id, None, start_nano, delay_ms, {
                "http.method": "GET",
                "http.url": "https://sevenkingdoms.local/app/slow-query",
                "http.status_code": 200,
                "enduser.id": user_email,
                "ClientIp": ip,
                "ux.scenario": "slow_query",
                "ux.degraded": True,
            })
            root["kind"] = 2
            spans.append(root)

            db_stmt = "SELECT * FROM kingdoms JOIN alliances ON k.id = a.kingdom_id WHERE ..."
            db_span = self._create_span("MSSQL.SlowQuery", trace_id, root["spanId"],
                                        start_nano + 50_000_000, delay_ms - 100, {
                "db.system": "mssql",
                "db.statement": db_stmt,
                "DbStatement": db_stmt,
                "server.address": "castelblack.sevenkingdoms.local",
                "ux.scenario": "slow_query",
            })
            db_span["kind"] = 3
            spans.append(db_span)

        elif scenario == "error_500":
            root = self._create_span("GET /app/error-page", trace_id, None, start_nano, 150, {
                "http.method": "GET",
                "http.url": "https://sevenkingdoms.local/app/error-page",
                "http.status_code": 500,
                "enduser.id": user_email,
                "ClientIp": ip,
                "ux.scenario": "error_500",
                "ux.degraded": True,
                "error": True,
                "error.message": "NullPointerException in UserService.getProfile",
            })
            root["kind"] = 2
            root["status"] = {"code": 2, "message": "Internal Server Error"}
            spans.append(root)

        elif scenario == "cascade_failure":
            root = self._create_span("GET /app/cascade-failure", trace_id, None, start_nano, 2000, {
                "http.method": "GET",
                "http.url": "https://sevenkingdoms.local/app/cascade-failure",
                "http.status_code": 503,
                "enduser.id": user_email,
                "ClientIp": ip,
                "ux.scenario": "cascade_failure",
                "ux.degraded": True,
                "error": True,
            })
            root["kind"] = 2
            root["status"] = {"code": 2, "message": "Service Unavailable"}
            spans.append(root)

            # Upstream call that failed
            upstream = self._create_span("payment-service.charge", trace_id, root["spanId"],
                                         start_nano + 100_000_000, 1800, {
                "http.method": "POST",
                "http.url": "http://payment-service:8080/charge",
                "http.status_code": 503,
                "error": True,
                "error.message": "Connection refused",
                "ux.scenario": "cascade_failure",
            })
            upstream["kind"] = 3
            upstream["status"] = {"code": 2}
            spans.append(upstream)

        elif scenario == "timeout":
            root = self._create_span("GET /app/timeout", trace_id, None, start_nano, 35000, {
                "http.method": "GET",
                "http.url": "https://sevenkingdoms.local/app/timeout",
                "http.status_code": 504,
                "enduser.id": user_email,
                "ClientIp": ip,
                "ux.scenario": "timeout",
                "ux.degraded": True,
                "error": True,
            })
            root["kind"] = 2
            root["status"] = {"code": 2, "message": "Gateway Timeout"}
            spans.append(root)

        elif scenario == "gc_pause":
            pause_ms = random.randint(500, 5000)
            root = self._create_span("GET /app/memory-pressure", trace_id, None, start_nano, pause_ms + 200, {
                "http.method": "GET",
                "http.url": "https://sevenkingdoms.local/app/memory-pressure",
                "http.status_code": 200,
                "enduser.id": user_email,
                "ClientIp": ip,
                "ux.scenario": "gc_pause",
                "ux.degraded": True,
                "ux.gc_pause_ms": pause_ms,
            })
            root["kind"] = 2
            spans.append(root)

        elif scenario == "intermittent_error":
            failed = random.random() < 0.5
            status = 500 if failed else 200
            root = self._create_span("GET /app/intermittent-error", trace_id, None, start_nano, 300, {
                "http.method": "GET",
                "http.url": "https://sevenkingdoms.local/app/intermittent-error",
                "http.status_code": status,
                "enduser.id": user_email,
                "ClientIp": ip,
                "ux.scenario": "intermittent_error",
                "ux.degraded": failed,
                "error": failed,
            })
            root["kind"] = 2
            if failed:
                root["status"] = {"code": 2, "message": "Connection reset"}
            spans.append(root)

        elif scenario == "bad_gateway":
            root = self._create_span("GET /app/bad-gateway", trace_id, None, start_nano, 500, {
                "http.method": "GET",
                "http.url": "https://sevenkingdoms.local/app/bad-gateway",
                "http.status_code": 502,
                "enduser.id": user_email,
                "ClientIp": ip,
                "ux.scenario": "bad_gateway",
                "ux.degraded": True,
                "error": True,
            })
            root["kind"] = 2
            root["status"] = {"code": 2, "message": "Bad Gateway"}
            spans.append(root)

        return {
            "resource": {"attributes": self.resource_attributes},
            "scopeSpans": [{"scope": {"name": "observability-demo"}, "spans": spans}]
        }

    def generate_db_trace(self, user_tuple, timestamp, db_node):
        trace_id = self.generate_hex_id(32)
        start_nano = get_current_time_nano(timestamp)
        user_id, user_email, _ = user_tuple
        
        db_ip = "192.168.56.12" if db_node == "meereen" else "192.168.56.22"
        
        root_span = self._create_span(f"GET /data/{db_node}", trace_id, None, start_nano, 600, {
            "http.url": f"https://app.sevenkingdoms.local/data/{db_node}",
            "enduser.id": user_email,
            "ClientIp": random.choice(CORPORATE_IPS)
        })
        root_span["kind"] = 2
        
        db_stmt = f"SELECT TOP 50 * FROM [GOAD].[dbo].[Financials] ORDER BY TransactionDate DESC"
        db_span = self._create_span("MSSQL.Execute", trace_id, root_span["spanId"], start_nano + 100*1000000, 400, {
            "db.system": "mssql",
            "db.statement": db_stmt,
            "DbStatement": db_stmt,
            "DbOracleSqlId": self.generate_hex_id(13),
            "server.ip": db_ip,
            "peer.service": f"database-{db_node}"
        })
        db_span["kind"] = 3
        
        return {
            "resource": {"attributes": self.resource_attributes},
            "scopeSpans": [{"scope": {"name": "observability-demo"}, "spans": [root_span, db_span]}]
        }
