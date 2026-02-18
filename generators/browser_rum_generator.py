import json
import random
import uuid
import datetime
from config.shared_data import OCI_USERS, THREAT_IPS, CORPORATE_IPS, CSP_REGION_MAP

def generate_hex_id(length):
    return ''.join(random.choices('0123456789abcdef', k=length))

class BrowserRumGenerator:
    def __init__(self, app_name="SevenKingdomsApp"):
        self.app_name = app_name
        self.resource_attributes = [
            {"key": "service.name", "value": {"stringValue": "APM Browser"}},
            {"key": "telemetry.sdk.language", "value": {"stringValue": "js"}},
            {"key": "cloud.provider", "value": {"stringValue": "oci"}},
            {"key": "WebApplicationName", "value": {"stringValue": app_name}},
            {"key": "ApmrumWebAppName", "value": {"stringValue": app_name}},
        ]

    def generate_session_id(self):
        return str(uuid.uuid4())

    def _create_rum_span(self, name, trace_id, parent_span_id, start_nano, duration_ms, attributes):
        span_id = generate_hex_id(16)
        end_nano = start_nano + (duration_ms * 1000000)
        
        # Standard OCI RUM Attributes
        attributes["service.name"] = "APM Browser"
        attributes["WebApplicationName"] = self.app_name
        attributes["ApmrumWebAppName"] = self.app_name

        otel_attributes = []
        for k, v in attributes.items():
            if v is None: continue
            val = {}
            if isinstance(v, bool): val = {"boolValue": v}
            elif isinstance(v, int): val = {"intValue": v}
            elif isinstance(v, float): val = {"doubleValue": v}
            else: val = {"stringValue": str(v)}
            otel_attributes.append({"key": k, "value": val})

        span = {
            "traceId": trace_id,
            "spanId": span_id,
            "name": name,
            "kind": 3, # CLIENT
            "startTimeUnixNano": str(start_nano),
            "endTimeUnixNano": str(end_nano),
            "attributes": otel_attributes,
            "status": {"code": 1}
        }
        if parent_span_id:
            span["parentSpanId"] = parent_span_id
        return span

    def generate_page_view_span(self, user_tuple, timestamp, trace_id, page_name, is_threat=False):
        user_id, user_email, _ = user_tuple
        csp_region = random.choice(list(CSP_REGION_MAP.keys()))
        geo = CSP_REGION_MAP[csp_region]
        ip = geo['ip_prefix'] + str(random.randint(1, 254))
        if is_threat: ip = random.choice(THREAT_IPS)

        start_nano = int(timestamp.timestamp() * 1e9)
        load_time_ms = int(random.lognormvariate(7.2, 0.6)) 
        load_time_ms = max(400, min(load_time_ms, 12000))
        
        attrs = {
            "ApmrumType": "Page",
            "ApmrumPageUpdateType": "Page Load",
            "PageViews": 1,
            "ApdexScore": 1.0 if load_time_ms < 1500 else 0.5 if load_time_ms < 4000 else 0.0,
            "PageLoadTime": load_time_ms,
            "ApmrumUrl": f"https://sevenkingdoms.local{page_name}",
            "http.url": f"https://sevenkingdoms.local{page_name}",
            "enduser.id": user_email,
            "net.peer.ip": ip,
            "ClientIp": ip, # Explicitly for OCI
            "GeoCountry": geo['country'],
            "GeoCity": geo['city'],
            "ApmrumCountry": geo['country'],
            "ApmrumCity": geo['city'],
            "ApmrumRegion": csp_region,
            "UserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "ApmrumBrowser": "Chrome",
            "ApmrumOs": "macOS"
        }
        
        if is_threat:
             attrs["ClientIpThreatConfidence"] = "High"
             attrs["ClientIpThreatType"] = "SuspiciousIP"
             attrs["appsec.event"] = True

        return {
            "resource": {"attributes": self.resource_attributes},
            "scopeSpans": [{"scope": {"name": "observability-demo-rum"}, "spans": [
                self._create_rum_span(f"Page Load: {page_name}", trace_id, None, start_nano, load_time_ms, attrs)
            ]}]
        }

    def generate_ux_degradation_rum(self, user_tuple, timestamp, scenario):
        """Generate RUM spans for UX degradation scenarios (UC2).

        Produces degraded Core Web Vitals: high LCP, FID, CLS values.
        """
        user_id, user_email, _ = user_tuple
        trace_id = generate_hex_id(32)
        csp_region = random.choice(list(CSP_REGION_MAP.keys()))
        geo = CSP_REGION_MAP[csp_region]
        ip = geo['ip_prefix'] + str(random.randint(1, 254))
        start_nano = int(timestamp.timestamp() * 1e9)

        # Degraded Web Vitals by scenario
        vitals = {
            "slow_query":         {"lcp": random.randint(8000, 30000), "fid": random.randint(100, 500),  "cls": round(random.uniform(0.0, 0.1), 3)},
            "error_500":          {"lcp": random.randint(1000, 3000),  "fid": random.randint(50, 200),   "cls": round(random.uniform(0.0, 0.05), 3)},
            "cascade_failure":    {"lcp": random.randint(4000, 15000), "fid": random.randint(200, 800),  "cls": round(random.uniform(0.1, 0.5), 3)},
            "hard_load":          {"lcp": random.randint(8000, 20000), "fid": random.randint(300, 1000), "cls": round(random.uniform(0.2, 0.8), 3)},
            "timeout":            {"lcp": 0,                          "fid": 0,                         "cls": 0},
            "gc_pause":           {"lcp": random.randint(3000, 8000),  "fid": random.randint(500, 5000), "cls": round(random.uniform(0.05, 0.3), 3)},
            "intermittent_error": {"lcp": random.randint(1000, 4000),  "fid": random.randint(50, 300),   "cls": round(random.uniform(0.0, 0.1), 3)},
            "bad_gateway":        {"lcp": random.randint(2000, 6000),  "fid": random.randint(100, 400),  "cls": round(random.uniform(0.0, 0.15), 3)},
        }

        v = vitals.get(scenario, vitals["error_500"])
        load_time_ms = v["lcp"] if v["lcp"] > 0 else random.randint(30000, 60000)

        # Apdex: satisfied < 2s, tolerating < 8s
        apdex = 1.0 if load_time_ms < 2000 else 0.5 if load_time_ms < 8000 else 0.0

        attrs = {
            "ApmrumType": "Page",
            "ApmrumPageUpdateType": "Page Load",
            "PageViews": 1,
            "ApdexScore": apdex,
            "PageLoadTime": load_time_ms,
            "LargestContentfulPaint": v["lcp"],
            "FirstInputDelay": v["fid"],
            "CumulativeLayoutShift": v["cls"],
            "TimeToFirstByte": random.randint(100, min(load_time_ms, 2000)),
            "ApmrumUrl": f"https://sevenkingdoms.local/app/{scenario.replace('_', '-')}",
            "http.url": f"https://sevenkingdoms.local/app/{scenario.replace('_', '-')}",
            "enduser.id": user_email,
            "net.peer.ip": ip,
            "ClientIp": ip,
            "GeoCountry": geo['country'],
            "GeoCity": geo['city'],
            "ApmrumCountry": geo['country'],
            "ApmrumCity": geo['city'],
            "ApmrumRegion": csp_region,
            "UserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "ApmrumBrowser": "Chrome",
            "ApmrumOs": "macOS",
            "ux.scenario": scenario,
            "ux.degraded": True,
        }

        page_span = self._create_rum_span(
            f"Page Load: /app/{scenario.replace('_', '-')}",
            trace_id, None, start_nano, load_time_ms, attrs,
        )

        return {
            "resource": {"attributes": self.resource_attributes},
            "scopeSpans": [{"scope": {"name": "observability-demo-rum"}, "spans": [page_span]}],
        }

    def generate_ajax_span(self, user_tuple, timestamp, trace_id, parent_span_id, page_name, target_url, is_threat=False):
        user_id, user_email, _ = user_tuple
        start_nano = int(timestamp.timestamp() * 1e9)
        resp_time_ms = random.randint(50, 800)
        
        attrs = {
            "ApmrumType": "AJAX call",
            "AjaxResponseTime": resp_time_ms,
            "http.url": target_url,
            "http.method": "POST" if "api" in target_url else "GET",
            "http.status_code": 200 if not is_threat else 403,
            "enduser.id": user_email,
            "ClientIp": random.choice(CORPORATE_IPS)
        }
        
        return {
            "resource": {"attributes": self.resource_attributes},
            "scopeSpans": [{"scope": {"name": "observability-demo-rum"}, "spans": [
                self._create_rum_span(f"AJAX: {target_url}", trace_id, parent_span_id, start_nano, resp_time_ms, attrs)
            ]}]
        }
