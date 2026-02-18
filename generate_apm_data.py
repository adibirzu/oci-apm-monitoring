#!/usr/bin/env python3
import sys
import os
import json
import random
import argparse
from datetime import datetime, timedelta, timezone

# Add current directory to path
sys.path.append(os.getcwd())

from config.shared_data import RICH_CAMPAIGNS, OCI_USERS, APP_PAGES
from generators.apm_trace_generator import TraceGenerator
from generators.browser_rum_generator import BrowserRumGenerator
from generators.oci_monitoring_generator import OciMonitoringGenerator
from generators.oci_audit_generator import OciAuditGenerator

class CampaignEngine:
    def __init__(self, output_dir, start_time, duration_days=7):
        self.output_dir = output_dir
        self.start_time = start_time
        self.end_time = start_time + timedelta(days=duration_days)
        self.trace_gen = TraceGenerator()
        self.rum_gen = BrowserRumGenerator()
        self.mon_gen = OciMonitoringGenerator()
        self.audit_gen = OciAuditGenerator()
        
    def run(self):
        all_traces = []
        all_rum = []
        all_rum_logs = []   # Rich logs for Logan "APM Browser RUM" source
        all_trace_logs = [] # Rich logs for Logan "APM Backend Traces" source
        all_metrics = []
        all_audit = []
        
        print(f"Generating 360° APM & Logan data from {self.start_time} to {self.end_time}...")
        
        # Helper to create rich logs for Log Analytics from an OTel trace/span object
        def log_from_otel(otel_obj, msg, log_list, level="INFO"):
            resource_attrs = {attr['key']: attr['value'] for attr in otel_obj['resource']['attributes']}
            span = otel_obj['scopeSpans'][0]['spans'][0]
            span_attrs = {attr['key']: attr['value'] for attr in span['attributes']}
            
            # Extract values from OTel 'value' dict (stringValue, intValue, etc)
            def get_val(v):
                if 'stringValue' in v: return v['stringValue']
                if 'intValue' in v: return int(v['intValue'])
                if 'doubleValue' in v: return float(v['doubleValue'])
                if 'boolValue' in v: return v['boolValue']
                return str(v)

            flat_attrs = {k: get_val(v) for k, v in span_attrs.items()}
            flat_res = {k: get_val(v) for k, v in resource_attrs.items()}
            
            log_entry = {
                "datetime": datetime.fromtimestamp(int(span['startTimeUnixNano']) / 1e9, tz=timezone.utc).isoformat(),
                "level": level,
                "message": msg,
                "traceId": span['traceId'],
                "spanId": span['spanId'],
                "parentSpanId": span.get('parentSpanId', ""),
                "operationName": span['name'],
                **flat_res,
                **flat_attrs
            }
            
            # Fix specific fields for Logan LQL compatibility
            if "http.status_code" in log_entry:
                log_entry["http_status_code"] = int(log_entry["http.status_code"])
            if "enduser.id" in log_entry:
                log_entry["enduser_id"] = log_entry["enduser.id"]
            
            log_list.append(log_entry)

        # 1. Process Campaigns (Threats)
        for campaign in RICH_CAMPAIGNS:
            print(f"  Processing Campaign: {campaign['name']}")
            user_tuple = campaign['oci_user']
            
            for phase in campaign['phases']:
                phase_start = self.start_time + timedelta(days=phase['day_start'])
                phase_end = self.start_time + timedelta(days=phase['day_end'])
                num_events = random.randint(10, 20)
                
                for _ in range(num_events):
                    ts = self._random_time(phase_start, phase_end)
                    if ts > self.end_time: continue
                    
                    trace_id = self.trace_gen.generate_hex_id(32)
                    is_threat = True
                    threat_details = {"threat_type": "CampaignActivity"}

                    # RUM
                    view_trace = self.rum_gen.generate_page_view_span(user_tuple, ts, trace_id, "/admin", is_threat)
                    all_rum.append(view_trace)
                    log_from_otel(view_trace, f"RUM View: /admin (Campaign: {campaign['name']})", all_rum_logs, "WARN")

                    # Trace
                    trace = self.trace_gen.generate_login_trace(user_tuple, ts, is_threat, threat_details)
                    trace['scopeSpans'][0]['spans'][0]['traceId'] = trace_id
                    trace['scopeSpans'][0]['spans'][0]['parentSpanId'] = view_trace['scopeSpans'][0]['spans'][0]['spanId']
                    all_traces.append(trace)
                    log_from_otel(trace, f"Security Alert: Campaign {campaign['name']} trace", all_trace_logs, "ERROR")

                    # Audit/Metrics
                    if phase['name'] == "brute_force":
                        all_audit.extend(self.audit_gen.generate_security_audit(user_tuple, ts, "45.33.32.156", "brute_force"))
                    all_metrics.extend(self.mon_gen.generate_system_metrics("auth-service", ts, is_high_load=True))

        # 1b. Process AppSec Threats (Web Attacks)
        print("  Processing AppSec Web Attacks...")
        for attack in ["SQL Injection", "XSS", "Command Injection", "LFI", "SSRF"]:
            for _ in range(random.randint(20, 40)):
                ts = self._random_time(self.start_time, self.end_time)
                user = random.choice(OCI_USERS)
                trace_id = self.trace_gen.generate_hex_id(32)
                
                view_trace = self.rum_gen.generate_page_view_span(user, ts, trace_id, "/vulnerable-page", True)
                all_rum.append(view_trace)
                log_from_otel(view_trace, f"Attacker RUM Activity: {attack}", all_rum_logs, "WARN")

                trace = self.trace_gen.generate_attack_trace(user, ts, attack)
                trace['scopeSpans'][0]['spans'][0]['traceId'] = trace_id
                trace['scopeSpans'][0]['spans'][0]['parentSpanId'] = view_trace['scopeSpans'][0]['spans'][0]['spanId']
                all_traces.append(trace)
                log_from_otel(trace, f"AppSec Threat Detected: {attack}", all_trace_logs, "ERROR")
                all_metrics.extend(self.mon_gen.generate_system_metrics("frontend", ts, is_high_load=True))

        # 1c. UX Degradation Scenarios (UC2: Digital User Experience)
        print("  Generating UX degradation scenarios...")
        ux_scenarios = ["slow_query", "error_500", "cascade_failure", "timeout",
                        "gc_pause", "intermittent_error", "bad_gateway"]
        for scenario in ux_scenarios:
            for _ in range(random.randint(15, 30)):
                ts = self._random_time(self.start_time, self.end_time)
                user = random.choice(OCI_USERS)

                # Backend trace
                trace = self.trace_gen.generate_ux_degradation_trace(user, ts, scenario)
                all_traces.append(trace)
                log_from_otel(trace, f"UX Degradation: {scenario}", all_trace_logs,
                              "ERROR" if "error" in scenario or scenario in ("cascade_failure", "timeout", "bad_gateway") else "WARN")

                # RUM span
                rum = self.rum_gen.generate_ux_degradation_rum(user, ts, scenario)
                all_rum.append(rum)
                log_from_otel(rum, f"RUM UX Degradation: {scenario}", all_rum_logs,
                              "ERROR" if "error" in scenario else "WARN")

                all_metrics.extend(self.mon_gen.generate_system_metrics("frontend", ts,
                                   is_high_load=scenario in ("slow_query", "cascade_failure", "timeout", "gc_pause")))

        # 2. Process Background Traffic (Normal Users)
        print(f"  Generating background traffic...")
        for user in OCI_USERS:
            for _ in range(random.randint(10, 20)):
                session_start = self._random_time(self.start_time, self.end_time)
                trace_id = self.trace_gen.generate_hex_id(32)
                
                view_trace = self.rum_gen.generate_page_view_span(user, session_start, trace_id, "/home")
                all_rum.append(view_trace)
                log_from_otel(view_trace, "User RUM: /home", all_rum_logs)

                trace = self.trace_gen.generate_login_trace(user, session_start)
                trace['scopeSpans'][0]['spans'][0]['traceId'] = trace_id
                trace['scopeSpans'][0]['spans'][0]['parentSpanId'] = view_trace['scopeSpans'][0]['spans'][0]['spanId']
                all_traces.append(trace)
                log_from_otel(trace, "User login success", all_trace_logs)
                
                curr_time = session_start
                for _ in range(random.randint(3, 10)):
                    curr_time += timedelta(seconds=random.randint(30, 120))
                    page = random.choice(APP_PAGES)
                    p_trace_id = self.trace_gen.generate_hex_id(32)
                    
                    p_view_trace = self.rum_gen.generate_page_view_span(user, curr_time, p_trace_id, page['path'])
                    all_rum.append(p_view_trace)
                    log_from_otel(p_view_trace, f"User RUM: {page['path']}", all_rum_logs)
                    
                    if "db" in page:
                        db_trace = self.trace_gen.generate_db_trace(user, curr_time, page['db'])
                        db_trace['scopeSpans'][0]['spans'][0]['traceId'] = p_trace_id
                        db_trace['scopeSpans'][0]['spans'][0]['parentSpanId'] = p_view_trace['scopeSpans'][0]['spans'][0]['spanId']
                        all_traces.append(db_trace)
                        log_from_otel(db_trace, f"DB Query executed for {page['path']}", all_trace_logs)
                
                all_metrics.extend(self.mon_gen.generate_system_metrics("frontend", session_start, False))

        # Sort all data
        all_rum.sort(key=lambda x: int(x['scopeSpans'][0]['spans'][0]['startTimeUnixNano']))
        all_rum_logs.sort(key=lambda x: x['datetime'])
        all_trace_logs.sort(key=lambda x: x['datetime'])
        all_metrics.sort(key=lambda x: x['datapoints'][0]['timestamp'])
        all_audit.sort(key=lambda x: x['data']['eventTime'])
        
        # Write outputs
        self._write_jsonl("apm_traces.jsonl", all_traces)
        self._write_jsonl("apm_rum.jsonl", all_rum)
        self._write_jsonl("logan_rum.json", all_rum_logs)
        self._write_jsonl("logan_traces.json", all_trace_logs)
        self._write_jsonl("oci_metrics.json", all_metrics)
        self._write_jsonl("oci_audit.json", all_audit)

    def _random_time(self, start, end):
        delta = end - start
        int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
        random_second = random.randrange(int_delta)
        return start + timedelta(seconds=random_second)

    def _write_jsonl(self, filename, data):
        filepath = os.path.join(self.output_dir, filename)
        print(f"  Writing {len(data)} records to {filepath}...")
        with open(filepath, 'w') as f:
            for entry in data:
                f.write(json.dumps(entry) + '\n')

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic 360° OCI O&M data")
    parser.add_argument("--output-dir", default="synthetic_apm_data", help="Output directory")
    parser.add_argument("--days", type=int, default=7, help="Number of days to generate")
    parser.add_argument("--scenario", choices=["all", "ux-degradation", "attacks", "normal"],
                        default="all", help="Scenario subset to generate")
    parser.add_argument("--upload", action="store_true", help="Upload data to OCI after generation")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    start_time = datetime.now(timezone.utc) - timedelta(days=args.days)
    engine = CampaignEngine(args.output_dir, start_time, args.days)
    engine.run()
    
    if args.upload:
        print("\nStarting 360° upload to OCI...")
        from uploader import APMUploader
        uploader = APMUploader()
        uploader.upload_otel_data(os.path.join(args.output_dir, "apm_traces.jsonl"), "Trace")
        uploader.upload_otel_data(os.path.join(args.output_dir, "apm_rum.jsonl"), "RUM")
        uploader.upload_app_logs(os.path.join(args.output_dir, "logan_rum.json"), "APM Browser RUM")
        uploader.upload_app_logs(os.path.join(args.output_dir, "logan_traces.json"), "APM Backend Traces")
        uploader.upload_oci_metrics(os.path.join(args.output_dir, "oci_metrics.json"))
    
    print("Done.")

if __name__ == "__main__":
    main()
