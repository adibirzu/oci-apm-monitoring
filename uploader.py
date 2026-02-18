#!/usr/bin/env python3
import os
import json
import requests
import argparse
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load configuration from .env.local
load_dotenv(".env.local")

ENDPOINT = os.getenv("OCI_APM_ENDPOINT")
PRIVATE_KEY = os.getenv("OCI_APM_PRIVATE_DATAKEY")

# OCI APM Private OTel Trace Path
OTEL_PATH = "/20200101/opentelemetry/private/v1/traces"

class APMUploader:
    def __init__(self):
        self.session = requests.Session()

    def upload_otel_data(self, file_path, data_type="Trace"):
        url = f"{ENDPOINT.rstrip('/')}{OTEL_PATH}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"dataKey {PRIVATE_KEY}"
        }
        print(f"Uploading {data_type} OTel data from {file_path} to {url}...")
        count = 0
        with open(file_path, 'r') as f:
            for line in f:
                payload = json.loads(line)
                if "resourceSpans" not in payload:
                    payload = {"resourceSpans": [payload]}
                try:
                    response = self.session.post(url, json=payload, headers=headers)
                    if response.status_code in (200, 202):
                        count += 1
                except: pass
                if count % 100 == 0 and count > 0:
                    print(f"  Uploaded {count} records...")
        print(f"Successfully uploaded {count} {data_type} records.")

    def upload_oci_metrics(self, file_path):
        import oci
        from oci.monitoring.models import PostMetricDataDetails, MetricDataDetails, Datapoint
        try:
            config = oci.config.from_file()
        except:
            print("  OCI Config not found, skipping Monitoring.")
            return
        
        client = oci.monitoring.MonitoringClient(config, service_endpoint="https://telemetry-ingestion.eu-frankfurt-1.oraclecloud.com")
        print(f"Uploading OCI metrics from {file_path}...")
        
        metrics_batch = []
        with open(file_path, 'r') as f:
            for line in f:
                raw = json.loads(line)
                namespace = raw['namespace']
                dp = Datapoint(
                    timestamp=datetime.fromisoformat(raw['datapoints'][0]['timestamp'].rstrip('Z')).replace(tzinfo=timezone.utc),
                    value=raw['datapoints'][0]['value'],
                    count=1
                )
                md = MetricDataDetails(
                    namespace=namespace,
                    compartment_id=raw['compartmentId'],
                    name=raw['name'],
                    dimensions=raw['dimensions'],
                    datapoints=[dp]
                )
                metrics_batch.append(md)
                if len(metrics_batch) >= 50:
                    try:
                        client.post_metric_data(post_metric_data_details=PostMetricDataDetails(metric_data=metrics_batch))
                    except: pass
                    metrics_batch = []
        if metrics_batch:
            try: client.post_metric_data(post_metric_data_details=PostMetricDataDetails(metric_data=metrics_batch))
            except: pass
        print("Successfully uploaded OCI metrics.")

    def upload_app_logs(self, file_path, source_name="Observability_Demo_App_Logs"):
        import oci
        try:
            config = oci.config.from_file()
        except: return
        namespace = os.getenv("LOG_ANALYTICS_NAMESPACE")
        log_group_id = os.getenv("LOG_ANALYTICS_LOG_GROUP_ID")
        if not namespace or not log_group_id or "your_" in namespace: return
        
        client = oci.log_analytics.LogAnalyticsClient(config)
        print(f"Uploading logs to Log Analytics (Source: {source_name})...")
        with open(file_path, 'rb') as f:
            try:
                client.upload_log_events_file(
                    namespace_name=namespace, 
                    log_group_id=log_group_id, 
                    upload_log_events_file_details=f, 
                    log_source_name=source_name
                )
                print(f"  Log upload successful for {source_name}.")
            except Exception as e:
                print(f"  Log upload failed for {source_name}: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--traces")
    parser.add_argument("--rum")
    parser.add_argument("--logs")
    parser.add_argument("--source")
    parser.add_argument("--metrics")
    args = parser.parse_args()
    up = APMUploader()
    if args.traces: up.upload_otel_data(args.traces, "Trace")
    if args.rum: up.upload_otel_data(args.rum, "RUM")
    if args.logs: up.upload_app_logs(args.logs, args.source or "Observability_Demo_App_Logs")
    if args.metrics: up.upload_oci_metrics(args.metrics)

if __name__ == "__main__":
    main()
