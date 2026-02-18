import json
import random
import datetime
from config.shared_data import OCI_METADATA

class OciMonitoringGenerator:
    def __init__(self, compartment_id=None):
        self.compartment_id = compartment_id or OCI_METADATA["compartment_id"]

    def generate_metric(self, service_name, metric_name, value, unit, timestamp):
        service_info = OCI_METADATA["services"].get(service_name, {})
        resource_id = service_info.get("ocid", "ocid1.resource.oc1..unknown")
        namespace = service_info.get("metrics_namespace", "custom_metrics")
        
        return {
            "namespace": namespace,
            "compartmentId": self.compartment_id,
            "name": metric_name,
            "dimensions": {
                "resourceId": resource_id,
                "serviceName": service_name,
                "region": "eu-frankfurt-1"
            },
            "metadata": {
                "unit": unit
            },
            "datapoints": [
                {
                    "timestamp": timestamp.isoformat() + "Z",
                    "value": value,
                    "count": 1
                }
            ]
        }

    def generate_system_metrics(self, service_name, timestamp, is_high_load=False):
        metrics = []
        cpu_base = 70 if is_high_load else 20
        mem_base = 80 if is_high_load else 40
        
        metrics.append(self.generate_metric(service_name, "CpuUtilization", cpu_base + random.uniform(0, 10), "percent", timestamp))
        metrics.append(self.generate_metric(service_name, "MemoryUtilization", mem_base + random.uniform(0, 5), "percent", timestamp))
        metrics.append(self.generate_metric(service_name, "DiskBytesRead", random.randint(1000, 5000), "bytes", timestamp))
        
        return metrics
