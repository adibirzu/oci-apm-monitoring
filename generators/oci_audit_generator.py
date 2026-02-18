import json
import random
import uuid
from datetime import datetime
from config.shared_data import OCI_METADATA, OCI_USERS

class OciAuditGenerator:
    def __init__(self, compartment_id=None):
        self.compartment_id = compartment_id or OCI_METADATA["compartment_id"]

    def generate_audit_event(self, user_tuple, event_type, status, timestamp, ip):
        user_id, user_name, _ = user_tuple
        
        return {
            "eventType": event_type,
            "cloudProvider": "OCI",
            "data": {
                "eventId": str(uuid.uuid4()),
                "eventTime": timestamp.isoformat() + "Z",
                "compartmentId": self.compartment_id,
                "identity": {
                    "principalName": user_name,
                    "ipAddress": ip
                },
                "request": {
                    "action": "POST" if "Create" in event_type else "GET",
                    "path": f"/20160918/{event_type.split('.')[-1].lower()}s"
                },
                "response": {
                    "status": str(status),
                    "message": "Success" if status == 200 else "Forbidden"
                }
            }
        }

    def generate_security_audit(self, user_tuple, timestamp, ip, scenario="attack"):
        if scenario == "brute_force":
            return [self.generate_audit_event(user_tuple, "com.oraclecloud.identity.Authenticate", 401, timestamp, ip) for _ in range(5)]
        elif scenario == "privilege_escalation":
            return [self.generate_audit_event(user_tuple, "com.oraclecloud.identity.UpdatePolicy", 200, timestamp, ip)]
        return []
