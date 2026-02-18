import io
import os
import json
import logging
from datetime import datetime, timedelta, timezone
from generate_apm_data import CampaignEngine
from uploader import APMUploader

from fdk import response

def handler(ctx, data: io.BytesIO = None):
    logging.getLogger().info("Observability Demo Function started.")
    
    output_dir = "/tmp/synthetic_data"
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Generate Data (Last 1 Day)
    start_time = datetime.now(timezone.utc) - timedelta(days=1)
    engine = CampaignEngine(output_dir, start_time, 1)
    engine.run()
    
    # 2. Upload Data
    uploader = APMUploader()
    uploader.upload_traces(os.path.join(output_dir, "apm_traces.jsonl"))
    uploader.upload_rum(os.path.join(output_dir, "apm_rum.jsonl"))
    uploader.upload_app_logs(os.path.join(output_dir, "app_logs.json"))
    
    return response.Response(
        ctx, response_data=json.dumps({"status": "success", "message": "Synthetic data generated and uploaded"}),
        headers={"Content-Type": "application/json"}
    )
