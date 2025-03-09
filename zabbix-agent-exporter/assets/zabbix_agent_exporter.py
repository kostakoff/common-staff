#!/usr/bin/env python3

import os
import yaml
from flask import Flask, Response
from zabbix_utils import Getter

ZABBIX_HOST = os.getenv("ZABBIX_HOST", "127.0.0.1")
ZABBIX_PORT = int(os.getenv("ZABBIX_PORT", "10050"))
METRICS_YAML_PATH = os.getenv("METRICS_YAML_PATH", "metrics.yaml")
METRICS_PATH = os.getenv("METRICS_PATH", "/prometheus")

try:
    with open(METRICS_YAML_PATH, 'r') as f:
        config = yaml.safe_load(f)
        metrics_mapping = config.get('metrics_mapping', [])
except Exception as e:
    print(f"ERROR: Could not read {METRICS_YAML_PATH} - {e}")
    sys.exit(1)

app = Flask(__name__)

@app.route("/health")
def health_check():
    json_body = '{"status": "up"}'
    return Response(json_body, mimetype="application/json", status=200)


@app.route(METRICS_PATH)
def prometheus_metrics():
    agent = Getter(host=ZABBIX_HOST, port=ZABBIX_PORT)
    lines = []

    for metric_info in metrics_mapping:
        prom_name = metric_info.get('name')
        zbx_key = metric_info.get('key')

        if not prom_name:
            continue

        if not zbx_key:
            zbx_key = prom_name

        try:
            resp = agent.get(zbx_key)
            value_str = str(resp.value).strip()
            
            try:
                val_float = float(value_str)
                lines.append(f"{prom_name} {val_float}")
            except ValueError:
                lines.append(f"{prom_name} 0")

        except Exception as exc:
            return Response(
                f"# Error fetching {zbx_key}: {exc}\n", 
                mimetype="text/plain", 
                status=500
            )    
    result = "\n".join(lines) + "\n"
    return Response(result, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
