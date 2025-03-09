FROM docker.io/kostakoff/rocky-base-images:8-python3.9

WORKDIR /app

USER root

RUN pip3 install flask pyyaml zabbix_utils

USER appuser

COPY ./assets/ ./

ENTRYPOINT /usr/bin/python3 /app/zabbix_agent_exporter.py
