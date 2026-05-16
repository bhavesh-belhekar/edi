#!/bin/bash

OSSEC_CONF="/var/ossec/etc/ossec.conf"

echo "[Synthetic-Init] Waiting for Wazuh initialization..."
while [ ! -f "$OSSEC_CONF" ]; do
    sleep 2
done

echo "[Synthetic-Init] Injecting synthetic telemetry log monitors..."
if ! grep -q "synthetic_telemetry" "$OSSEC_CONF"; then
    sed -i '/<\/ossec_config>/i \
  <localfile>\
    <log_format>json</log_format>\
    <location>/var/ossec/logs/synthetic_telemetry/*.log</location>\
  </localfile>' "$OSSEC_CONF"
fi

echo "[Synthetic-Init] Deploying decoders and rules..."
cp /tmp/synthetic_decoders.xml /var/ossec/etc/decoders/
cp /tmp/synthetic_rules.xml /var/ossec/etc/rules/

# Link logs directory
mkdir -p /var/ossec/logs
rm -rf /var/ossec/logs/synthetic_telemetry
ln -s /tmp/synthetic_telemetry /var/ossec/logs/synthetic_telemetry

echo "[Synthetic-Init] Configuration complete."
