#!/bin/bash
# Setup script to inject custom localfile configuration for the synthetic telemetry

OSSEC_CONF="/var/ossec/etc/ossec.conf"

if ! grep -q "logs/synthetic_telemetry" "$OSSEC_CONF"; then
  echo "[Synthetic-Init] Injecting synthetic telemetry log monitors into ossec.conf..."
  sed -i '/<\/ossec_config>/i \
  <localfile>\
    <log_format>json</log_format>\
    <location>/var/ossec/logs/synthetic_telemetry/*.log</location>\
  </localfile>' "$OSSEC_CONF"
else
  echo "[Synthetic-Init] Monitor block already present."
fi

# Fix permissions for custom files mounted directly as root
chown -R wazuh:wazuh /var/ossec/etc/decoders/synthetic_decoders.xml || true
chown -R wazuh:wazuh /var/ossec/etc/rules/synthetic_rules.xml || true

echo "[Synthetic-Init] Configuration complete. Handing over to Wazuh init."
