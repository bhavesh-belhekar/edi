#!/usr/bin/env bash
set -euo pipefail

OSSEC_CONF="/var/ossec/etc/ossec.conf"
SYNTHETIC_DIR="/var/ossec/logs/synthetic_telemetry"
DECODER_SRC="/tmp/synthetic_decoders.xml"
RULE_SRC="/tmp/synthetic_rules.xml"
DECODER_DST="/var/ossec/etc/decoders/synthetic_decoders.xml"
RULE_DST="/var/ossec/etc/rules/synthetic_rules.xml"
BACKUP_CONF="/var/ossec/etc/ossec.conf.pre_synthetic_step2"
TMP_CONF="/tmp/ossec.conf.synthetic.$$"

log() {
  printf '[Synthetic-Step2] %s\n' "$*"
}

require_file() {
  if [ ! -f "$1" ]; then
    log "ERROR: required file is missing: $1"
    exit 1
  fi
}

wait_for_file() {
  path="$1"
  label="$2"
  attempts="${3:-120}"

  i=1
  while [ "$i" -le "$attempts" ]; do
    if [ -f "$path" ]; then
      return 0
    fi

    if [ "$i" -eq 1 ] || [ $((i % 10)) -eq 0 ]; then
      log "Waiting for $label: $path"
    fi

    i=$((i + 1))
    sleep 1
  done

  log "ERROR: timed out waiting for $label: $path"
  return 1
}

install_custom_xml() {
  log "Installing synthetic decoder and rule files."
  require_file "$DECODER_SRC"
  require_file "$RULE_SRC"

  mkdir -p /var/ossec/etc/decoders /var/ossec/etc/rules

  tr -d '\r' < "$DECODER_SRC" > "$DECODER_DST"
  tr -d '\r' < "$RULE_SRC" > "$RULE_DST"

  chmod 0640 "$DECODER_DST" "$RULE_DST"
  chown root:wazuh "$DECODER_DST" "$RULE_DST" 2>/dev/null || chown root:ossec "$DECODER_DST" "$RULE_DST" 2>/dev/null || true
}

ensure_alert_files() {
  current_year="$(date -u +%Y)"

  log "Ensuring Wazuh log output files and directories exist."
  mkdir -p \
    "/var/ossec/logs/alerts/${current_year}" \
    "/var/ossec/logs/archives/${current_year}" \
    "/var/ossec/logs/firewall/${current_year}" \
    /var/ossec/logs/cluster \
    /var/ossec/logs/api

  touch \
    /var/ossec/logs/alerts/alerts.json \
    /var/ossec/logs/alerts/alerts.log \
    /var/ossec/logs/active-responses.log \
    /var/ossec/logs/firewall/firewall.log

  chown -R wazuh:wazuh /var/ossec/logs 2>/dev/null || chown -R ossec:ossec /var/ossec/logs 2>/dev/null || true
}

rewrite_synthetic_localfile_block() {
  require_file "$OSSEC_CONF"

  if [ ! -f "$BACKUP_CONF" ]; then
    cp "$OSSEC_CONF" "$BACKUP_CONF"
    log "Backed up original ossec.conf to $BACKUP_CONF."
  fi

  log "Removing previous synthetic telemetry localfile blocks."
  awk '
    BEGIN {
      in_localfile = 0
      block = ""
    }

    /^[[:space:]]*<localfile>[[:space:]]*$/ {
      in_localfile = 1
      block = $0 ORS
      next
    }

    in_localfile == 1 {
      block = block $0 ORS
      if ($0 ~ /^[[:space:]]*<\/localfile>[[:space:]]*$/) {
        if (block !~ /\/var\/ossec\/logs\/synthetic_telemetry\//) {
          printf "%s", block
        }
        in_localfile = 0
        block = ""
      }
      next
    }

    {
      print
    }

    END {
      if (in_localfile == 1) {
        printf "%s", block
      }
    }
  ' "$OSSEC_CONF" > "$TMP_CONF"

  if ! grep -q '</ossec_config>' "$TMP_CONF"; then
    log "ERROR: $OSSEC_CONF has no closing </ossec_config> tag."
    exit 1
  fi

  log "Adding exactly one synthetic telemetry monitor block."
  awk -v synthetic_dir="$SYNTHETIC_DIR" '
    /^[[:space:]]*<\/ossec_config>[[:space:]]*$/ && inserted == 0 {
      print "  <!-- STEP 2: Synthetic telemetry JSON logs. Managed by /setup_wazuh.sh. -->"
      print "  <localfile>"
      print "    <log_format>syslog</log_format>"
      print "    <location>" synthetic_dir "/*.log</location>"
      print "  </localfile>"
      print ""
      inserted = 1
    }
    {
      print
    }
  ' "$TMP_CONF" > "$OSSEC_CONF"
  rm -f "$TMP_CONF"
}

main() {
  log "Waiting for Wazuh Manager init to create base configuration."
  wait_for_file "$OSSEC_CONF" "ossec.conf"

  log "Applying Wazuh Manager Step 2 bootstrap."
  install_custom_xml
  ensure_alert_files
  rewrite_synthetic_localfile_block
  log "Restarting Wazuh services after Step 2 configuration."
  /var/ossec/bin/wazuh-control restart || true
  log "Bootstrap complete."
}

start_wazuh() {
  log "Starting Wazuh supervisor."
  exec /init
}

main "$@" &
start_wazuh
