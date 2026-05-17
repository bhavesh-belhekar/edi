#!/usr/bin/env python3
"""
Quick validation script for the multi-source telemetry pipeline.
Run: python synthetic_logs/validate.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    print("=" * 60)
    print(" VALIDATION: Multi-Source Telemetry Pipeline")
    print("=" * 60)

    # 1. Schema imports
    print("\n[1/4] Testing schema imports...")
    try:
        from shared.schemas import (
            SecurityEvent, FirewallInfo, ProxyInfo
        )
        print("  ✓ SecurityEvent, FirewallInfo, ProxyInfo, DNSInfo imported")
        print(f"    FirewallInfo fields: {list(FirewallInfo.model_fields.keys())}")
        print(f"    ProxyInfo fields: {list(ProxyInfo.model_fields.keys())}")
        assert 'firewall' in SecurityEvent.model_fields, "firewall field missing from SecurityEvent"
        assert 'proxy' in SecurityEvent.model_fields, "proxy field missing from SecurityEvent"
        print("  ✓ SecurityEvent has firewall and proxy fields")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return 1

    # 2. Generator imports
    print("\n[2/4] Testing generator imports...")
    try:
        from synthetic_logs.generators.auth_generator import AuthEventGenerator
        from synthetic_logs.generators.endpoint_generator import EndpointEventGenerator
        from synthetic_logs.generators.dns_generator import DNSEventGenerator
        from synthetic_logs.generators.firewall_generator import FirewallEventGenerator
        from synthetic_logs.generators.proxy_generator import ProxyEventGenerator
        print("  ✓ All 5 generators imported successfully")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback; traceback.print_exc()
        return 1

    # 3. Quick event generation test
    print("\n[3/4] Testing event generation...")
    try:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc)

        auth_gen = AuthEventGenerator()
        endpoint_gen = EndpointEventGenerator()
        dns_gen = DNSEventGenerator()
        fw_gen = FirewallEventGenerator()
        proxy_gen = ProxyEventGenerator()

        user = auth_gen.users[0]
        system = auth_gen.systems[0]

        ev1 = auth_gen.generate_successful_login(ts, user)
        print(f"  ✓ Auth event: {ev1.event_type} (severity={ev1.severity})")

        ev2 = endpoint_gen.generate_normal_activity(ts, user, system)
        print(f"  ✓ Endpoint events: {len(ev2)} events generated")

        ev3 = dns_gen.generate_benign_dns(ts, user, system)
        print(f"  ✓ DNS events: {len(ev3)} events generated")

        ev4 = dns_gen.generate_typosquat_query(ts, user, system)
        print(f"  ✓ DNS typosquat: {ev4.dns.queried_domain}")

        ev5 = fw_gen.generate_normal_outbound(ts, user, system)
        print(f"  ✓ Firewall events: {len(ev5)} events, action={ev5[0].firewall.action}")

        ev6 = proxy_gen.generate_normal_browsing(ts, user, system)
        print(f"  ✓ Proxy events: {len(ev6)} events, url={ev6[0].proxy.url[:50]}...")

    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback; traceback.print_exc()
        return 1

    # 4. Serialization test
    print("\n[4/4] Testing JSON serialization...")
    try:
        from shared.utils import to_json_str
        import json

        for ev in [ev1] + ev2 + ev3 + [ev4] + ev5 + ev6:
            json_str = to_json_str(ev)
            parsed = json.loads(json_str)
            assert "event_id" in parsed
            assert "timestamp" in parsed
            assert "raw_log" in parsed

        print("  ✓ All events serialize to valid JSON")
        print(f"  ✓ Sample keys: {list(json.loads(to_json_str(ev5[0])).keys())}")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        import traceback; traceback.print_exc()
        return 1

    print("\n" + "=" * 60)
    print(" ALL VALIDATIONS PASSED ✓")
    print("=" * 60)
    print("\nTo generate full datasets, run:")
    print("  python -m synthetic_logs.generate_logs --count 500 --attacks 3 --seed 42")
    return 0

if __name__ == "__main__":
    sys.exit(main())
