import json
import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Optional

from faker import Faker
from shared.schemas import (
    SecurityEvent, SourceInfo, DestinationInfo, UserInfo, SystemInfo,
    ProxyInfo, BehavioralFeatures, DetectionInfo, MITREAttackInfo, CorrelationInfo
)


class ProxyEventGenerator:
    """
    Enterprise Web Proxy Telemetry Generator (Squid/Blue Coat/Zscaler style).
    Simulates HTTP/HTTPS web requests including normal browsing, SaaS access,
    software updates, malicious downloads, phishing, and C2 HTTP beaconing.
    """

    def __init__(self, template_dir: str = "synthetic_logs/templates"):
        self.fake = Faker()
        with open(f"{template_dir}/users.json", "r") as f:
            self.users = json.load(f)
        with open(f"{template_dir}/systems.json", "r") as f:
            self.systems = json.load(f)
        with open(f"{template_dir}/ips.json", "r") as f:
            self.ips = json.load(f)

        self.legitimate_domains = {
            "business": [
                "salesforce.com", "office365.com", "teams.microsoft.com",
                "slack.com", "jira.atlassian.net", "confluence.atlassian.net",
                "zoom.us", "webex.com", "servicenow.com",
            ],
            "search": [
                "google.com", "bing.com", "duckduckgo.com",
            ],
            "social": [
                "linkedin.com", "twitter.com", "reddit.com",
            ],
            "news": [
                "reuters.com", "bbc.com", "techcrunch.com", "arstechnica.com",
            ],
            "dev": [
                "github.com", "stackoverflow.com", "npmjs.com", "pypi.org",
                "docs.python.org", "developer.mozilla.org",
            ],
            "cloud": [
                "console.aws.amazon.com", "portal.azure.com", "console.cloud.google.com",
                "s3.amazonaws.com", "blob.core.windows.net",
            ],
        }
        self.update_domains = [
            "windowsupdate.com", "update.microsoft.com", "download.docker.com",
            "apt.ubuntu.com", "packages.debian.org", "rpm.releases.hashicorp.com",
            "dl.google.com", "updates.jenkins.io",
        ]
        self.malicious_urls = {
            "download": [
                "http://temp-storage.cc/payload.exe",
                "http://file-share-cdn.tk/update_patch.scr",
                "https://pastebin-downloads.ru/tools/agent.dll",
                "http://dynamic-resolve-01.duckdns.org/svchost.exe",
                "https://mimi-k-toolkit.xyz/mk64.zip",
            ],
            "phishing": [
                "https://secure-banklogin.com/auth/verify",
                "https://paypal-verify-account.net/login",
                "https://hr-benefits-update.com/enroll",
                "https://it-helpdesk-reset.com/password-reset",
                "https://login-office365-secure.net/signin",
            ],
            "c2": [
                "https://xj3k91-malware-c2.xyz/api/beacon",
                "https://data-sync-ddns.biz/check-in",
                "https://powershell-gallery-dl.info/callback",
                "https://update-kb4013429.info/status",
                "https://node-proxy-88.no-ip.biz/gate",
            ],
        }
        self.user_agents = {
            "normal": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/125.0.2535.67",
            ],
            "suspicious": [
                "python-requests/2.31.0",
                "curl/8.4.0",
                "PowerShell/7.4 (Windows NT 10.0; Microsoft Windows 10.0.22631)",
                "Wget/1.21.4",
                "Java/17.0.8",
            ],
        }
        self.proxy_ip = "10.0.1.3"

    def _create_base_event(self, event_type, severity, timestamp):
        return SecurityEvent(
            event_id=str(uuid.uuid4()), timestamp=timestamp,
            event_type=event_type, severity=severity, raw_log="Placeholder"
        )

    def _get_random_malicious_ip(self):
        return random.choice(self.ips["known_malicious_ips"])

    # ==========================================================================
    # 1. NORMAL WEB BROWSING
    # ==========================================================================
    def generate_normal_browsing(self, timestamp, user, system):
        events = []
        count = random.randint(2, 5)
        current_time = timestamp
        session_id = f"sess_{random.randint(10000, 99999)}"
        category = random.choice(list(self.legitimate_domains.keys()))
        domain = random.choice(self.legitimate_domains[category])

        for _ in range(count):
            current_time += timedelta(seconds=random.randint(1, 15))
            path = random.choice(["/", f"/{self.fake.uri_path()}", f"/api/{self.fake.word()}"])
            url = f"https://{domain}{path}"
            method = random.choices(["GET", "POST"], weights=[0.85, 0.15])[0]
            status = random.choices([200, 304, 301, 302], weights=[0.7, 0.15, 0.1, 0.05])[0]

            event = self._create_base_event("proxy_request", "info", current_time)
            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
            event.destination = DestinationInfo(ip=self.fake.ipv4(), port=443, hostname=domain)
            event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
            event.system = SystemInfo(os=system["os"])
            event.proxy = ProxyInfo(
                url=url, method=method, status_code=status,
                user_agent=random.choice(self.user_agents["normal"]),
                domain=domain, content_type="text/html",
                bytes_transferred=random.randint(1000, 150000),
                referrer=f"https://{domain}/" if random.random() < 0.5 else None,
                category=category
            )
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.0, 0.05), ueba_score=0.01,
                                             risk_score=0.0, risk_level="low")
            event.correlation = CorrelationInfo(session_id=session_id)
            event.raw_log = (
                f"PROXY: {current_time.isoformat()} {user['username']} {system['ip']} "
                f"{method} {url} {status} {event.proxy.bytes_transferred} "
                f"\"{event.proxy.user_agent}\" category={category}"
            )
            events.append(event)
        return events

    # ==========================================================================
    # 2. SOFTWARE UPDATE TRAFFIC
    # ==========================================================================
    def generate_software_update(self, timestamp, user, system):
        domain = random.choice(self.update_domains)
        path = random.choice(["/v2/update", "/packages/pool/main", "/release/download", "/api/check"])
        url = f"https://{domain}{path}"

        event = self._create_base_event("proxy_request", "info", timestamp)
        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        event.destination = DestinationInfo(ip=self.fake.ipv4(), port=443, hostname=domain)
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.system = SystemInfo(os=system["os"])
        event.proxy = ProxyInfo(
            url=url, method="GET", status_code=200,
            user_agent=random.choice(self.user_agents["normal"]),
            domain=domain, content_type="application/octet-stream",
            bytes_transferred=random.randint(100000, 50000000),
            category="software_update"
        )
        event.detection = DetectionInfo(anomaly_score=random.uniform(0.0, 0.03), ueba_score=0.01,
                                         risk_score=0.0, risk_level="low")
        event.correlation = CorrelationInfo(session_id=f"sess_{random.randint(10000, 99999)}")
        event.raw_log = (
            f"PROXY: {timestamp.isoformat()} {user['username']} {system['ip']} "
            f"GET {url} 200 {event.proxy.bytes_transferred} "
            f"\"{event.proxy.user_agent}\" category=software_update"
        )
        return event

    # ==========================================================================
    # 3. CLOUD SERVICE ACCESS
    # ==========================================================================
    def generate_cloud_access(self, timestamp, user, system):
        domain = random.choice(self.legitimate_domains["cloud"])
        path = random.choice(["/api/resources", "/storage/list", "/compute/instances", "/iam/roles"])
        url = f"https://{domain}{path}"
        method = random.choice(["GET", "POST", "PUT"])

        event = self._create_base_event("proxy_request", "info", timestamp)
        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        event.destination = DestinationInfo(ip=self.fake.ipv4(), port=443, hostname=domain)
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.system = SystemInfo(os=system["os"])
        event.proxy = ProxyInfo(
            url=url, method=method, status_code=random.choice([200, 201, 204]),
            user_agent=random.choice(self.user_agents["normal"]),
            domain=domain, content_type="application/json",
            bytes_transferred=random.randint(500, 25000),
            category="cloud"
        )
        event.detection = DetectionInfo(anomaly_score=random.uniform(0.0, 0.05), ueba_score=0.01,
                                         risk_score=0.0, risk_level="low")
        event.correlation = CorrelationInfo(session_id=f"sess_{random.randint(10000, 99999)}")
        event.raw_log = (
            f"PROXY: {timestamp.isoformat()} {user['username']} {system['ip']} "
            f"{method} {url} {event.proxy.status_code} {event.proxy.bytes_transferred} "
            f"\"{event.proxy.user_agent}\" category=cloud"
        )
        return event

    # ==========================================================================
    # 4. MALICIOUS DOWNLOAD (Ingress Tool Transfer)
    # ==========================================================================
    def generate_malicious_download(self, timestamp, user, system, attack_chain_id=None, prev_event_id=None):
        url = random.choice(self.malicious_urls["download"])
        domain = url.split("/")[2]

        event = self._create_base_event("proxy_request", "high", timestamp)
        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        event.destination = DestinationInfo(ip=self._get_random_malicious_ip(), port=443 if "https" in url else 80,
                                             hostname=domain)
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.system = SystemInfo(os=system["os"])
        event.proxy = ProxyInfo(
            url=url, method="GET", status_code=200,
            user_agent=random.choice(self.user_agents["suspicious"]),
            domain=domain, content_type="application/octet-stream",
            bytes_transferred=random.randint(50000, 5000000),
            category="malicious"
        )
        event.detection = DetectionInfo(
            anomaly_score=random.uniform(0.75, 0.92), ueba_score=random.uniform(0.70, 0.88),
            risk_score=random.uniform(70.0, 90.0), risk_level="high", signature_match=True
        )
        event.mitre_attack = MITREAttackInfo(
            technique_id="T1105", technique_name="Ingress Tool Transfer",
            tactic="Command and Control", confidence=0.88
        )
        event.correlation = CorrelationInfo(
            attack_chain_id=attack_chain_id,
            session_id=f"sess_{uuid.uuid4().hex[:8]}",
            related_events=[prev_event_id] if prev_event_id else []
        )
        event.raw_log = (
            f"PROXY_ALERT: {timestamp.isoformat()} {user['username']} {system['ip']} "
            f"GET {url} 200 {event.proxy.bytes_transferred} "
            f"\"{event.proxy.user_agent}\" category=malicious "
            f"alert=suspicious_download content_type=application/octet-stream "
            f"threat_intel=known_malicious_domain"
        )
        return event

    # ==========================================================================
    # 5. PHISHING PAGE ACCESS
    # ==========================================================================
    def generate_phishing_access(self, timestamp, user, system, attack_chain_id=None, prev_event_id=None):
        url = random.choice(self.malicious_urls["phishing"])
        domain = url.split("/")[2]

        event = self._create_base_event("proxy_request", "high", timestamp)
        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        event.destination = DestinationInfo(ip=self._get_random_malicious_ip(), port=443, hostname=domain)
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.system = SystemInfo(os=system["os"])

        # User submits credentials via POST
        method = random.choices(["GET", "POST"], weights=[0.4, 0.6])[0]
        status = 200 if method == "GET" else 302

        event.proxy = ProxyInfo(
            url=url, method=method, status_code=status,
            user_agent=random.choice(self.user_agents["normal"]),
            domain=domain, content_type="text/html",
            bytes_transferred=random.randint(2000, 30000),
            referrer=f"https://{self.fake.domain_name()}/redirect" if random.random() < 0.6 else None,
            category="malicious"
        )
        event.detection = DetectionInfo(
            anomaly_score=random.uniform(0.65, 0.85), ueba_score=random.uniform(0.60, 0.80),
            risk_score=random.uniform(60.0, 85.0), risk_level="high"
        )
        event.mitre_attack = MITREAttackInfo(
            technique_id="T1566", technique_name="Phishing",
            tactic="Initial Access", confidence=0.78
        )
        event.correlation = CorrelationInfo(
            attack_chain_id=attack_chain_id,
            session_id=f"sess_{uuid.uuid4().hex[:8]}",
            related_events=[prev_event_id] if prev_event_id else []
        )
        event.raw_log = (
            f"PROXY_ALERT: {timestamp.isoformat()} {user['username']} {system['ip']} "
            f"{method} {url} {status} {event.proxy.bytes_transferred} "
            f"\"{event.proxy.user_agent}\" category=malicious "
            f"alert=phishing_page_detected"
        )
        return event

    # ==========================================================================
    # 6. C2 HTTP BEACON
    # ==========================================================================
    def generate_c2_http_beacon(self, timestamp, user, system, attack_chain_id=None, prev_event_id=None):
        events = []
        current_time = timestamp
        c2_url = random.choice(self.malicious_urls["c2"])
        domain = c2_url.split("/")[2]
        session_id = f"sess_{uuid.uuid4().hex[:8]}"

        for i in range(random.randint(3, 6)):
            current_time += timedelta(seconds=random.randint(10, 60))
            event = self._create_base_event("proxy_request", "critical", current_time)
            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
            event.destination = DestinationInfo(ip=self._get_random_malicious_ip(), port=443, hostname=domain)
            event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
            event.system = SystemInfo(os=system["os"])
            event.proxy = ProxyInfo(
                url=c2_url, method="POST", status_code=200,
                user_agent=random.choice(self.user_agents["suspicious"]),
                domain=domain, content_type="application/octet-stream",
                bytes_transferred=random.randint(200, 5000),
                category="malicious"
            )
            event.detection = DetectionInfo(
                anomaly_score=random.uniform(0.88, 0.99), ueba_score=random.uniform(0.85, 0.97),
                risk_score=random.uniform(85.0, 100.0), risk_level="critical", signature_match=True
            )
            event.mitre_attack = MITREAttackInfo(
                technique_id="T1071.001", technique_name="Application Layer Protocol: Web Protocols",
                tactic="Command and Control", confidence=0.94
            )
            event.correlation = CorrelationInfo(
                attack_chain_id=attack_chain_id, session_id=session_id,
                related_events=[prev_event_id] if prev_event_id else []
            )
            event.raw_log = (
                f"PROXY_C2_ALERT: {current_time.isoformat()} {user['username']} {system['ip']} "
                f"POST {c2_url} 200 {event.proxy.bytes_transferred} "
                f"\"{event.proxy.user_agent}\" category=malicious "
                f"alert=c2_beacon beacon_interval=periodic beacon#{i+1}"
            )
            events.append(event)
            prev_event_id = event.event_id
        return events
