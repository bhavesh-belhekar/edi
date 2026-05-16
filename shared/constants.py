from enum import Enum, auto

"""
CENTRALIZED CONSTANTS AND ENUMERATIONS.

Defining constants strictly categorizes system state, preventing hard-coded typos 
(e.g., checking for "critical" vs "Critical") from breaking analytics down the pipeline.
"""

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class WazuhSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    ALERT = "alert"

class MitreTactic(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

class PlaybookStatus(str, Enum):
    NONE = "none"
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"

class ConnectionStatus(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    RETRYING = "retrying"

# ==============================================================================
# GLOBAL DEFAULT CONFIGURATIONS
# ==============================================================================

# Time window mappings in seconds
SLIDING_WINDOW_1M = 60
SLIDING_WINDOW_5M = 300
SLIDING_WINDOW_15M = 900
SLIDING_WINDOW_1H = 3600
