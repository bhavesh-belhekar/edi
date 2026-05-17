from shared.logger import get_logger
from shared.schemas import SecurityEvent

logger = get_logger("enrichment.user")

# Static role-privilege mapping for offline enrichment.
# In production this would be backed by an LDAP/AD lookup service.
_PRIVILEGED_ROLES = frozenset({
    "administrator",
    "admin",
    "root",
    "superuser",
    "domain_admin",
    "dba",
    "sysadmin",
})

_DEPARTMENT_RISK = {
    "IT": "elevated",
    "Security": "elevated",
    "Finance": "elevated",
    "Engineering": "standard",
    "HR": "standard",
    "Marketing": "low",
    "Sales": "low",
}


def enrich_user(event: SecurityEvent) -> SecurityEvent:
    """Add role-based and department-based context to user metadata."""
    if event.user is None:
        return event

    username = event.user.username or ""

    # Assign default role when missing
    if event.user.role is None:
        if username.lower() in ("admin", "root", "superuser"):
            event.user.role = "administrator"
        else:
            event.user.role = "standard_user"

    # Assign default department when missing
    if event.user.department is None:
        event.user.department = "Unknown"

    is_privileged = event.user.role.lower() in _PRIVILEGED_ROLES
    dept_risk = _DEPARTMENT_RISK.get(event.user.department, "standard")

    logger.debug(
        "user=%s role=%s privileged=%s dept_risk=%s",
        username,
        event.user.role,
        is_privileged,
        dept_risk,
    )

    return event
