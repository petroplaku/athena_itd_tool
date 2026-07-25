"""MITRE ATT&CK (Enterprise) technique catalogue for insider-threat detection.

Every ATHENA detector declares the ATT&CK techniques it observes, which lets the
console render a coverage heat-map, lets alerts carry standard technique IDs into
a SIEM, and lets a SOC lead answer "which parts of the kill chain do we see?".

Only the techniques an insider-threat / UEBA product genuinely observes are
modelled — this is a curated working set, not a mirror of the full ATT&CK corpus.
Tactic ordering follows the ATT&CK Enterprise kill chain so the UI can lay the
matrix out left-to-right.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Ordered as the ATT&CK Enterprise matrix presents them.
TACTICS: list[tuple[str, str]] = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
]

TACTIC_NAMES: dict[str, str] = dict(TACTICS)


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique (or sub-technique) ATHENA can observe."""

    id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    url: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            path = self.id.replace(".", "/")
            object.__setattr__(self, "url", f"https://attack.mitre.org/techniques/{path}/")

    @property
    def tactic_names(self) -> list[str]:
        return [TACTIC_NAMES.get(t, t) for t in self.tactics]


def _t(tid: str, name: str, tactics: str, description: str) -> Technique:
    return Technique(id=tid, name=name, tactics=tuple(tactics.split(",")), description=description)


TECHNIQUES: dict[str, Technique] = {
    t.id: t
    for t in [
        # --- Initial Access / Credential Access -------------------------------
        _t("T1078", "Valid Accounts", "TA0001,TA0003,TA0004,TA0005",
           "Use of legitimate credentials — the defining characteristic of insider "
           "and account-takeover activity, which is why signature tools miss it."),
        _t("T1078.004", "Valid Accounts: Cloud Accounts", "TA0001,TA0003,TA0004,TA0005",
           "Authentication to SaaS/IaaS identities (Entra ID, Okta, Workspace) from "
           "unexpected geography, device or time."),
        _t("T1110", "Brute Force", "TA0006",
           "Repeated authentication attempts against one or many accounts."),
        _t("T1110.003", "Brute Force: Password Spraying", "TA0006",
           "A small set of common passwords tried across many accounts, producing a "
           "broad but shallow failure pattern."),
        _t("T1110.004", "Brute Force: Credential Stuffing", "TA0006",
           "Breached credential pairs replayed against corporate SSO."),
        _t("T1556", "Modify Authentication Process", "TA0003,TA0005,TA0006",
           "Tampering with MFA registration, auth providers or trusted-device lists."),
        _t("T1621", "Multi-Factor Authentication Request Generation", "TA0006",
           "MFA fatigue / push-bombing: repeated challenges until the user approves."),
        # --- Privilege Escalation / Persistence -------------------------------
        _t("T1548", "Abuse Elevation Control Mechanism", "TA0004,TA0005",
           "sudo, UAC bypass, setuid abuse and equivalent elevation paths."),
        _t("T1548.003", "Abuse Elevation Control: Sudo and Sudo Caching", "TA0004,TA0005",
           "Unusual sudo volume or sudo by an identity with no operational need."),
        _t("T1098", "Account Manipulation", "TA0003,TA0004",
           "Adding privileges, keys or group memberships to retain or widen access."),
        _t("T1136", "Create Account", "TA0003",
           "Creation of new local, domain or cloud accounts as a persistence foothold."),
        # --- Defense Evasion --------------------------------------------------
        _t("T1070", "Indicator Removal", "TA0005",
           "Clearing logs, deleting history or destroying evidence of activity."),
        _t("T1070.004", "Indicator Removal: File Deletion", "TA0005",
           "Mass deletion of files that would otherwise evidence the actor's actions."),
        _t("T1562", "Impair Defenses", "TA0005",
           "Disabling agents, audit policy or security tooling before acting."),
        _t("T1090", "Proxy", "TA0011",
           "Use of Tor, commercial VPN or anonymising relays to mask true origin."),
        # --- Discovery / Lateral Movement -------------------------------------
        _t("T1083", "File and Directory Discovery", "TA0007",
           "Enumeration of shares and directories — the reconnaissance that precedes "
           "insider data staging."),
        _t("T1087", "Account Discovery", "TA0007",
           "Enumerating users, groups and roles to find privilege or data targets."),
        _t("T1021", "Remote Services", "TA0008",
           "Movement between hosts via SSH/RDP/SMB using valid credentials."),
        _t("T1021.001", "Remote Services: Remote Desktop Protocol", "TA0008",
           "Interactive RDP sessions to hosts outside the user's normal footprint."),
        # --- Collection -------------------------------------------------------
        _t("T1005", "Data from Local System", "TA0009",
           "Bulk reads of local files, often immediately preceding exfiltration."),
        _t("T1039", "Data from Network Shared Drive", "TA0009",
           "Bulk access to file shares beyond the user's role-normal footprint."),
        _t("T1530", "Data from Cloud Storage", "TA0009",
           "Mass download from SharePoint/OneDrive/Drive/S3 buckets."),
        _t("T1074", "Data Staged", "TA0009",
           "Collecting data into a single archive or directory before moving it out."),
        _t("T1114", "Email Collection", "TA0009",
           "Auto-forward rules, mailbox exports or bulk message harvesting."),
        _t("T1114.003", "Email Collection: Email Forwarding Rule", "TA0009",
           "Silent forwarding rules that copy corporate mail to an external address."),
        _t("T1213", "Data from Information Repositories", "TA0009",
           "Scraping Confluence/SharePoint/Jira/code repositories."),
        # --- Exfiltration -----------------------------------------------------
        _t("T1052", "Exfiltration Over Physical Medium", "TA0010",
           "Copying data to USB or other removable media."),
        _t("T1052.001", "Exfiltration Over USB", "TA0010",
           "Removable-media writes — the classic departing-employee exfil channel."),
        _t("T1048", "Exfiltration Over Alternative Protocol", "TA0010",
           "Moving data out over DNS, ICMP, SMTP or other non-web channels."),
        _t("T1567", "Exfiltration Over Web Service", "TA0010",
           "Uploads to personal cloud storage, paste sites or file-transfer services."),
        _t("T1567.002", "Exfiltration to Cloud Storage", "TA0010",
           "Personal Dropbox/Drive/Mega uploads from a managed endpoint."),
        _t("T1029", "Scheduled Transfer", "TA0010",
           "Exfiltration paced to off-hours windows to evade volume baselines."),
        # --- Impact -----------------------------------------------------------
        _t("T1485", "Data Destruction", "TA0040",
           "Deliberate destruction of data or backups — insider sabotage."),
        _t("T1486", "Data Encrypted for Impact", "TA0040",
           "Encryption of files at scale, whether ransomware or insider sabotage."),
        _t("T1531", "Account Access Removal", "TA0040",
           "Locking legitimate owners out of accounts or resources."),
        _t("T1499", "Endpoint Denial of Service", "TA0040",
           "Deliberate degradation of systems the actor has legitimate access to."),
    ]
}


@dataclass
class CoverageCell:
    """One cell of the ATT&CK coverage matrix rendered by the console."""

    technique: Technique
    detectors: list[str] = field(default_factory=list)
    hits: int = 0


def get(technique_id: str) -> Technique | None:
    return TECHNIQUES.get(technique_id)


def resolve(technique_ids: list[str]) -> list[Technique]:
    """Return the known techniques for ``technique_ids``, skipping unknown IDs."""
    return [TECHNIQUES[t] for t in technique_ids if t in TECHNIQUES]


def describe(technique_ids: list[str]) -> list[dict]:
    """JSON-friendly technique records for API responses."""
    return [
        {
            "id": t.id,
            "name": t.name,
            "tactics": list(t.tactics),
            "tactic_names": t.tactic_names,
            "description": t.description,
            "url": t.url,
        }
        for t in resolve(technique_ids)
    ]


def coverage_matrix(detector_techniques: dict[str, list[str]],
                    hit_counts: dict[str, int] | None = None) -> dict:
    """Build the tactic→technique matrix for the console heat-map.

    ``detector_techniques`` maps detector key → technique IDs it observes;
    ``hit_counts`` maps technique ID → how many live alerts referenced it.
    """
    hit_counts = hit_counts or {}
    by_technique: dict[str, list[str]] = {}
    for detector, tids in detector_techniques.items():
        for tid in tids:
            by_technique.setdefault(tid, []).append(detector)

    columns = []
    for tactic_id, tactic_name in TACTICS:
        cells = []
        for tid, tech in TECHNIQUES.items():
            if tactic_id not in tech.tactics:
                continue
            detectors = by_technique.get(tid, [])
            cells.append({
                "id": tid,
                "name": tech.name,
                "description": tech.description,
                "url": tech.url,
                "detectors": detectors,
                "covered": bool(detectors),
                "hits": hit_counts.get(tid, 0),
            })
        cells.sort(key=lambda c: (not c["covered"], -c["hits"], c["id"]))
        if cells:
            columns.append({
                "tactic_id": tactic_id,
                "tactic": tactic_name,
                "techniques": cells,
                "covered": sum(1 for c in cells if c["covered"]),
                "total": len(cells),
            })

    covered = sum(c["covered"] for c in columns)
    total = sum(c["total"] for c in columns)
    return {
        "tactics": columns,
        "covered_techniques": covered,
        "total_techniques": total,
        "coverage_pct": round(100 * covered / total, 1) if total else 0.0,
    }
