"""Regulatory and control-framework mapping for ATHENA detections.

Insider-threat monitoring is nearly always justified to a board through a control
framework rather than through threat language. This module maps each detector to
the specific controls it provides evidence for, and produces a coverage report an
auditor can read: which controls are monitored, which are not, and which alerts
in the current window constitute evidence.

Mappings are conservative — a detector is only claimed against a control when the
detection genuinely produces the monitoring evidence that control requires.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Control:
    """A single control/article within a framework."""

    id: str
    title: str
    summary: str


@dataclass(frozen=True)
class Framework:
    """A regulation or control standard ATHENA maps detections onto."""

    key: str
    name: str
    authority: str
    description: str
    controls: dict[str, Control] = field(default_factory=dict)


def _fw(key: str, name: str, authority: str, description: str,
        controls: list[tuple[str, str, str]]) -> Framework:
    return Framework(
        key=key, name=name, authority=authority, description=description,
        controls={c[0]: Control(id=c[0], title=c[1], summary=c[2]) for c in controls},
    )


FRAMEWORKS: dict[str, Framework] = {
    f.key: f
    for f in [
        _fw("gdpr", "GDPR", "EU 2016/679",
            "EU General Data Protection Regulation — personal-data protection, "
            "accountability and breach notification.",
            [
                ("Art.5(1)(f)", "Integrity and confidentiality",
                 "Personal data must be processed with protection against unauthorised "
                 "or unlawful processing, including by insiders."),
                ("Art.25", "Data protection by design and by default",
                 "Technical measures must limit access to what each purpose requires."),
                ("Art.30", "Records of processing activities",
                 "Maintain records of processing, including who accessed what."),
                ("Art.32", "Security of processing",
                 "Ongoing confidentiality/integrity assurance plus a process for "
                 "regularly testing and evaluating effectiveness of measures."),
                ("Art.33", "Notification of a breach to the supervisory authority",
                 "Detect and report personal-data breaches within 72 hours."),
                ("Art.35", "Data protection impact assessment",
                 "Assess risk of high-risk processing, including monitoring."),
            ]),
        _fw("hipaa", "HIPAA Security Rule", "45 CFR Part 164 (US HHS)",
            "US health-information security rule governing ePHI safeguards.",
            [
                ("164.308(a)(1)(ii)(D)", "Information system activity review",
                 "Regularly review audit logs, access reports and security-incident "
                 "tracking reports."),
                ("164.308(a)(3)", "Workforce security",
                 "Ensure workforce members have appropriate ePHI access and prevent "
                 "those who should not have access from obtaining it."),
                ("164.308(a)(5)(ii)(C)", "Log-in monitoring",
                 "Procedures for monitoring log-in attempts and reporting discrepancies."),
                ("164.308(a)(6)", "Security incident procedures",
                 "Identify, respond to and document suspected security incidents."),
                ("164.312(a)(1)", "Access control",
                 "Technical policies allowing ePHI access only to authorised persons."),
                ("164.312(b)", "Audit controls",
                 "Record and examine activity in systems containing ePHI."),
            ]),
        _fw("iso27001", "ISO/IEC 27001:2022", "ISO/IEC",
            "Information security management system requirements, Annex A controls.",
            [
                ("A.5.7", "Threat intelligence",
                 "Collect and analyse information about threats to inform action."),
                ("A.5.15", "Access control",
                 "Rules for physical and logical access based on business requirements."),
                ("A.5.16", "Identity management",
                 "Full lifecycle management of identities."),
                ("A.5.18", "Access rights",
                 "Provision, review, modify and remove access rights."),
                ("A.6.8", "Information security event reporting",
                 "Provide a mechanism to report observed security events timely."),
                ("A.8.15", "Logging",
                 "Produce, store, protect and analyse logs of activities and events."),
                ("A.8.16", "Monitoring activities",
                 "Monitor networks, systems and applications for anomalous behaviour "
                 "and evaluate potential incidents."),
                ("A.8.12", "Data leakage prevention",
                 "Apply DLP measures to systems and networks processing sensitive data."),
            ]),
        _fw("soc2", "SOC 2 (TSC 2017)", "AICPA",
            "Trust Services Criteria for security, availability and confidentiality.",
            [
                ("CC6.1", "Logical access security",
                 "Implement logical access controls over protected information assets."),
                ("CC6.2", "Access provisioning",
                 "Register and authorise new users before granting access."),
                ("CC6.6", "External threat protection",
                 "Implement controls to prevent or detect threats from outside "
                 "the system boundary."),
                ("CC6.7", "Restricted data transmission",
                 "Restrict movement of information to authorised users and processes."),
                ("CC7.2", "Anomaly monitoring",
                 "Monitor system components for anomalies indicative of malicious acts, "
                 "natural disasters and errors."),
                ("CC7.3", "Security event evaluation",
                 "Evaluate security events to determine whether they are incidents."),
                ("CC7.4", "Incident response",
                 "Respond to identified security incidents through a defined programme."),
            ]),
        _fw("pcidss", "PCI DSS v4.0", "PCI Security Standards Council",
            "Payment card data protection standard.",
            [
                ("7.2", "Least-privilege access",
                 "Access to system components and data is appropriately defined and "
                 "assigned by business need to know."),
                ("8.3", "Strong authentication",
                 "Strong authentication for users and administrators is established."),
                ("10.2", "Audit logs",
                 "Audit logs are implemented to support anomaly and suspicious-activity "
                 "detection and forensic analysis."),
                ("10.4", "Audit log review",
                 "Audit logs are reviewed to identify anomalies or suspicious activity."),
                ("10.7", "Failure detection",
                 "Failures of critical security control systems are detected, reported "
                 "and responded to promptly."),
                ("12.10", "Incident response",
                 "Suspected and confirmed security incidents are responded to immediately."),
            ]),
        _fw("nist80053", "NIST SP 800-53 Rev.5", "NIST",
            "US federal security and privacy control catalogue.",
            [
                ("AC-2", "Account management",
                 "Monitor the use of accounts and report atypical usage."),
                ("AC-2(12)", "Account monitoring for atypical usage",
                 "Monitor system accounts for atypical usage and report it."),
                ("AC-6(9)", "Log use of privileged functions",
                 "Log the execution of privileged functions."),
                ("AU-6", "Audit record review, analysis and reporting",
                 "Review and analyse audit records for indications of inappropriate "
                 "or unusual activity."),
                ("AU-6(3)", "Correlate audit repositories",
                 "Analyse and correlate audit records across repositories for "
                 "organisation-wide situational awareness."),
                ("IR-4", "Incident handling",
                 "Implement incident handling for security incidents."),
                ("PM-12", "Insider threat programme",
                 "Implement an insider-threat programme including a cross-discipline "
                 "incident handling team."),
                ("SI-4", "System monitoring",
                 "Monitor the system to detect attacks, indicators of potential attacks "
                 "and unauthorised local/network/remote connections."),
                ("SI-4(20)", "Privileged users",
                 "Implement additional monitoring of privileged users."),
            ]),
        _fw("nistcsf", "NIST CSF 2.0", "NIST",
            "Cybersecurity Framework functions and categories.",
            [
                ("ID.RA-01", "Vulnerabilities identified",
                 "Vulnerabilities in assets are identified, validated and recorded."),
                ("PR.AA-05", "Access permissions",
                 "Access permissions, entitlements and authorisations are defined and "
                 "managed incorporating least privilege and separation of duties."),
                ("DE.AE-02", "Adverse event analysis",
                 "Potentially adverse events are analysed to better understand "
                 "associated activities."),
                ("DE.AE-03", "Information correlation",
                 "Information is correlated from multiple sources."),
                ("DE.CM-01", "Network monitoring",
                 "Networks and network services are monitored to find potentially "
                 "adverse events."),
                ("DE.CM-03", "Personnel activity monitoring",
                 "Personnel activity and technology usage are monitored to find "
                 "potentially adverse events."),
                ("RS.MA-01", "Incident response executed",
                 "The incident response plan is executed once an incident is declared."),
            ]),
    ]
}

# Controls every deployed detector contributes evidence for, simply by running.
BASELINE_CONTROLS: dict[str, list[str]] = {
    "gdpr": ["Art.5(1)(f)", "Art.32"],
    "hipaa": ["164.308(a)(1)(ii)(D)", "164.312(b)"],
    "iso27001": ["A.8.15", "A.8.16"],
    "soc2": ["CC7.2"],
    "pcidss": ["10.2", "10.4"],
    "nist80053": ["AU-6", "SI-4", "PM-12"],
    "nistcsf": ["DE.AE-02", "DE.CM-03"],
}


def list_frameworks() -> list[dict]:
    """Framework metadata for the console's compliance view."""
    return [
        {
            "key": f.key,
            "name": f.name,
            "authority": f.authority,
            "description": f.description,
            "control_count": len(f.controls),
        }
        for f in FRAMEWORKS.values()
    ]


def resolve_controls(mapping: dict[str, list[str]]) -> list[dict]:
    """Expand a detector's ``{framework: [control_ids]}`` map into full records."""
    out: list[dict] = []
    for fw_key, control_ids in mapping.items():
        fw = FRAMEWORKS.get(fw_key)
        if not fw:
            continue
        for cid in control_ids:
            ctrl = fw.controls.get(cid)
            if ctrl:
                out.append({
                    "framework": fw.key, "framework_name": fw.name,
                    "control": ctrl.id, "title": ctrl.title, "summary": ctrl.summary,
                })
    return out


def coverage_report(detector_mappings: dict[str, dict[str, list[str]]],
                    evidence_counts: dict[str, int] | None = None) -> dict:
    """Build the auditor-facing coverage report.

    ``detector_mappings`` maps detector key → ``{framework: [control_ids]}``.
    ``evidence_counts`` maps detector key → number of alerts it fired in the
    reporting window, which becomes the "evidence" column.
    """
    evidence_counts = evidence_counts or {}

    # control -> detectors providing evidence
    by_control: dict[tuple[str, str], list[str]] = {}
    for detector, mapping in detector_mappings.items():
        for fw_key, control_ids in mapping.items():
            for cid in control_ids:
                by_control.setdefault((fw_key, cid), []).append(detector)
    for fw_key, control_ids in BASELINE_CONTROLS.items():
        for cid in control_ids:
            by_control.setdefault((fw_key, cid), [])

    frameworks = []
    for fw in FRAMEWORKS.values():
        controls = []
        for ctrl in fw.controls.values():
            detectors = sorted(set(by_control.get((fw.key, ctrl.id), [])))
            baseline = ctrl.id in BASELINE_CONTROLS.get(fw.key, [])
            evidence = sum(evidence_counts.get(d, 0) for d in detectors)
            if baseline and not detectors:
                status = "monitored"
            elif detectors:
                status = "covered"
            else:
                status = "gap"
            controls.append({
                "control": ctrl.id,
                "title": ctrl.title,
                "summary": ctrl.summary,
                "detectors": detectors,
                "status": status,
                "evidence_alerts": evidence,
            })
        covered = sum(1 for c in controls if c["status"] != "gap")
        frameworks.append({
            "key": fw.key,
            "name": fw.name,
            "authority": fw.authority,
            "description": fw.description,
            "controls": controls,
            "covered": covered,
            "total": len(controls),
            "coverage_pct": round(100 * covered / len(controls), 1) if controls else 0.0,
            "gaps": [c["control"] for c in controls if c["status"] == "gap"],
        })

    frameworks.sort(key=lambda f: -f["coverage_pct"])
    total_controls = sum(f["total"] for f in frameworks)
    total_covered = sum(f["covered"] for f in frameworks)
    return {
        "frameworks": frameworks,
        "total_controls": total_controls,
        "total_covered": total_covered,
        "overall_pct": round(100 * total_covered / total_controls, 1) if total_controls else 0.0,
    }
