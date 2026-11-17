"""The incident report the agent must produce, and the check that keeps it honest.

The model is constrained to this schema, so a report always parses. What a
schema cannot guarantee is that the report is true. ``check_report`` therefore
looks up every cited flow in the capture: it must exist, it must involve the
addresses the finding names, and at least one cited flow must connect an
attacker to a victim. A finding that fails goes back to the agent once and is
removed if it fails again.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .. import store

AttackType = Literal["brute_force", "dos", "port_scan", "web_attack", "botnet", "other"]
MAX_CITED_FLOWS = 2000


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(_Strict):
    claim: str = Field(description="One factual statement the cited flows show, with numbers where you have them.")
    flow_ids: list[int] = Field(
        description="3 to 10 flow_id values, taken from tool results, of flows that show this claim."
    )


class Finding(_Strict):
    title: str = Field(description="Short name of what happened, e.g. 'SSH password guessing against 192.168.10.50'.")
    attack_type: AttackType
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"] = Field(
        description="How sure you are that this is malicious and correctly identified."
    )
    attacker_ips: list[str] = Field(description="Addresses that carried out the activity.")
    victim_ips: list[str] = Field(description="Addresses it was aimed at. List the main ones if there are many.")
    first_seen: str = Field(description="When the activity starts, ISO 8601, e.g. 2017-07-04T12:17:52.")
    last_seen: str = Field(description="When the activity ends, ISO 8601.")
    description: str = Field(description="What happened and why it is malicious, in a few sentences.")
    evidence: list[Evidence] = Field(description="One to five evidence items. Every claim needs cited flows.")


class Report(_Strict):
    verdict: Literal["malicious_activity", "no_malicious_activity", "inconclusive"]
    summary: str = Field(description="Two to four sentences an on-call analyst can act on.")
    findings: list[Finding] = Field(description="One per distinct attack. Empty if nothing malicious was found.")
    limitations: list[str] = Field(description="What you could not check or are unsure about.")


@dataclass
class FindingCheck:
    index: int
    title: str
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip())
        return True
    except ValueError:
        return False


def _parse_time(text: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


def check_report(report: Report, capture_id: str) -> list[FindingCheck]:
    """Verify every finding's evidence against the capture. One check per finding, in order."""
    cited = sorted({i for f in report.findings for e in f.evidence for i in e.flow_ids if isinstance(i, int)})
    flows: dict[int, tuple[str, str]] = {}
    con = store.connect_readonly(capture_id)
    try:
        first_ts, last_ts = con.execute("SELECT min(ts), max(ts) FROM flows").fetchone()
        for start in range(0, min(len(cited), MAX_CITED_FLOWS), 500):
            ids = ", ".join(str(i) for i in cited[start:start + 500])
            for flow_id, src, dst in con.execute(
                f"SELECT flow_id, src_ip, dst_ip FROM flows WHERE flow_id IN ({ids})"
            ).fetchall():
                flows[flow_id] = (src, dst)
    finally:
        con.close()

    checks = []
    for index, finding in enumerate(report.findings):
        check = FindingCheck(index=index, title=finding.title)
        ids = [i for e in finding.evidence for i in e.flow_ids]
        if not finding.evidence:
            check.problems.append("It has no evidence.")
        for number, item in enumerate(finding.evidence, start=1):
            if not item.flow_ids:
                check.problems.append(f"Evidence item {number} cites no flows.")
        missing = sorted({i for i in ids if i not in flows})
        if missing:
            check.problems.append(f"These flow ids are not in the capture: {missing[:10]}.")
        if len(cited) > MAX_CITED_FLOWS:
            check.problems.append(f"The report cites more than {MAX_CITED_FLOWS} flows; cite a few per claim.")

        found = [flows[i] for i in ids if i in flows]
        seen_addresses = {address for pair in found for address in pair}
        if not finding.attacker_ips:
            check.problems.append("It names no attacker address.")
        for role, addresses in (("attacker", finding.attacker_ips), ("victim", finding.victim_ips)):
            for address in addresses:
                if not _valid_ip(address):
                    check.problems.append(f"{address!r} is not an IP address.")
                elif address.strip() not in seen_addresses:
                    check.problems.append(f"No cited flow involves the {role} {address}.")
        attackers = {a.strip() for a in finding.attacker_ips}
        victims = {v.strip() for v in finding.victim_ips}
        if attackers and victims and found and not any(
            (src in attackers and dst in victims) or (src in victims and dst in attackers) for src, dst in found
        ):
            check.problems.append("No cited flow connects a named attacker with a named victim.")

        start, end = _parse_time(finding.first_seen), _parse_time(finding.last_seen)
        if start is None or end is None:
            check.problems.append("first_seen and last_seen must be ISO 8601 timestamps.")
        elif start > end:
            check.problems.append("first_seen is later than last_seen.")
        elif first_ts and (end < first_ts - timedelta(seconds=1) or start > last_ts + timedelta(seconds=1)):
            check.problems.append(f"Its time span lies outside the capture ({first_ts} to {last_ts}).")
        checks.append(check)
    return checks


def drop_failed(report: Report, checks: list[FindingCheck]) -> Report:
    """The report without the findings that failed the check."""
    failed = {c.index for c in checks if not c.ok}
    if not failed:
        return report
    kept = [f for i, f in enumerate(report.findings) if i not in failed]
    limitations = [
        *report.limitations,
        f"{len(failed)} finding(s) were removed automatically because their evidence could not be verified.",
    ]
    verdict = report.verdict
    if verdict == "malicious_activity" and not kept:
        verdict = "inconclusive"
        limitations.append("The verdict was lowered to inconclusive because no finding survived the evidence check.")
    return report.model_copy(update={"findings": kept, "limitations": limitations, "verdict": verdict})
