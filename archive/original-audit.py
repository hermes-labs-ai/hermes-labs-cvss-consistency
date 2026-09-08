#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from cpe import CPE
from cvss import CVSS3, CVSS4

CISA_ORG = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
SSVC_ALLOWED = {
    "Exploitation": {"none", "poc", "active"},
    "Automatable": {"no", "yes"},
    "Technical Impact": {"partial", "total"},
}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def cwe_catalog(zip_path: Path):
    import zipfile
    with zipfile.ZipFile(zip_path) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".xml"))
        root = ET.fromstring(zf.read(name))
    ns = {"c": "http://cwe.mitre.org/cwe-7"}
    weaknesses = {"CWE-" + e.attrib["ID"] for e in root.findall(".//c:Weakness", ns)}
    categories = {"CWE-" + e.attrib["ID"] for e in root.findall(".//c:Category", ns)}
    views = {"CWE-" + e.attrib["ID"] for e in root.findall(".//c:View", ns)}
    return weaknesses, categories, views, root.attrib.get("Version"), root.attrib.get("Date")


def open_issue_cves(path: Path):
    issues = json.loads(path.read_text())
    ids = set()
    for issue in issues:
        if "pull_request" in issue:
            continue
        text = f"{issue.get('title','')}\n{issue.get('body','')}"
        ids.update(x.upper() for x in CVE_RE.findall(text))
    return ids


def cisa_adps(record):
    for adp in record.get("containers", {}).get("adp", []):
        meta = adp.get("providerMetadata", {})
        if meta.get("orgId") == CISA_ORG or meta.get("shortName") == "CISA-ADP":
            yield adp


def cisa_refs(adp):
    for ref in adp.get("references", []):
        url = ref.get("url")
        if isinstance(url, str):
            yield url


def walk_values(obj, key):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            yield from walk_values(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_values(v, key)


def audit_metric(cve, path, metric, findings, stats):
    for key, value in metric.items():
        if key in {"cvssV3_0", "cvssV3_1"}:
            stats["cvss3_checked"] += 1
            vector = value.get("vectorString")
            stated = value.get("baseScore")
            try:
                computed = float(CVSS3(vector).scores()[0])
                if stated is None or abs(float(stated) - computed) > 1e-9:
                    findings.append({"cve": cve, "path": path, "check": "cvss_score", "metric": key, "stated": stated, "computed": computed, "vector": vector})
            except Exception as exc:
                findings.append({"cve": cve, "path": path, "check": "cvss_vector_parse", "metric": key, "vector": vector, "error": f"{type(exc).__name__}: {exc}"})
        elif key == "cvssV4_0":
            stats["cvss4_checked"] += 1
            vector = value.get("vectorString")
            stated = value.get("baseScore")
            try:
                computed = float(CVSS4(vector).scores()[0])
                if stated is None or abs(float(stated) - computed) > 1e-9:
                    findings.append({"cve": cve, "path": path, "check": "cvss_score", "metric": key, "stated": stated, "computed": computed, "vector": vector})
            except Exception as exc:
                findings.append({"cve": cve, "path": path, "check": "cvss_vector_parse", "metric": key, "vector": vector, "error": f"{type(exc).__name__}: {exc}"})
        elif key == "other" and value.get("type", "").lower() == "ssvc":
            stats["ssvc_checked"] += 1
            content = value.get("content", {})
            options = content.get("options")
            seen = {}
            if not isinstance(options, list):
                findings.append({"cve": cve, "path": path, "check": "ssvc_options_shape", "value": options})
                continue
            for item in options:
                if not isinstance(item, dict):
                    findings.append({"cve": cve, "path": path, "check": "ssvc_option_shape", "value": item})
                    continue
                for name, option in item.items():
                    seen.setdefault(name, []).append(option)
                    allowed = SSVC_ALLOWED.get(name)
                    if allowed is None or option not in allowed:
                        findings.append({"cve": cve, "path": path, "check": "ssvc_vocabulary", "decision": name, "value": option})
            for name in SSVC_ALLOWED:
                if len(seen.get(name, [])) != 1:
                    findings.append({"cve": cve, "path": path, "check": "ssvc_cardinality", "decision": name, "count": len(seen.get(name, []))})
            if content.get("id") != cve:
                findings.append({"cve": cve, "path": path, "check": "ssvc_id", "value": content.get("id")})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", type=Path)
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--cwe-zip", required=True, type=Path)
    parser.add_argument("--open-issues", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    since, until = dt(args.since), dt(args.until)
    weaknesses, categories, views, cwe_version, cwe_date = cwe_catalog(args.cwe_zip)
    issue_cves = open_issue_cves(args.open_issues)
    stats = {"json_seen": 0, "eligible_records": 0, "excluded_kernel": 0, "excluded_open_issue": 0, "cvss3_checked": 0, "cvss4_checked": 0, "cwe_checked": 0, "cpe_checked": 0, "ssvc_checked": 0}
    findings = []
    invalid_json = []

    paths = []
    for year_dir in args.repo.iterdir():
        if year_dir.is_dir() and re.fullmatch(r"\d{4}", year_dir.name):
            paths.extend(year_dir.rglob("*.json"))
    for path in sorted(paths):
        stats["json_seen"] += 1
        rel = str(path.relative_to(args.repo))
        try:
            record = json.loads(path.read_text())
        except Exception as exc:
            invalid_json.append({"path": rel, "error": f"{type(exc).__name__}: {exc}"})
            continue
        cve = record.get("cveMetadata", {}).get("cveId", path.stem)
        for adp in cisa_adps(record):
            updated_raw = adp.get("providerMetadata", {}).get("dateUpdated")
            if not updated_raw:
                continue
            updated = dt(updated_raw)
            if not (since <= updated <= until):
                continue
            refs = list(cisa_refs(adp))
            cna = record.get("containers", {}).get("cna", {})
            all_urls = refs + [x for x in walk_values(cna.get("references", []), "url") if isinstance(x, str)]
            if any("kernel.org" in url.lower() for url in all_urls):
                stats["excluded_kernel"] += 1
                continue
            if cve.upper() in issue_cves:
                stats["excluded_open_issue"] += 1
                continue
            stats["eligible_records"] += 1
            for metric in adp.get("metrics", []):
                audit_metric(cve, rel, metric, findings, stats)

            for problem_types in adp.get("problemTypes", []):
                for desc in problem_types.get("descriptions", []):
                    cwe = desc.get("cweId")
                    if not isinstance(cwe, str) or not cwe.startswith("CWE-"):
                        continue
                    stats["cwe_checked"] += 1
                    if cwe in categories:
                        findings.append({"cve": cve, "path": rel, "check": "cwe_is_category", "cwe": cwe, "description": desc.get("description")})
                    elif cwe in views:
                        findings.append({"cve": cve, "path": rel, "check": "cwe_is_view", "cwe": cwe, "description": desc.get("description")})
                    elif cwe not in weaknesses:
                        findings.append({"cve": cve, "path": rel, "check": "cwe_unknown", "cwe": cwe, "description": desc.get("description")})

            for cpes in walk_values(adp, "cpes"):
                if not isinstance(cpes, list):
                    continue
                for value in cpes:
                    if not isinstance(value, str):
                        continue
                    stats["cpe_checked"] += 1
                    try:
                        CPE(value)
                    except Exception as exc:
                        findings.append({"cve": cve, "path": rel, "check": "cpe_parse", "cpe": value, "error": f"{type(exc).__name__}: {exc}"})
            for value in walk_values(adp, "criteria"):
                if not isinstance(value, str) or not value.startswith("cpe:"):
                    continue
                stats["cpe_checked"] += 1
                try:
                    CPE(value)
                except Exception as exc:
                    findings.append({"cve": cve, "path": rel, "check": "cpe_parse", "cpe": value, "error": f"{type(exc).__name__}: {exc}"})

    findings.sort(key=lambda x: (x["cve"], x["check"], json.dumps(x, sort_keys=True)))
    payload = {
        "contract": {"snapshot": "b4481a9ea6cbb1e36ba9a746ef29de45b95567f8", "since": args.since, "until": args.until, "checks": ["CVSS vector/base-score agreement", "CWE current-catalog existence and entry type", "CPE parser acceptance", "SSVC vocabulary/cardinality/id"], "exclusions": ["kernel.org references", "CVE named by an open vulnrichment issue", "judgment-only findings"]},
        "catalog": {"cwe_version": cwe_version, "cwe_date": cwe_date, "sha256": hashlib.sha256(args.cwe_zip.read_bytes()).hexdigest()},
        "stats": stats,
        "invalid_json": invalid_json,
        "findings": findings,
    }
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"stats": stats, "invalid_json": len(invalid_json), "findings": len(findings), "by_check": {k: sum(f["check"] == k for f in findings) for k in sorted({f["check"] for f in findings})}}, indent=2))


if __name__ == "__main__":
    main()
