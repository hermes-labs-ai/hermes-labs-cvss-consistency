"""Check CVSS v3 metric objects embedded in local CVE 5.x JSON records."""

from __future__ import annotations

from importlib.metadata import version
from math import isfinite
from typing import Any, Iterator

from cvss import CVSS3

SUPPORTED_METRICS = {"cvssV3_0", "cvssV3_1"}
DEPENDENCY_VERSION = version("cvss")


def _pointer(parts: tuple[str, ...]) -> str:
    return "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in parts)


def _metrics(value: Any, parts: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], str, Any]]:
    if isinstance(value, dict):
        for key in sorted(value):
            child = value[key]
            next_parts = parts + (key,)
            if key in SUPPORTED_METRICS:
                yield next_parts, key, child
            yield from _metrics(child, next_parts)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _metrics(child, parts + (str(index),))


def _source(record: dict[str, Any], parts: tuple[str, ...]) -> dict[str, Any]:
    containers = record.get("containers")
    if not isinstance(containers, dict):
        containers = {}
    if len(parts) >= 2 and parts[:2] == ("containers", "cna"):
        cna = containers.get("cna")
        provider = cna.get("providerMetadata") if isinstance(cna, dict) else {}
        provider = provider if isinstance(provider, dict) else {}
        return {"container": "cna", "index": None, "org_id": provider.get("orgId"), "short_name": provider.get("shortName")}
    if len(parts) >= 3 and parts[:2] == ("containers", "adp") and parts[2].isdigit():
        index = int(parts[2])
        adps = containers.get("adp")
        adps = adps if isinstance(adps, list) else []
        provider = adps[index].get("providerMetadata") if index < len(adps) and isinstance(adps[index], dict) else {}
        provider = provider if isinstance(provider, dict) else {}
        return {"container": "adp", "index": index, "org_id": provider.get("orgId"), "short_name": provider.get("shortName")}
    return {"container": "other", "index": None, "org_id": None, "short_name": None}


def check_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Return stable, JSON-serializable results for every supported CVSS v3 metric."""
    metadata = record.get("cveMetadata")
    cve_id = metadata.get("cveId") if isinstance(metadata, dict) else None
    results: list[dict[str, Any]] = []
    for parts, metric_version, metric in _metrics(record):
        vector = metric.get("vectorString") if isinstance(metric, dict) else None
        stated = metric.get("baseScore") if isinstance(metric, dict) else None
        result: dict[str, Any] = {
            "computed_score": None,
            "cve_id": cve_id,
            "error": None,
            "json_path": _pointer(parts),
            "metric_source": _source(record, parts),
            "metric_version": metric_version,
            "stated_score": stated,
            "status": "invalid",
            "vector": vector,
        }
        try:
            if not isinstance(metric, dict):
                raise ValueError(f"{metric_version} must be an object")
            if not isinstance(vector, str):
                raise ValueError("vectorString must be a string")
            if isinstance(stated, bool) or not isinstance(stated, (int, float)):
                raise ValueError("baseScore must be a number")
            computed = float(CVSS3(vector).scores()[0])
            if not isfinite(float(stated)) or not isfinite(computed):
                raise ValueError("baseScore and computed score must be finite")
            result["computed_score"] = computed
            result["status"] = "consistent" if abs(float(stated) - computed) <= 1e-9 else "mismatch"
        except Exception as exc:
            if isinstance(stated, float) and not isfinite(stated):
                result["stated_score"] = None
            result["error"] = f"{type(exc).__name__}: {exc}"
        results.append(result)
    return sorted(results, key=lambda item: (item["json_path"], item["metric_version"]))
