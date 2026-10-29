#!/usr/bin/env python3
"""Regression scan for the IIS cert automation repos. Exits 1 if a fixed bug returns."""

from __future__ import annotations

import json
import sys
from pathlib import Path

RULES = [
    ("PS-001", "error", "password-in-script", "${plainPassword}", "PFX password interpolated into a generated script"),
    ("PS-003", "error", "executionpolicy-bypass", "-ExecutionPolicy Bypass", "Scheduled task bypasses execution policy"),
    ("PS-005", "error", "curl-insecure", '-k $healthUrl', "Health check disables TLS by default"),
    ("PS-008", "error", "persisted-keyset", "DefaultKeySet", "PFX verify imports a persisted private key"),
    ("PS-004", "error", "internal-host", "devops.local", "Internal lab host left in source"),
    ("PS-004b", "error", "internal-host", "ocplab.net", "Internal lab host left in source"),
    ("PS-004c", "error", "internal-host", "labwinadm", "Internal lab host left in source"),
]

SKIP_PARTS = {".git", "bin", "obj", "artifacts", "archive"}
TEXT_SUFFIXES = {".ps1", ".bat", ".cs", ".json", ".yml", ".py"}


def scan(root: Path) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if path.name == "static_scan.py" or SKIP_PARTS.intersection(path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for rule_id, level, name, needle, message in RULES:
            if needle in text:
                line_no = text[: text.index(needle)].count("\n") + 1
                hits.append(
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "name": name,
                        "message": message,
                        "path": str(path.relative_to(root)).replace("\\", "/"),
                        "line": str(line_no),
                    }
                )
    return hits


def sarif(hits: list[dict[str, str]]) -> dict:
    rules = []
    seen = set()
    for hit in hits:
        if hit["ruleId"] in seen:
            continue
        seen.add(hit["ruleId"])
        rules.append(
            {
                "id": hit["ruleId"],
                "shortDescription": {"text": hit["name"]},
                "defaultConfiguration": {"level": hit["level"]},
            }
        )
    results = [
        {
            "ruleId": hit["ruleId"],
            "level": hit["level"],
            "message": {"text": hit["message"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": hit["path"]},
                        "region": {"startLine": int(hit["line"])},
                    }
                }
            ],
        }
        for hit in hits
    ]
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "iis-cert-static-scan",
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: static_scan.py ROOT SARIF_OUT", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    hits = scan(root)
    Path(sys.argv[2]).write_text(json.dumps(sarif(hits), indent=2) + "\n", encoding="utf-8")
    print(f"{root}: {len(hits)} open regression hit(s)")
    for hit in hits:
        print(f"  {hit['ruleId']} {hit['path']}:{hit['line']} {hit['message']}")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
