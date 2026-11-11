#!/usr/bin/env python3
"""Local physical-line guard for every tracked or unignored Python source."""

import argparse
import ast
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    path: str
    name: str
    line: int
    size: int

    @property
    def key(self) -> str:
        return f"{self.path}:{self.name}"


class FunctionVisitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.scope: list[str] = []
        self.findings: list[Finding] = []

    def visit_ClassDef(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def _function(self, node, name):
        self.scope.append(name)
        self.findings.append(
            Finding(
                self.path,
                ".".join(self.scope),
                node.lineno,
                node.end_lineno - node.lineno + 1,
            )
        )
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node):
        self._function(node, node.name)

    def visit_AsyncFunctionDef(self, node):
        self._function(node, node.name)

    def visit_Lambda(self, node):
        self._function(node, f"<lambda>@{node.lineno}")


def scan_source(source: str, path: str) -> list[Finding]:
    visitor = FunctionVisitor(path)
    visitor.visit(ast.parse(source, filename=path))
    return visitor.findings


def project_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "*.py",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [root / name for name in sorted(set(completed.stdout.split("\0"))) if name]


def scan_project(root: Path) -> list[Finding]:
    return [
        finding
        for path in project_files(root)
        for finding in scan_source(
            path.read_text(encoding="utf-8"), path.relative_to(root).as_posix()
        )
    ]


def violations(findings: list[Finding], reasons: dict[str, str]) -> list[str]:
    errors = []
    preferred = {finding.key for finding in findings if 30 < finding.size <= 60}
    for finding in findings:
        if finding.size > 60:
            errors.append(f"{finding.key}: {finding.size} lines exceeds hard limit 60")
        elif finding.size > 30 and not reasons.get(finding.key, "").strip():
            errors.append(f"{finding.key}: missing cohesion justification")
    for key in sorted(set(reasons) - preferred):
        errors.append(f"{key}: stale justification")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quiet", action="store_true", help="Print only the summary on success."
    )
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    reasons = json.loads((root / "docs/function_size_justifications.json").read_text())
    findings = scan_project(root)
    errors = violations(findings, reasons)
    if not args.quiet:
        for finding in findings:
            if 30 < finding.size <= 60:
                print(
                    f"{finding.key}: {finding.size} lines; {reasons.get(finding.key, 'UNJUSTIFIED')}"
                )
    for error in errors:
        print(error)
    preferred = sum(finding.size <= 30 for finding in findings)
    print(
        f"Functions: {len(findings)}; <=30 lines: {preferred}; >60 lines: {sum(f.size > 60 for f in findings)}"
    )
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
