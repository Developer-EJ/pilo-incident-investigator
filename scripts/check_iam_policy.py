"""Fail-closed static guardrails for the Terraform ownership and IAM boundary."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

_ACTIONS_ASSIGNMENT = re.compile(
    r"\b(?:actions|Action)\s*=\s*\[(?P<body>[^\]]*)\]", re.DOTALL | re.IGNORECASE
)
_ACTION_LITERAL = re.compile(r'"(?P<action>[a-z0-9-]+:[A-Za-z*?][A-Za-z0-9*?]*)"', re.IGNORECASE)
_RESOURCE_DECLARATION = re.compile(r'\bresource\s+"(?P<type>[A-Za-z0-9_]+)"')
_STATEMENT_START = re.compile(r"\bstatement\s*\{")
_STAR_RESOURCE = re.compile(r'\bresources\s*=\s*\[[^\]]*"\*"', re.DOTALL)

_ALLOWED_PILO_ACTIONS = frozenset(
    {
        "ecs:DescribeServices",
        "ecs:DescribeTasks",
        "ecs:ListTasks",
        "elasticloadbalancing:DescribeTargetHealth",
        "logs:FilterLogEvents",
        "rds:DescribeDBInstances",
        "rds:DescribeEvents",
        "secretsmanager:DescribeSecret",
        "sqs:GetQueueAttributes",
    }
)
_ALLOWED_PILO_ACTIONS_NORMALIZED = frozenset(action.casefold() for action in _ALLOWED_PILO_ACTIONS)
_PILO_SERVICE_PREFIXES = frozenset({"ecs", "elasticloadbalancing", "rds", "secretsmanager", "sqs"})
_RESOURCE_SCOPED_READS = _ALLOWED_PILO_ACTIONS_NORMALIZED - {
    "ecs:listtasks",
    "rds:describeevents",
}
_UNAVOIDABLE_STAR_READS = frozenset({"ecs:listtasks", "rds:describeevents"})
_FORBIDDEN_RESOURCE_PREFIXES = (
    "aws_alb_",
    "aws_db_",
    "aws_ecs_",
    "aws_lb",
    "aws_rds_",
    "aws_secretsmanager_",
    "aws_sqs_",
)
_FORBIDDEN_RESOURCE_TYPES = frozenset(
    {
        "aws_cloudwatch_metric_alarm",
        "aws_ssm_parameter",
        "github_repository",
    }
)


@dataclass(frozen=True, slots=True)
class Finding:
    path: Path
    line: int
    message: str


def scan_terraform(root: Path) -> tuple[Finding, ...]:
    if not root.is_dir():
        return (Finding(root, 1, "Terraform module directory does not exist"),)
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.tf")):
        source = path.read_text(encoding="utf-8")
        findings.extend(_scan_resources(path, source))
        findings.extend(_scan_actions(path, source))
        findings.extend(_scan_statements(path, source))
    return tuple(sorted(set(findings), key=lambda item: (str(item.path), item.line, item.message)))


def _scan_resources(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in _RESOURCE_DECLARATION.finditer(source):
        resource_type = match.group("type")
        if resource_type in _FORBIDDEN_RESOURCE_TYPES or resource_type.startswith(
            _FORBIDDEN_RESOURCE_PREFIXES
        ):
            findings.append(
                Finding(
                    path,
                    _line_number(source, match.start()),
                    f"forbidden Terraform resource {resource_type}",
                )
            )
    return findings


def _scan_actions(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for action, offset in _actions(source):
        normalized = action.casefold()
        service = normalized.split(":", 1)[0]
        forbidden = normalized == "secretsmanager:getsecretvalue" or (
            service in _PILO_SERVICE_PREFIXES and normalized not in _ALLOWED_PILO_ACTIONS_NORMALIZED
        )
        if forbidden:
            findings.append(
                Finding(
                    path,
                    _line_number(source, offset),
                    f"forbidden IAM action {action}",
                )
            )
    return findings


def _scan_statements(path: Path, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for start, block in _statement_blocks(source):
        actions = {action.casefold(): action for action, _ in _actions(block)}
        if _STAR_RESOURCE.search(block) is None:
            continue
        line = _line_number(source, start)
        for normalized in sorted(actions.keys() & _RESOURCE_SCOPED_READS):
            action = actions[normalized]
            findings.append(
                Finding(path, line, f"PILO read action {action} uses wildcard Resource")
            )
        for normalized in sorted(actions.keys() & _UNAVOIDABLE_STAR_READS):
            action = actions[normalized]
            if not _has_region_condition(block):
                findings.append(
                    Finding(
                        path,
                        line,
                        f"wildcard {action} lacks aws:RequestedRegion=ap-northeast-2",
                    )
                )
            if normalized == "ecs:listtasks" and "ecs:cluster" not in block.casefold():
                findings.append(
                    Finding(path, line, "wildcard ecs:ListTasks lacks ecs:cluster condition")
                )
    return findings


def _actions(source: str) -> tuple[tuple[str, int], ...]:
    actions: list[tuple[str, int]] = []
    for assignment in _ACTIONS_ASSIGNMENT.finditer(source):
        body = assignment.group("body")
        body_offset = assignment.start("body")
        for match in _ACTION_LITERAL.finditer(body):
            actions.append((match.group("action"), body_offset + match.start()))
    return tuple(actions)


def _statement_blocks(source: str) -> tuple[tuple[int, str], ...]:
    blocks: list[tuple[int, str]] = []
    for match in _STATEMENT_START.finditer(source):
        depth = 1
        index = match.end()
        in_string = False
        escaped = False
        while index < len(source) and depth:
            character = source[index]
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
            elif character == '"':
                in_string = True
            elif character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
            index += 1
        if depth == 0:
            blocks.append((match.start(), source[match.start() : index]))
    return tuple(blocks)


def _has_region_condition(block: str) -> bool:
    return "aws:RequestedRegion" in block and '"ap-northeast-2"' in block


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Terraform IAM and ownership guardrails")
    parser.add_argument("root", type=Path)
    args = parser.parse_args(argv)
    findings = scan_terraform(args.root)
    for finding in findings:
        print(f"{finding.path}:{finding.line}: {finding.message}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
