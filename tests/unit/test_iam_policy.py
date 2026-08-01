from __future__ import annotations

from pathlib import Path

from scripts.check_iam_policy import scan_terraform


def write_module(tmp_path: Path, source: str) -> Path:
    module = tmp_path / "infra"
    module.mkdir()
    (module / "main.tf").write_text(source, encoding="utf-8")
    return module


def messages(module: Path) -> list[str]:
    return sorted(finding.message for finding in scan_terraform(module))


def test_safe_bounded_policy_is_accepted(tmp_path: Path) -> None:
    module = write_module(
        tmp_path,
        """
        data "aws_iam_policy_document" "runtime" {
          statement {
            actions   = ["ecs:DescribeServices"]
            resources = [var.pilo_ecs_service_arns]
          }
          statement {
            actions   = ["rds:DescribeEvents"]
            resources = ["*"]
            condition {
              test     = "StringEquals"
              variable = "aws:RequestedRegion"
              values   = ["ap-northeast-2"]
            }
          }
        }
        """,
    )

    assert scan_terraform(module) == ()


def test_get_secret_value_is_always_rejected(tmp_path: Path) -> None:
    module = write_module(
        tmp_path,
        """
        statement {
          actions   = ["secretsmanager:GetSecretValue"]
          resources = [var.pilo_secret_arns]
        }
        """,
    )

    assert messages(module) == ["forbidden IAM action secretsmanager:GetSecretValue"]


def test_iam_actions_are_checked_case_insensitively(tmp_path: Path) -> None:
    module = write_module(
        tmp_path,
        """
        statement {
          actions = [
            "secretsmanager:getsecretvalue",
            "ecs:updateservice",
          ]
          resources = [var.pilo_resources]
        }
        """,
    )

    assert messages(module) == [
        "forbidden IAM action ecs:updateservice",
        "forbidden IAM action secretsmanager:getsecretvalue",
    ]


def test_iam_action_question_mark_wildcard_is_rejected(tmp_path: Path) -> None:
    module = write_module(
        tmp_path,
        """
        statement {
          actions   = ["ecs:UpdateServic?"]
          resources = ["*"]
        }
        """,
    )

    assert messages(module) == ["forbidden IAM action ecs:UpdateServic?"]


def test_application_mutation_actions_are_rejected(tmp_path: Path) -> None:
    module = write_module(
        tmp_path,
        """
        statement {
          actions = [
            "ecs:UpdateService",
            "rds:RebootDBInstance",
            "elasticloadbalancing:ModifyTargetGroup",
            "sqs:PurgeQueue",
          ]
          resources = [var.resources]
        }
        """,
    )

    assert messages(module) == [
        "forbidden IAM action ecs:UpdateService",
        "forbidden IAM action elasticloadbalancing:ModifyTargetGroup",
        "forbidden IAM action rds:RebootDBInstance",
        "forbidden IAM action sqs:PurgeQueue",
    ]


def test_resource_scopeable_pilo_read_cannot_use_star(tmp_path: Path) -> None:
    module = write_module(
        tmp_path,
        """
        statement {
          actions   = ["logs:FilterLogEvents"]
          resources = ["*"]
        }
        """,
    )

    assert messages(module) == ["PILO read action logs:FilterLogEvents uses wildcard Resource"]


def test_unavoidable_wildcard_requires_explicit_region_and_service_conditions(
    tmp_path: Path,
) -> None:
    module = write_module(
        tmp_path,
        """
        statement {
          actions   = ["rds:DescribeEvents"]
          resources = ["*"]
        }
        statement {
          actions   = ["ecs:ListTasks"]
          resources = ["*"]
          condition {
            variable = "aws:RequestedRegion"
            values   = ["ap-northeast-2"]
          }
        }
        """,
    )

    assert messages(module) == [
        "wildcard ecs:ListTasks lacks ecs:cluster condition",
        "wildcard rds:DescribeEvents lacks aws:RequestedRegion=ap-northeast-2",
    ]


def test_application_resource_ownership_is_rejected(tmp_path: Path) -> None:
    module = write_module(
        tmp_path,
        """
        resource "aws_ecs_service" "app" {}
        resource "aws_db_instance" "app" {}
        resource "aws_lb_target_group" "app" {}
        resource "aws_alb_listener" "app" {}
        resource "aws_sqs_queue" "app" {}
        resource "aws_sqs_queue_policy" "app" {}
        resource "aws_secretsmanager_secret" "app" {}
        resource "aws_ssm_parameter" "credential" {}
        resource "aws_cloudwatch_metric_alarm" "app" {}
        """,
    )

    assert messages(module) == [
        "forbidden Terraform resource aws_alb_listener",
        "forbidden Terraform resource aws_cloudwatch_metric_alarm",
        "forbidden Terraform resource aws_db_instance",
        "forbidden Terraform resource aws_ecs_service",
        "forbidden Terraform resource aws_lb_target_group",
        "forbidden Terraform resource aws_secretsmanager_secret",
        "forbidden Terraform resource aws_sqs_queue",
        "forbidden Terraform resource aws_sqs_queue_policy",
        "forbidden Terraform resource aws_ssm_parameter",
    ]


def test_repository_terraform_passes_policy_scan() -> None:
    root = Path(__file__).parents[2]

    assert scan_terraform(root / "infra") == ()
