# The server roles' boundary: the ceiling on the instance role and DLM's
# service role (server_roles.tf). Whatever either is given, by bootstrap or by
# the deploy role (the CloudWatch agent's policy, the S3 backups' inline
# policy), it never holds more than this: Session Manager's agent, the
# CloudWatch agent's metrics, DLM's snapshots of the server stack's volume,
# and assuming the snapshot writer. The bucket's own rights are never here:
# they live in the snapshot writer's session alone, so the instance role
# cannot hold them itself.

resource "aws_iam_policy" "workload" {
  name        = local.workload_boundary_name
  path        = "/"
  description = "The permissions boundary of every role fermix-server-aws server/ creates."
  policy      = data.aws_iam_policy_document.workload.json
}

locals {
  workload_boundary_name = "fermix-server-workload-boundary"
  workload_boundary_arn  = "arn:${local.partition}:iam::${local.account_id}:policy/${local.workload_boundary_name}"
}

data "aws_iam_policy_document" "workload" {
  # AmazonSSMManagedInstanceCore's actions.
  statement {
    sid = "SessionManagerAgent"
    actions = [
      "ssm:DescribeAssociation",
      "ssm:GetDeployablePatchSnapshotForInstance",
      "ssm:GetDocument",
      "ssm:DescribeDocument",
      "ssm:GetManifest",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:ListAssociations",
      "ssm:ListInstanceAssociations",
      "ssm:PutInventory",
      "ssm:PutComplianceItems",
      "ssm:PutConfigurePackageResult",
      "ssm:UpdateAssociationStatus",
      "ssm:UpdateInstanceAssociationStatus",
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply",
    ]
    resources = ["*"]
  }

  # The CloudWatch agent sends metrics only, into its own namespace.
  statement {
    sid       = "CloudWatchAgentMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CWAgent"]
    }
  }

  statement {
    sid       = "CloudWatchAgentReads"
    actions   = ["ec2:DescribeVolumes", "ec2:DescribeTags"]
    resources = ["*"]
  }

  # EBS snapshots: AWSDataLifecycleManagerServiceRole's actions for a schedule of
  # snapshots in this region, held to the server stack: a snapshot only of a
  # volume carrying the tag, only carrying it itself (the policy copies the
  # volume's tags and adds it), and a deletion only of a snapshot carrying it.
  # Never sharing one.
  statement {
    sid = "DlmReads"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeSnapshotAttribute",
      "ec2:DescribeAvailabilityZones",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }
  }

  statement {
    sid     = "DlmSnapshotsTaggedVolumes"
    actions = ["ec2:CreateSnapshot", "ec2:CreateSnapshots"]
    resources = [
      "arn:${local.partition}:ec2:${var.region}:${local.account_id}:volume/*",
      "arn:${local.partition}:ec2:${var.region}:${local.account_id}:instance/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  statement {
    sid       = "DlmCreatesTaggedSnapshots"
    actions   = ["ec2:CreateSnapshot", "ec2:CreateSnapshots"]
    resources = ["arn:${local.partition}:ec2:${var.region}::snapshot/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  statement {
    sid       = "DlmDeletesTaggedSnapshots"
    actions   = ["ec2:DeleteSnapshot"]
    resources = ["arn:${local.partition}:ec2:${var.region}::snapshot/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${local.stack_tag_key}"
      values   = [local.server_tag]
    }
  }

  statement {
    sid       = "DlmTagsItsSnapshots"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${local.partition}:ec2:${var.region}::snapshot/*"]
  }

  statement {
    sid = "DlmRules"
    actions = [
      "events:PutRule",
      "events:DeleteRule",
      "events:DescribeRule",
      "events:EnableRule",
      "events:DisableRule",
      "events:ListTargetsByRule",
      "events:PutTargets",
      "events:RemoveTargets",
    ]
    resources = ["arn:${local.partition}:events:${var.region}:${local.account_id}:rule/AwsDataLifecycleRule.managed-cwe.*"]
  }

  # The server key's policy grants DLM's role these, through EC2; a boundary
  # limits a grant made to a role's ARN, so they are named here too.
  statement {
    sid = "DlmUsesTheServerKeyThroughEc2"
    actions = [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = ["arn:${local.partition}:kms:${var.region}:${local.account_id}:key/*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ec2.${var.region}.amazonaws.com"]
    }
  }

  # S3 backups: the instance role's grant, which server/ writes with
  # enable_s3_backups, on the snapshot writer alone (server_roles.tf).
  statement {
    sid       = "AssumeTheSnapshotWriter"
    actions   = ["sts:AssumeRole"]
    resources = [local.snapshot_writer_role_arn]
  }

  statement {
    sid       = "NeverShareASnapshot"
    effect    = "Deny"
    actions   = ["ec2:ModifySnapshotAttribute"]
    resources = ["*"]
  }
}
