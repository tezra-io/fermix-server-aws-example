# The server's key: the root volume and its EBS snapshots, the snapshot
# bucket, and the alert topic. The account administers it through IAM, which
# is how the deploy role reaches it (only while it carries the server stack's
# tag). Two services are named in the key policy itself, each only when its
# part of the stack exists.

resource "aws_kms_key" "server" {
  description             = "fermix-server: the root volume, its snapshots, the snapshot bucket and the alert topic"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = jsonencode({ Version = "2012-10-17", Statement = local.key_statements })

  tags = local.tags
}

resource "aws_kms_alias" "server" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.server.key_id
}

locals {
  key_statements = concat(
    [{
      Sid       = "AccountAdministersThroughIam"
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }],
    # CloudWatch alarms publish to the encrypted topic. AWS's own aws/sns key
    # cannot be used: CloudWatch cannot publish to a topic encrypted with it.
    local.alerts ? [{
      Sid       = "CloudWatchPublishesToTheAlertTopic"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
      Resource  = "*"
    }] : [],
    # DLM snapshots an encrypted volume as its own role, which needs the key
    # through EC2; the role holds only AWS's DLM policy, so the grant is here.
    var.enable_ebs_snapshots ? [{
      Sid       = "DlmSnapshotsTheRootVolume"
      Effect    = "Allow"
      Principal = { AWS = data.aws_iam_role.dlm.arn }
      Action = [
        "kms:CreateGrant",
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:ReEncryptFrom",
        "kms:ReEncryptTo",
      ]
      Resource  = "*"
      Condition = { StringEquals = { "kms:ViaService" = "ec2.${local.region}.amazonaws.com" } }
    }] : [],
  )
}
