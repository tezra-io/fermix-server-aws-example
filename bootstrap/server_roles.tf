# The roles server/ uses, made here with the owner's sign-in so their trust is
# fixed: IAM cannot hold a trust policy's contents to a condition, so a role
# the deploy role could create could trust anything. The instance role and
# DLM's each trust one service and carry the server roles' boundary
# (workload.tf). server/ reads them by name; the deploy role passes each to its
# one service, attaches the CloudWatch agent's policy to the instance role with
# enable_cloudwatch_agent, and may write the S3 backups' inline policy on it,
# and nothing more (permissions.tf). The snapshot writer is assumed by the
# instance role alone, and only while server/ grants it (enable_s3_backups).

resource "aws_iam_role" "instance" {
  name                 = local.instance_role
  path                 = local.iam_path
  description          = "fermix-server: the instance's role. Session Manager; with enable_cloudwatch_agent, the CloudWatch agent; with enable_s3_backups, the snapshot writer."
  permissions_boundary = local.workload_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  depends_on = [aws_iam_policy.workload]
}

resource "aws_iam_role_policy_attachment" "instance_ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = local.ssm_core_policy
}

resource "aws_iam_instance_profile" "instance" {
  name = local.instance_role
  path = local.iam_path
  role = aws_iam_role.instance.name
}

# EBS snapshots: Data Lifecycle Manager's service role, for this account's
# policies only.
resource "aws_iam_role" "dlm" {
  name                 = local.dlm_role
  path                 = local.iam_path
  description          = "fermix-server: Data Lifecycle Manager snapshots the root volume."
  permissions_boundary = local.workload_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "dlm.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
    }]
  })

  depends_on = [aws_iam_policy.workload]
}

resource "aws_iam_role_policy_attachment" "dlm" {
  role       = aws_iam_role.dlm.name
  policy_arn = local.dlm_service_policy
}

# S3 backups: the session the server's credentials helper (Fermix's first boot, a root
# timer) hands the engine, which never reaches the metadata service itself.
# It puts objects into the snapshot bucket and nothing else: it cannot read,
# list or delete one, and holds none of the instance role's other rights. The
# trust names the account, so a caller needs a grant of its own as well, and
# only the instance role may use it: server/ writes that grant with
# enable_s3_backups, and without it no one can assume this role. A session of
# a role assumed with another role's credentials lasts an hour at most. No
# boundary: bootstrap alone writes this role, and the deploy role's boundary
# refuses every IAM write on it.
resource "aws_iam_role" "snapshot_writer" {
  name                 = local.snapshot_writer_role
  path                 = local.iam_path
  description          = "fermix-server: Fermix's snapshots into the snapshot bucket, assumed by the instance role."
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = { ArnEquals = { "aws:PrincipalArn" = local.instance_role_arn } }
    }]
  })
}

resource "aws_iam_role_policy" "snapshot_writer" {
  name   = "snapshot-bucket"
  role   = aws_iam_role.snapshot_writer.name
  policy = data.aws_iam_policy_document.snapshot_writer.json
}

data "aws_iam_policy_document" "snapshot_writer" {
  # The bucket's name is predictable and S3's names are global: while the
  # owner's bucket does not exist (enable_s3_backups off, or after a
  # teardown), another account could make one of that name. Only a bucket of
  # this account takes the snapshots; the engine also names the owner it
  # expects on every upload (x-amz-expected-bucket-owner).
  statement {
    sid       = "PutSnapshots"
    actions   = ["s3:PutObject"]
    resources = ["arn:${local.partition}:s3:::${local.snapshot_bucket}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:ResourceAccount"
      values   = [local.account_id]
    }
  }

  # The bucket encrypts with the server's key (server/ makes it, so it is named
  # by what S3 asks of it): through S3 in this region, for this bucket alone.
  # With the bucket key on, S3 names the bucket as the encryption context.
  statement {
    sid       = "EncryptThroughS3"
    actions   = ["kms:GenerateDataKey"]
    resources = ["arn:${local.partition}:kms:${var.region}:${local.account_id}:key/*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values = [
        "arn:${local.partition}:s3:::${local.snapshot_bucket}",
        "arn:${local.partition}:s3:::${local.snapshot_bucket}/*",
      ]
    }
  }
}
