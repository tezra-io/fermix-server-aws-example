# The two roles the server uses and the instance profile are bootstrap's
# (bootstrap/server_roles.tf), made with the owner's sign-in so their trust is
# fixed; this reads them by name. The deploy role may pass each to its one
# service, attach the CloudWatch agent's policy to the instance role and
# write the S3 backups' inline policy on it, nothing more.

data "aws_iam_role" "server" {
  name = "${local.name}-instance"
}

data "aws_iam_instance_profile" "server" {
  name = "${local.name}-instance"
}

data "aws_iam_role" "dlm" {
  name = "${local.name}-dlm"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  count = var.enable_cloudwatch_agent ? 1 : 0

  role       = data.aws_iam_role.server.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# The instance role may assume bootstrap's snapshot writer, whose one-hour
# session puts objects into the snapshot bucket and does nothing else. Root's
# credentials helper on the server (Fermix's first boot installs it) assumes it
# and hands the engine that session alone; the instance role itself holds no
# right on the bucket, and the server roles' boundary allows it none.
resource "aws_iam_role_policy" "snapshot_writer" {
  count = var.enable_s3_backups ? 1 : 0

  name = "${local.name}-snapshots"
  role = data.aws_iam_role.server.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeTheSnapshotWriter"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = local.snapshot_writer_role_arn
    }]
  })
}
