data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  region     = data.aws_region.current.region
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  name       = "fermix-server"

  # The server stack's tag, on everything here that takes tags. bootstrap's
  # deploy role manages KMS keys, SNS topics and DLM policies only while they
  # carry it, the DLM policy snapshots the volume that carries it, and after a
  # destroy nothing carrying it remains (README.md, "Removing the server").
  # bootstrap's own resources carry the same key with "bootstrap".
  tags = { "fermix-server-stack" = "server" }

  # The deploy role's boundary names this bucket exactly (bootstrap/locals.tf).
  # CHANGE ME only if S3 says this name is taken: change it with bootstrap/locals.tf and the tests that pin it.
  snapshot_bucket = "${local.name}-snapshots-${local.account_id}-${local.region}"

  # bootstrap's snapshot writer (bootstrap/server_roles.tf), by its ARN:
  # the deploy role reads no role but the two server roles.
  snapshot_writer_role_arn = "arn:${local.partition}:iam::${local.account_id}:role/${local.name}/${local.name}-snapshot-writer"

  alerts = length(var.alert_emails) > 0
}
