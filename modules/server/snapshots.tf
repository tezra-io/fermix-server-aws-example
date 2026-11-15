# A daily EBS snapshot of the root volume, 7 kept, through Data Lifecycle
# Manager, through bootstrap's DLM role. It targets the volume carrying the
# server stack's tag and puts that tag on every snapshot, which is how the
# teardown finds and deletes them: they outlive this policy (README.md,
# "Removing the server").

resource "aws_dlm_lifecycle_policy" "root_volume" {
  count = var.enable_ebs_snapshots ? 1 : 0

  description        = "fermix-server root volume daily 7 kept"
  execution_role_arn = data.aws_iam_role.dlm.arn
  state              = "ENABLED"

  policy_details {
    policy_type    = "EBS_SNAPSHOT_MANAGEMENT"
    resource_types = ["VOLUME"]
    target_tags    = local.tags

    schedule {
      name      = "daily"
      copy_tags = true

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = [var.ebs_snapshot_time_utc]
      }

      retain_rule {
        count = 7
      }

      # Copied from the volume too; added here so DLM's role, which may delete
      # only a snapshot carrying it, can expire every one it takes.
      tags_to_add = local.tags
    }
  }

  tags = local.tags

  depends_on = [aws_kms_key.server]
}
