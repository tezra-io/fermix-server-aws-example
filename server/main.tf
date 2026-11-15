# One Always On server (README.md).

module "server" {
  source = "../modules/server"

  instance_type            = var.instance_type
  root_volume_gb           = var.root_volume_gb
  availability_zone        = var.availability_zone
  vpc_cidr                 = var.vpc_cidr
  enable_cloudwatch_agent  = var.enable_cloudwatch_agent
  enable_ebs_snapshots     = var.enable_ebs_snapshots
  enable_s3_backups        = var.enable_s3_backups
  ebs_snapshot_time_utc    = var.ebs_snapshot_time_utc
  snapshot_noncurrent_days = var.snapshot_noncurrent_days
  alert_emails             = var.alert_emails
  monthly_budget_usd       = var.monthly_budget_usd
  allow_destroy            = var.allow_destroy
}
