# The server's first-boot script (instance.tf's user data), with no provider:
# ci.yml renders it here and runs shellcheck on exactly what a server boots.
#   terraform -chdir=modules/server/user_data init
#   terraform -chdir=modules/server/user_data apply -auto-approve -var region=us-east-1 -var cloudwatch_agent=true \
#     -var snapshot_bucket=fermix-server-snapshots-111122223333-us-east-1 \
#     -var snapshot_role_arn=arn:aws:iam::111122223333:role/fermix-server/fermix-server-snapshot-writer
#   terraform -chdir=modules/server/user_data output -raw script

variable "region" {
  description = "The server's region: the SSM and CloudWatch agents download from AWS's buckets there."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region))
    error_message = "region must be an AWS region name."
  }
}

variable "cloudwatch_agent" {
  description = "Install the CloudWatch agent too (enable_cloudwatch_agent)."
  type        = bool
}

variable "snapshot_bucket" {
  description = "With enable_s3_backups, the bucket Fermix's first boot keeps its snapshots in, written to /etc/fermix/snapshot-destination; empty writes no file."
  type        = string
  default     = ""

  validation {
    condition     = var.snapshot_bucket == "" || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.snapshot_bucket))
    error_message = "snapshot_bucket must be an S3 bucket name, or empty."
  }
}

variable "snapshot_role_arn" {
  description = "With enable_s3_backups, the snapshot writer role Fermix's credentials helper assumes, beside snapshot_bucket; empty with it."
  type        = string
  default     = ""

  validation {
    condition     = var.snapshot_role_arn == "" || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", var.snapshot_role_arn))
    error_message = "snapshot_role_arn must be an IAM role's ARN, or empty."
  }
}

locals {
  # The agents' public keys exactly as AWS publishes them (keys/), pinned by
  # their fingerprints (README.md, "The agents' signatures").
  ssm_agent_fingerprint        = "1C5B395CBE5E74E2F1CA21592784DBF388D19D46"
  cloudwatch_agent_fingerprint = "937616F3450B7D806CBD9725D58167303B789C72"

  # The CloudWatch agent's: memory and disk use of /, every minute, by instance.
  cloudwatch_agent_config = jsonencode({
    agent = { metrics_collection_interval = 60, run_as_user = "cwagent" }
    metrics = {
      namespace         = "CWAgent"
      append_dimensions = { InstanceId = "$${aws:InstanceId}" }
      metrics_collected = {
        mem  = { measurement = ["mem_used_percent"] }
        disk = { measurement = ["used_percent"], resources = ["/"], drop_device = true }
      }
    }
  })
}

output "script" {
  description = "The user data: a POSIX sh script, run once by cloud-init at the first boot."
  value = templatefile("${path.module}/user_data.sh.tftpl", {
    region                       = var.region
    cloudwatch_agent             = var.cloudwatch_agent
    ssm_agent_key                = chomp(file("${path.module}/keys/amazon-ssm-agent.asc"))
    ssm_agent_fingerprint        = local.ssm_agent_fingerprint
    cloudwatch_agent_key         = chomp(file("${path.module}/keys/amazon-cloudwatch-agent.asc"))
    cloudwatch_agent_fingerprint = local.cloudwatch_agent_fingerprint
    cloudwatch_agent_config      = local.cloudwatch_agent_config
    snapshot_bucket              = var.snapshot_bucket
    snapshot_role_arn            = var.snapshot_role_arn
  })

  precondition {
    condition     = (var.snapshot_bucket == "") == (var.snapshot_role_arn == "")
    error_message = "snapshot_bucket and snapshot_role_arn are set together, or neither."
  }
}
