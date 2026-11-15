# The server: Debian 13 arm64 on Graviton, reached by Session Manager only,
# with IMDSv2, automatic recovery and termination protection. Its root volume
# holds the Fermix home, so nothing here ever replaces it by itself: the AMI
# and the user data are read once, at create (RUNBOOK.md, "Replacing the AMI
# deliberately").

data "aws_ssm_parameter" "debian" {
  name = "/aws/service/debian/release/13/latest/arm64"
}

# The first boot's script, rendered by a module with no provider, so CI can
# render and lint the exact script a server boots with (ci.yml).
module "user_data" {
  source = "./user_data"

  region            = local.region
  cloudwatch_agent  = var.enable_cloudwatch_agent
  snapshot_bucket   = var.enable_s3_backups ? local.snapshot_bucket : ""
  snapshot_role_arn = var.enable_s3_backups ? local.snapshot_writer_role_arn : ""
}

resource "aws_instance" "server" {
  ami                         = data.aws_ssm_parameter.debian.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.server.id]
  associate_public_ip_address = true
  iam_instance_profile        = data.aws_iam_instance_profile.server.name
  user_data                   = module.user_data.script
  user_data_replace_on_change = false
  disable_api_termination     = !var.allow_destroy
  monitoring                  = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    kms_key_id            = aws_kms_key.server.arn
    delete_on_termination = true
  }

  # Tagged at launch (RunInstances' own tag specification), so the deploy role
  # creates the volume only with the stack's tag; the DLM policy snapshots the
  # volume that carries it.
  volume_tags = merge(local.tags, { Name = "${local.name}-root" })

  # EC2's simplified automatic recovery: a failed system status check moves
  # the instance to healthy hardware, same volume, same addresses.
  maintenance_options {
    auto_recovery = "default"
  }

  tags = merge(local.tags, { Name = local.name })

  lifecycle {
    # Read once. A newer AMI or a changed user data never replaces the server:
    # replacing it destroys the home it holds. AWS stops and starts an instance
    # to change its user data, and cloud-init runs it only at the first boot,
    # so a change would only restart the primary (DESIGN.md).
    ignore_changes = [ami, user_data]

    precondition {
      condition     = startswith(data.aws_ssm_parameter.debian.insecure_value, "ami-")
      error_message = "/aws/service/debian/release/13/latest/arm64 did not resolve to an AMI id in ${local.region}."
    }
  }

  depends_on = [aws_route_table_association.public]
}

# What the server booted with for the CloudWatch agent and S3 backups, kept
# from its create: the agent itself and the snapshot destination are written
# only by the first boot, the role's policies follow the variables at every
# apply.
resource "terraform_data" "first_boot" {
  input = { cloudwatch_agent = var.enable_cloudwatch_agent, s3_backups = var.enable_s3_backups }

  lifecycle {
    ignore_changes = [input]
  }

  depends_on = [aws_instance.server]
}

check "cloudwatch_agent_matches_first_boot" {
  assert {
    condition     = terraform_data.first_boot.input.cloudwatch_agent == var.enable_cloudwatch_agent
    error_message = "enable_cloudwatch_agent is ${var.enable_cloudwatch_agent} but the server booted with ${terraform_data.first_boot.input.cloudwatch_agent}. The role's policy follows the variable; the agent itself does not. RUNBOOK.md, \"Turning metrics on or off later\"."
  }
}

# A server made by a version of this module without enable_s3_backups booted
# with no snapshot destination.
check "s3_backups_match_first_boot" {
  assert {
    condition     = try(terraform_data.first_boot.input.s3_backups, false) == var.enable_s3_backups
    error_message = "enable_s3_backups is ${var.enable_s3_backups} but the server booted with ${try(terraform_data.first_boot.input.s3_backups, false)}. The bucket and the instance role's grant follow the variable; /etc/fermix/snapshot-destination and Fermix's own settings do not. RUNBOOK.md, \"Turning S3 backups on or off later\"."
  }
}

# terraform destroy refuses here, before it removes anything, until an apply
# with allow_destroy = true has lifted termination protection and let the
# bucket be emptied. Everything else depends on this, so it is destroyed
# first. Its check runs as a shell command on the owner's computer.
resource "terraform_data" "destroy_guard" {
  input = var.allow_destroy

  provisioner "local-exec" {
    when    = destroy
    command = self.input ? "true" : "echo 'fermix-server: destroy refused. Move Fermix back to the Mac, apply with allow_destroy = true, then destroy (README.md, \"Removing the server\").' >&2; exit 1"
  }

  depends_on = [
    aws_instance.server,
    terraform_data.first_boot,
    aws_s3_bucket_policy.snapshots,
    aws_s3_bucket_lifecycle_configuration.snapshots,
    aws_s3_bucket_versioning.snapshots,
    aws_s3_bucket_server_side_encryption_configuration.snapshots,
    aws_s3_bucket_ownership_controls.snapshots,
    aws_dlm_lifecycle_policy.root_volume,
    aws_cloudwatch_metric_alarm.instance_status,
    aws_sns_topic_subscription.alerts,
    aws_sns_topic_policy.alerts,
    aws_budgets_budget.monthly,
    aws_kms_alias.server,
    aws_iam_role_policy_attachment.cloudwatch_agent,
    aws_iam_role_policy.snapshot_writer,
  ]
}
