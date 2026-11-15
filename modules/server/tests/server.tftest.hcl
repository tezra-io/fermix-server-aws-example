# The server's invariants, with a mocked provider:
# no credentials, no API calls.
#   terraform -chdir=modules/server init -backend=false
#   terraform -chdir=modules/server test
#
# Plans check what the configuration decides. The last run, which compares one
# resource's ARN with another's, applies against the mock so the ARNs exist;
# it comes last because every later run would plan against its state, and it
# sets allow_destroy because the test's own cleanup is a destroy, which the
# destroy guard (instance.tf) refuses without it.

mock_provider "aws" {
  mock_data "aws_region" {
    defaults = { region = "us-east-1" }
  }

  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }

  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }

  mock_data "aws_ssm_parameter" {
    defaults = { insecure_value = "ami-0aaaaaaaaaaaaaaaa", value = "ami-0aaaaaaaaaaaaaaaa" }
  }

  mock_data "aws_ec2_instance_type_offerings" {
    defaults = { locations = ["us-east-1c", "us-east-1a", "us-east-1b"] }
  }

  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555" }
  }

  mock_data "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/fermix-server/fermix-server-dlm" }
  }

  mock_data "aws_iam_instance_profile" {
    defaults = { arn = "arn:aws:iam::111122223333:instance-profile/fermix-server/fermix-server-instance" }
  }

  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::fermix-server-snapshots-111122223333-us-east-1" }
  }

  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:111122223333:fermix-server-alerts" }
  }
}

variables {
  alert_emails = ["owner@example.test"]
}

run "nothing_comes_in" {
  command = plan

  assert {
    condition     = length(aws_security_group.server.ingress) == 0
    error_message = "the server's security group has no inbound rule"
  }

  assert {
    condition     = length(aws_instance.server.vpc_security_group_ids) == 1
    error_message = "the instance is in the server's security group alone"
  }

  assert {
    condition = alltrue([
      for rule in aws_security_group.server.egress : rule.protocol == "-1" && rule.cidr_blocks == tolist(["0.0.0.0/0"])
    ]) && length(aws_security_group.server.egress) == 1
    error_message = "all outbound traffic is allowed, with no allowlist"
  }
}

run "imdsv2_is_required" {
  command = plan

  assert {
    condition = (
      aws_instance.server.metadata_options[0].http_endpoint == "enabled" &&
      aws_instance.server.metadata_options[0].http_tokens == "required" &&
      aws_instance.server.metadata_options[0].http_put_response_hop_limit == 1
    )
    error_message = "IMDSv2 is required, with a hop limit of 1"
  }
}

run "user_data_holds_no_secret" {
  command = plan

  assert {
    condition     = !issensitive(aws_instance.server.user_data)
    error_message = "the user data is built from no value marked sensitive"
  }

  assert {
    condition = alltrue([
      for secret in ["FERMIX_ENROLL_CODE", "TS_AUTHKEY", "tskey-", "enroll.code"] : !strcontains(aws_instance.server.user_data, secret)
    ])
    error_message = "the user data never carries the enrollment code or a Tailscale key"
  }

  assert {
    condition     = length(aws_instance.server.user_data) <= 16384
    error_message = "the user data fits EC2's 16 KB"
  }

  assert {
    condition = (
      strcontains(aws_instance.server.user_data, "1C5B395CBE5E74E2F1CA21592784DBF388D19D46") &&
      strcontains(aws_instance.server.user_data, "BEGIN PGP PUBLIC KEY BLOCK") &&
      strcontains(aws_instance.server.user_data, "with_cloudwatch_agent='false'")
    )
    error_message = "the user data pins AWS's SSM agent key and, by default, leaves the CloudWatch agent off"
  }
}

# Session Manager is the only way in: the first boot stops and disables
# Debian's sshd and masks its socket, so nothing listens on 22 even inside the
# VPC.
run "user_data_turns_sshd_off" {
  command = plan

  assert {
    condition = (
      strcontains(aws_instance.server.user_data, "systemctl disable --now ssh.service") &&
      strcontains(aws_instance.server.user_data, "systemctl mask --now ssh.socket")
    )
    error_message = "the user data stops and disables ssh.service and masks ssh.socket"
  }
}

run "termination_protection_is_on" {
  command = plan

  assert {
    condition     = aws_instance.server.disable_api_termination == true
    error_message = "termination protection is on unless allow_destroy is set"
  }

  assert {
    condition     = terraform_data.destroy_guard.input == false && aws_s3_bucket.snapshots[0].force_destroy == false
    error_message = "without allow_destroy, terraform destroy refuses and the snapshot bucket cannot be emptied"
  }
}

run "allow_destroy_is_the_one_switch" {
  command = plan

  variables {
    allow_destroy = true
  }

  assert {
    condition = (
      aws_instance.server.disable_api_termination == false &&
      aws_s3_bucket.snapshots[0].force_destroy == true &&
      terraform_data.destroy_guard.input == true
    )
    error_message = "allow_destroy lifts termination protection, lets Terraform empty the bucket and lets destroy run"
  }
}

run "the_server_uses_bootstraps_roles" {
  command = plan

  assert {
    condition = (
      data.aws_iam_role.server.name == "fermix-server-instance" &&
      data.aws_iam_instance_profile.server.name == "fermix-server-instance" &&
      data.aws_iam_role.dlm.name == "fermix-server-dlm" &&
      aws_instance.server.iam_instance_profile == "fermix-server-instance"
    )
    error_message = "the server runs as bootstrap's instance profile, and DLM as bootstrap's role, read by name"
  }

  assert {
    condition = (
      length(aws_iam_role_policy_attachment.cloudwatch_agent) == 0 &&
      aws_dlm_lifecycle_policy.root_volume[0].execution_role_arn == "arn:aws:iam::111122223333:role/fermix-server/fermix-server-dlm"
    )
    error_message = "the instance role gets no managed policy here until enable_cloudwatch_agent; DLM runs as bootstrap's DLM role"
  }
}

run "metrics_on_add_the_agent_and_its_policy" {
  command = plan

  variables {
    enable_cloudwatch_agent = true
  }

  assert {
    condition = (
      length(aws_iam_role_policy_attachment.cloudwatch_agent) == 1 &&
      aws_iam_role_policy_attachment.cloudwatch_agent[0].role == "fermix-server-instance" &&
      aws_iam_role_policy_attachment.cloudwatch_agent[0].policy_arn == "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy" &&
      strcontains(aws_instance.server.user_data, "with_cloudwatch_agent='true'") &&
      strcontains(aws_instance.server.user_data, "937616F3450B7D806CBD9725D58167303B789C72")
    )
    error_message = "enable_cloudwatch_agent installs the CloudWatch agent at first boot and gives the role CloudWatchAgentServerPolicy"
  }
}

run "no_address_means_no_topic_and_no_budget" {
  command = plan

  variables {
    alert_emails = []
  }

  assert {
    condition = (
      length(aws_sns_topic.alerts) == 0 &&
      length(aws_budgets_budget.monthly) == 0 &&
      length(aws_cloudwatch_metric_alarm.instance_status.alarm_actions) == 0
    )
    error_message = "without alert_emails the alarm exists with no action, and there is no topic and no budget"
  }
}

run "each_address_gets_the_alarm_and_the_budget" {
  command = plan

  variables {
    alert_emails = ["owner@example.test", "second@example.test"]
  }

  assert {
    condition = (
      toset([for s in values(aws_sns_topic_subscription.alerts) : s.endpoint]) == toset(["owner@example.test", "second@example.test"]) &&
      alltrue([for n in aws_budgets_budget.monthly[0].notification :
        toset(n.subscriber_email_addresses) == toset(["owner@example.test", "second@example.test"])
      ])
    )
    error_message = "every address in alert_emails gets the status-check alarm's topic and every budget notification"
  }
}

run "snapshots_follow_their_switch" {
  command = plan

  variables {
    enable_ebs_snapshots = false
  }

  assert {
    condition     = length(aws_dlm_lifecycle_policy.root_volume) == 0 && !strcontains(aws_kms_key.server.policy, "DlmSnapshotsTheRootVolume")
    error_message = "enable_ebs_snapshots = false turns the DLM policy, and its use of the server key, off"
  }
}

# With enable_s3_backups (on unless set), the bucket, the instance role's
# one grant (assuming bootstrap's snapshot writer) and the destination the
# user data hands Fermix's first boot.
run "s3_backups_are_on_by_default" {
  command = plan

  assert {
    condition = (
      length(aws_s3_bucket.snapshots) == 1 &&
      length(aws_s3_bucket_policy.snapshots) == 1 &&
      length(aws_s3_bucket_versioning.snapshots) == 1 &&
      length(aws_s3_bucket_server_side_encryption_configuration.snapshots) == 1 &&
      length(aws_s3_bucket_lifecycle_configuration.snapshots) == 1 &&
      length(aws_s3_bucket_ownership_controls.snapshots) == 1
    )
    error_message = "enable_s3_backups makes the snapshot bucket, with its versioning, encryption, lifecycle, policy and ownership"
  }

  assert {
    condition = (
      length(aws_iam_role_policy.snapshot_writer) == 1 &&
      aws_iam_role_policy.snapshot_writer[0].role == "fermix-server-instance" &&
      aws_iam_role_policy.snapshot_writer[0].name == "fermix-server-snapshots" &&
      length(jsondecode(aws_iam_role_policy.snapshot_writer[0].policy).Statement) == 1 &&
      jsondecode(aws_iam_role_policy.snapshot_writer[0].policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_iam_role_policy.snapshot_writer[0].policy).Statement[0].Action == "sts:AssumeRole" &&
      jsondecode(aws_iam_role_policy.snapshot_writer[0].policy).Statement[0].Resource == "arn:aws:iam::111122223333:role/fermix-server/fermix-server-snapshot-writer"
    )
    error_message = "the instance role's one inline policy assumes bootstrap's snapshot writer and nothing else; it holds no S3 right itself"
  }

  assert {
    condition = (
      strcontains(aws_instance.server.user_data, "snapshot_bucket='fermix-server-snapshots-111122223333-us-east-1'") &&
      strcontains(aws_instance.server.user_data, "snapshot_role_arn='arn:aws:iam::111122223333:role/fermix-server/fermix-server-snapshot-writer'") &&
      strcontains(aws_instance.server.user_data, "/etc/fermix/snapshot-destination")
    )
    error_message = "the user data writes the bucket and the snapshot writer's role for Fermix's first boot"
  }

  assert {
    condition     = terraform_data.first_boot.input.s3_backups == true
    error_message = "what the server booted with for S3 backups is kept, as for the CloudWatch agent"
  }
}

run "s3_backups_off_write_and_grant_nothing" {
  command = plan

  variables {
    enable_s3_backups = false
  }

  assert {
    condition = (
      length(aws_s3_bucket.snapshots) == 0 &&
      length(aws_s3_bucket_policy.snapshots) == 0 &&
      length(aws_s3_bucket_versioning.snapshots) == 0 &&
      length(aws_s3_bucket_server_side_encryption_configuration.snapshots) == 0 &&
      length(aws_s3_bucket_lifecycle_configuration.snapshots) == 0 &&
      length(aws_s3_bucket_ownership_controls.snapshots) == 0
    )
    error_message = "without enable_s3_backups there is no snapshot bucket"
  }

  assert {
    condition     = length(aws_iam_role_policy.snapshot_writer) == 0
    error_message = "without enable_s3_backups the instance role is granted nothing"
  }

  assert {
    condition = (
      strcontains(aws_instance.server.user_data, "snapshot_bucket=''") &&
      !strcontains(aws_instance.server.user_data, "fermix-server-snapshot-writer")
    )
    error_message = "without enable_s3_backups the user data hands first boot no destination"
  }
}

# The snapshot bucket keeps the public access block S3 gives every new bucket
# (all four settings on), and the module writes none, so the deploy role
# needs no right to write one and is denied it (bootstrap/denies.tf). A plan
# cannot name a resource the configuration does not declare, so this reads
# the module's own files: no file declares one, and storage.tf forgets the one
# an older apply made without destroying it, leaving its settings on AWS.
run "the_snapshot_bucket_keeps_s3s_public_access_block" {
  command = plan

  assert {
    condition = alltrue([
      for f in fileset(path.module, "*.tf") : !strcontains(file("${path.module}/${f}"), "resource \"aws_s3_bucket_public_access_block\"")
    ])
    error_message = "no file in the module declares an aws_s3_bucket_public_access_block: the bucket keeps S3's own"
  }

  assert {
    condition     = length(regexall("removed\\s*\\{\\s*from\\s*=\\s*aws_s3_bucket_public_access_block\\.snapshots\\s*lifecycle\\s*\\{\\s*destroy\\s*=\\s*false\\s*\\}\\s*\\}", file("${path.module}/storage.tf"))) == 1
    error_message = "storage.tf forgets the public access block an older apply made (removed, destroy = false), so an apply never deletes it"
  }
}

# EventBridge publishes to bootstrap's security alert topic, never to this
# one, so it gets nothing on the server key.
run "eventbridge_gets_nothing_on_the_server_key" {
  command = plan

  assert {
    condition     = !strcontains(aws_kms_key.server.policy, "events.amazonaws.com")
    error_message = "the server key's policy names no EventBridge"
  }
}

run "names_bootstrap_scopes_the_deploy_role_by" {
  command = plan

  assert {
    condition = (
      aws_s3_bucket.snapshots[0].bucket == "fermix-server-snapshots-111122223333-us-east-1" &&
      aws_kms_alias.server.name == "alias/fermix-server" &&
      aws_cloudwatch_metric_alarm.instance_status.alarm_name == "fermix-server-instance-status" &&
      aws_budgets_budget.monthly[0].name == "fermix-server-monthly" &&
      aws_sns_topic.alerts[0].name == "fermix-server-alerts"
    )
    error_message = "the names bootstrap/locals.tf scopes the deploy role by"
  }

  assert {
    condition = alltrue([
      aws_kms_key.server.tags["fermix-server-stack"] == "server",
      aws_sns_topic.alerts[0].tags["fermix-server-stack"] == "server",
      aws_dlm_lifecycle_policy.root_volume[0].tags["fermix-server-stack"] == "server",
      aws_s3_bucket.snapshots[0].tags["fermix-server-stack"] == "server",
      aws_instance.server.volume_tags["fermix-server-stack"] == "server",
      aws_dlm_lifecycle_policy.root_volume[0].policy_details[0].target_tags["fermix-server-stack"] == "server",
      try(aws_dlm_lifecycle_policy.root_volume[0].policy_details[0].schedule[0].tags_to_add["fermix-server-stack"], null) == "server",
    ])
    error_message = "everything the deploy role manages by tag, the volume DLM snapshots and every snapshot it takes carry the server stack's tag"
  }

  assert {
    condition     = aws_subnet.public.availability_zone == "us-east-1a"
    error_message = "with no zone given, the first zone in name order that offers the type"
  }
}

run "every_volume_bucket_and_key_is_encrypted" {
  command = apply

  variables {
    allow_destroy = true
  }

  assert {
    condition = (
      aws_instance.server.root_block_device[0].encrypted == true &&
      aws_instance.server.root_block_device[0].kms_key_id == aws_kms_key.server.arn &&
      aws_instance.server.root_block_device[0].volume_type == "gp3" &&
      aws_instance.server.root_block_device[0].volume_size == 20
    )
    error_message = "the root volume is a 20 GB gp3 volume encrypted with the server's key"
  }

  assert {
    condition = (
      one(aws_s3_bucket_server_side_encryption_configuration.snapshots[0].rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" &&
      one(aws_s3_bucket_server_side_encryption_configuration.snapshots[0].rule).apply_server_side_encryption_by_default[0].kms_master_key_id == aws_kms_key.server.arn
    )
    error_message = "the snapshot bucket is encrypted with the server's key"
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_s3_bucket_policy.snapshots[0].policy).Statement : statement.Effect == "Deny"
      ]) && contains(
      [for statement in jsondecode(aws_s3_bucket_policy.snapshots[0].policy).Statement : statement.Sid],
      "RefuseAnythingButTls"
      ) && contains(
      [for statement in jsondecode(aws_s3_bucket_policy.snapshots[0].policy).Statement : statement.Sid],
      "RefuseUploadsNamingAnotherEncryption"
    )
    error_message = "the snapshot bucket refuses requests without TLS and uploads that name another encryption"
  }

  # An upload that names no encryption takes the bucket's default, the server
  # key: Fermix's uploads name none (the engine's S3 target sends no encryption
  # header). One that names another encryption, SSE-KMS with another key or
  # none, or a key of its own (SSE-C), is refused. Each deny needs a header
  # present (Null false), so none refuses an upload that names none.
  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.snapshots[0].policy).Statement : anytrue([
        for header, absent in try(s.Condition.Null, {}) : absent == "false"
      ]) if s.Action == "s3:PutObject"
    ])
    error_message = "every upload deny needs an encryption header present, so an upload that names none passes and takes the server key"
  }

  assert {
    condition = alltrue([
      for condition in [
        { Null = { "s3:x-amz-server-side-encryption" = "false" }, StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } },
        { Null = { "s3:x-amz-server-side-encryption" = "false" }, StringNotEqualsIfExists = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.server.arn } },
        ] : contains(
        [for s in jsondecode(aws_s3_bucket_policy.snapshots[0].policy).Statement : jsonencode(s.Condition) if s.Action == "s3:PutObject"],
        jsonencode(condition)
      )
    ])
    error_message = "the snapshot bucket refuses an upload that names an encryption other than SSE-KMS with the server key"
  }

  # SSE-C sets no x-amz-server-side-encryption header, so the denies above let
  # it through and the object would bypass the server key: refused twice over,
  # by the policy and by the bucket's own encryption rule.
  assert {
    condition = contains(
      [for s in jsondecode(aws_s3_bucket_policy.snapshots[0].policy).Statement : jsonencode(s.Condition) if s.Action == "s3:PutObject"],
      jsonencode({ Null = { "s3:x-amz-server-side-encryption-customer-algorithm" = "false" } })
    )
    error_message = "the snapshot bucket's policy refuses an upload that brings its own key (SSE-C)"
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.snapshots[0].rule).blocked_encryption_types == tolist(["SSE-C"])
    error_message = "the snapshot bucket's encryption rule blocks SSE-C"
  }

  assert {
    condition     = aws_sns_topic.alerts[0].kms_master_key_id == aws_kms_key.server.arn
    error_message = "the alert topic is encrypted with the server's key"
  }

  # The account's security alerts have their own topic in bootstrap
  # (bootstrap/alerts.tf), out of the deploy role's reach; this topic takes
  # CloudWatch's alarms alone.
  assert {
    condition = alltrue([
      for s in jsondecode(aws_sns_topic_policy.alerts[0].policy).Statement : s.Principal == { Service = "cloudwatch.amazonaws.com" }
    ])
    error_message = "the server's alert topic takes messages from CloudWatch alarms alone"
  }

  assert {
    condition     = aws_kms_key.server.enable_key_rotation == true
    error_message = "the server's key rotates"
  }

  assert {
    condition     = aws_dlm_lifecycle_policy.root_volume[0].policy_details[0].schedule[0].copy_tags == true
    error_message = "every DLM snapshot carries the stack's tag, so the runbook can find and delete it"
  }
}
