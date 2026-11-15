# The account's security alerts and the topic they reach (README.md, "The
# session email"), with a mocked provider and plans, as
# tests/bootstrap.tftest.hcl.
#   terraform -chdir=bootstrap test -filter=tests/alerts.tftest.hcl

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  # Keys' ARNs, known to the plan.
  mock_resource "aws_kms_key" {
    override_during = plan
    defaults = {
      arn = "arn:aws:kms:us-east-1:111122223333:key/22222222-3333-4444-5555-666666666666"
    }
  }

  mock_resource "aws_sns_topic" {
    override_during = plan
    defaults = {
      arn = "arn:aws:sns:us-east-1:111122223333:fermix-owner-security-alerts"
    }
  }
}

variables {
  region         = "us-east-1"
  admin_role_arn = "arn:aws:iam::111122223333:role/managed/OwnerAdmin"
}

# EventBridge sees an API call only through a trail with logging (EventBridge
# User Guide, "AWS service events delivered via AWS CloudTrail"). The trail
# is the least that does it: write management events, this region, its own
# key, a private bucket.
run "a_minimal_trail_by_default" {
  command = plan

  assert {
    condition = (
      aws_cloudtrail.this[0].name == "fermix-server" &&
      aws_cloudtrail.this[0].s3_bucket_name == "fermix-server-trail-111122223333-us-east-1" &&
      aws_cloudtrail.this[0].is_multi_region_trail == false &&
      aws_cloudtrail.this[0].include_global_service_events == false &&
      aws_cloudtrail.this[0].enable_log_file_validation == true &&
      aws_cloudtrail.this[0].kms_key_id == "arn:aws:kms:us-east-1:111122223333:key/22222222-3333-4444-5555-666666666666"
    )
    error_message = "a single-region trail, logs validated, encrypted with its own key, into its own bucket"
  }

  assert {
    condition = (
      length(aws_cloudtrail.this[0].event_selector) == 1 &&
      aws_cloudtrail.this[0].event_selector[0].read_write_type == "WriteOnly" &&
      aws_cloudtrail.this[0].event_selector[0].include_management_events == true &&
      length(aws_cloudtrail.this[0].event_selector[0].data_resource) == 0 &&
      length(aws_cloudtrail.this[0].advanced_event_selector) == 0 &&
      length(aws_cloudtrail.this[0].insight_selector) == 0
    )
    error_message = "the trail records write management events only: no data events, no Insights"
  }

  assert {
    condition = (
      aws_kms_key.trail[0].enable_key_rotation == true &&
      one(aws_s3_bucket_server_side_encryption_configuration.trail[0].rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" &&
      aws_s3_bucket_versioning.trail[0].versioning_configuration[0].status == "Enabled" &&
      aws_s3_bucket_ownership_controls.trail[0].rule[0].object_ownership == "BucketOwnerEnforced" &&
      aws_s3_bucket_public_access_block.trail[0].block_public_acls &&
      aws_s3_bucket_public_access_block.trail[0].block_public_policy &&
      aws_s3_bucket_public_access_block.trail[0].ignore_public_acls &&
      aws_s3_bucket_public_access_block.trail[0].restrict_public_buckets
    )
    error_message = "the trail's bucket is private, versioned and encrypted with the trail's own key, which rotates"
  }

  # Only this trail writes the logs, and only through TLS.
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.trail_bucket[0].statement : (
        s.effect == "Deny" && anytrue([for c in s.condition : c.variable == "aws:SecureTransport" && c.values == tolist(["false"])])
        ) || anytrue([
          for c in s.condition : c.variable == "aws:SourceArn" && c.values == tolist(["arn:aws:cloudtrail:us-east-1:111122223333:trail/fermix-server"])
      ])
    ])
    error_message = "the trail's bucket takes requests over TLS only, and CloudTrail's writes only from this trail"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.trail_key[0].statement : anytrue([
        for c in s.condition : c.variable == "aws:SourceArn" && c.values == tolist(["arn:aws:cloudtrail:us-east-1:111122223333:trail/fermix-server"])
      ]) if anytrue([for p in s.principals : contains(p.identifiers, "cloudtrail.amazonaws.com")])
    ])
    error_message = "the trail's key lets CloudTrail use it for this trail alone"
  }
}

run "no_trail_when_switched_off" {
  command = plan

  variables {
    enable_cloudtrail = false
  }

  assert {
    condition     = try(aws_cloudtrail.this[0].name, null) == null && try(aws_s3_bucket.trail[0].bucket, null) == null && try(aws_kms_key.trail[0].description, null) == null
    error_message = "enable_cloudtrail = false makes no trail, bucket or key"
  }
}

# A session that starts or resumes anywhere in the account's region emails
# through server/'s alert topic, named by its exact name: who, the request
# (a start names the instance; a resume, the session), the session and when.
run "a_session_emails_the_alert_topic" {
  command = plan

  assert {
    condition = (
      aws_cloudwatch_event_rule.sessions.name == "fermix-server-sessions" &&
      jsondecode(aws_cloudwatch_event_rule.sessions.event_pattern) == {
        source        = ["aws.ssm"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ssm.amazonaws.com"]
          eventName   = ["StartSession", "ResumeSession"]
        }
      }
    )
    error_message = "the rule matches Session Manager's StartSession and ResumeSession calls"
  }

  assert {
    condition = (
      aws_cloudwatch_event_target.sessions.rule == "fermix-server-sessions" &&
      aws_cloudwatch_event_target.sessions.arn == "arn:aws:sns:us-east-1:111122223333:fermix-owner-security-alerts"
    )
    error_message = "the rule sends to the security alert topic"
  }

  assert {
    condition = (
      aws_cloudwatch_event_target.sessions.input_transformer[0].input_paths == tomap({
        call    = "$.detail.eventName"
        who     = "$.detail.userIdentity.arn"
        request = "$.detail.requestParameters"
        session = "$.detail.responseElements.sessionId"
        when    = "$.detail.eventTime"
        from    = "$.detail.sourceIPAddress"
      }) &&
      alltrue([for v in ["<call>", "<who>", "<request>", "<session>", "<when>", "<from>"] : strcontains(aws_cloudwatch_event_target.sessions.input_transformer[0].input_template, v)])
    )
    error_message = "the email names the call, who made it, the request with its instance, the session, the time and the address"
  }
}

# A Run Command command, which runs as root and is no session, emails too:
# who, the request (the instances or targets and the document), the command
# and when.
run "a_command_emails_the_alert_topic" {
  command = plan

  assert {
    condition = (
      aws_cloudwatch_event_rule.commands.name == "fermix-server-commands" &&
      jsondecode(aws_cloudwatch_event_rule.commands.event_pattern) == {
        source        = ["aws.ssm"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ssm.amazonaws.com"]
          eventName   = ["SendCommand"]
        }
      }
    )
    error_message = "the commands rule matches Run Command's SendCommand calls"
  }

  assert {
    condition = (
      aws_cloudwatch_event_target.commands.rule == "fermix-server-commands" &&
      aws_cloudwatch_event_target.commands.arn == "arn:aws:sns:us-east-1:111122223333:fermix-owner-security-alerts" &&
      alltrue([for v in ["<call>", "<who>", "<request>", "<command>", "<when>", "<from>"] : strcontains(aws_cloudwatch_event_target.commands.input_transformer[0].input_template, v)]) &&
      aws_cloudwatch_event_target.commands.input_transformer[0].input_paths["command"] == "$.detail.responseElements.command.commandId"
    )
    error_message = "a command's email goes to the alert topic and names who, the request, the command id and when"
  }
}

# An instance attribute changed, or a change refused: user data is code the
# instance runs at boot, with no session or command to email. Who, the
# request (the instance and the attribute; CloudTrail hides user data), the
# error code when refused, when and from where.
run "an_instance_attribute_change_emails_the_alert_topic" {
  command = plan

  assert {
    condition = (
      aws_cloudwatch_event_rule.instance_attributes.name == "fermix-server-instance-attributes" &&
      jsondecode(aws_cloudwatch_event_rule.instance_attributes.event_pattern) == {
        source        = ["aws.ec2"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["ModifyInstanceAttribute"]
        }
      }
    )
    error_message = "the instance attributes rule matches EC2's ModifyInstanceAttribute calls"
  }

  assert {
    condition = (
      aws_cloudwatch_event_target.instance_attributes.rule == "fermix-server-instance-attributes" &&
      aws_cloudwatch_event_target.instance_attributes.arn == "arn:aws:sns:us-east-1:111122223333:fermix-owner-security-alerts" &&
      aws_cloudwatch_event_target.instance_attributes.input_transformer[0].input_paths == tomap({
        call    = "$.detail.eventName"
        who     = "$.detail.userIdentity.arn"
        request = "$.detail.requestParameters"
        error   = "$.detail.errorCode"
        when    = "$.detail.eventTime"
        from    = "$.detail.sourceIPAddress"
      }) &&
      alltrue([for v in ["<call>", "<who>", "<request>", "<error>", "<when>", "<from>"] : strcontains(aws_cloudwatch_event_target.instance_attributes.input_transformer[0].input_template, v)])
    )
    error_message = "an instance attribute's email goes to the alert topic and names who, the request, a refusal's error code and when"
  }
}

# A bucket-level write that can widen who reaches the snapshot or the state
# bucket, or a refused one: the deploy role writes the snapshot bucket's
# policy, IAM has no condition on a policy's contents, and an administrator
# can write the rest. By CloudTrail's names, which are not always IAM's or the API's
# (the PutPublicAccessBlock call is PutBucketPublicAccessBlock), held to the
# two buckets by name. Who, the request (the bucket and its new setting), the
# error code when refused, when and from where.
run "a_bucket_access_change_emails_the_alert_topic" {
  command = plan

  assert {
    condition = (
      aws_cloudwatch_event_rule.bucket_access.name == "fermix-server-bucket-access" &&
      jsondecode(aws_cloudwatch_event_rule.bucket_access.event_pattern) == {
        source        = ["aws.s3"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          eventName = [
            "PutBucketPolicy",
            "DeleteBucketPolicy",
            "PutBucketPublicAccessBlock",
            "DeleteBucketPublicAccessBlock",
            "PutBucketAcl",
            "PutBucketOwnershipControls",
            "DeleteBucketOwnershipControls",
            "PutBucketReplication",
          ]
          requestParameters = {
            bucketName = [
              "fermix-server-snapshots-111122223333-us-east-1",
              "fermix-server-state-111122223333-us-east-1",
            ]
          }
        }
      }
    )
    error_message = "the bucket access rule matches S3's policy, public access block, ACL, ownership and replication writes on the snapshot and state buckets alone"
  }

  assert {
    condition = (
      aws_cloudwatch_event_target.bucket_access.rule == "fermix-server-bucket-access" &&
      aws_cloudwatch_event_target.bucket_access.arn == "arn:aws:sns:us-east-1:111122223333:fermix-owner-security-alerts" &&
      aws_cloudwatch_event_target.bucket_access.input_transformer[0].input_paths == tomap({
        call    = "$.detail.eventName"
        who     = "$.detail.userIdentity.arn"
        request = "$.detail.requestParameters"
        error   = "$.detail.errorCode"
        when    = "$.detail.eventTime"
        from    = "$.detail.sourceIPAddress"
      }) &&
      alltrue([for v in ["<call>", "<who>", "<request>", "<error>", "<when>", "<from>"] : strcontains(aws_cloudwatch_event_target.bucket_access.input_transformer[0].input_template, v)])
    )
    error_message = "a bucket access email goes to the alert topic and names who, the request, a refusal's error code and when"
  }
}

# enable_guardduty: one detector per account and region, so bootstrap's.
run "guardduty_is_off_by_default" {
  command = plan

  assert {
    condition     = try(aws_guardduty_detector.this[0].enable, null) == null && try(aws_guardduty_detector_feature.runtime_monitoring[0].name, null) == null
    error_message = "without enable_guardduty there is no detector"
  }
}

run "guardduty_on_runs_ec2_runtime_monitoring" {
  command = plan

  variables {
    enable_guardduty = true
  }

  assert {
    condition = (
      aws_guardduty_detector.this[0].enable == true &&
      aws_guardduty_detector_feature.runtime_monitoring[0].name == "RUNTIME_MONITORING" &&
      aws_guardduty_detector_feature.runtime_monitoring[0].status == "ENABLED" &&
      one(aws_guardduty_detector_feature.runtime_monitoring[0].additional_configuration).name == "EC2_AGENT_MANAGEMENT" &&
      one(aws_guardduty_detector_feature.runtime_monitoring[0].additional_configuration).status == "ENABLED"
    )
    error_message = "enable_guardduty makes a detector with Runtime Monitoring for EC2, its agent managed by GuardDuty"
  }
}

# Whichever detector runs in the region (bootstrap's, one already there, an
# organization's), its findings reach the alert topic.
run "findings_email_the_alert_topic" {
  command = plan

  assert {
    condition = (
      aws_cloudwatch_event_rule.guardduty.name == "fermix-server-guardduty" &&
      jsondecode(aws_cloudwatch_event_rule.guardduty.event_pattern) == { source = ["aws.guardduty"], "detail-type" = ["GuardDuty Finding"] } &&
      aws_cloudwatch_event_target.guardduty.rule == "fermix-server-guardduty" &&
      aws_cloudwatch_event_target.guardduty.arn == "arn:aws:sns:us-east-1:111122223333:fermix-owner-security-alerts"
    )
    error_message = "every GuardDuty finding in the region goes to the security alert topic"
  }

  assert {
    condition = alltrue([
      for v in ["<severity>", "<title>", "<type>", "<resource>", "<id>"] : strcontains(aws_cloudwatch_event_target.guardduty.input_transformer[0].input_template, v)
    ])
    error_message = "the finding's email names its severity, title, type, resource and id"
  }
}

# The alerts must not go through server/'s own topic, which
# the deploy role manages and could silence. bootstrap's topic sits outside
# the role's fermix-server-* scope, under its own key, tagged bootstrap.
run "security_alerts_have_a_topic_the_deploy_role_cannot_reach" {
  command = plan

  assert {
    condition = (
      aws_sns_topic.security_alerts.name == "fermix-owner-security-alerts" &&
      aws_sns_topic.security_alerts.kms_master_key_id == aws_kms_key.security_alerts.arn &&
      aws_kms_alias.security_alerts.name == "alias/fermix-owner-security-alerts" &&
      aws_kms_key.security_alerts.enable_key_rotation == true &&
      try(aws_kms_key.security_alerts.tags["fermix-server-stack"], "bootstrap") == "bootstrap"
    )
    error_message = "the security alert topic is fermix-owner-security-alerts, encrypted with its own rotating key, which never carries the server tag"
  }

  assert {
    condition = (
      length(data.aws_iam_policy_document.security_alerts_topic.statement) == 1 &&
      data.aws_iam_policy_document.security_alerts_topic.statement[0].actions == toset(["sns:Publish"]) &&
      one(data.aws_iam_policy_document.security_alerts_topic.statement[0].principals).identifiers == toset(["events.amazonaws.com"]) &&
      anytrue([
        for c in data.aws_iam_policy_document.security_alerts_topic.statement[0].condition : c.test == "ArnEquals" && c.variable == "aws:SourceArn" && toset(c.values) == toset([
          "arn:aws:events:us-east-1:111122223333:rule/fermix-server-sessions",
          "arn:aws:events:us-east-1:111122223333:rule/fermix-server-commands",
          "arn:aws:events:us-east-1:111122223333:rule/fermix-server-guardduty",
          "arn:aws:events:us-east-1:111122223333:rule/fermix-server-instance-attributes",
          "arn:aws:events:us-east-1:111122223333:rule/fermix-server-bucket-access",
        ])
      ])
    )
    error_message = "the security alert topic takes messages from the five EventBridge rules alone, by their ARNs"
  }

  assert {
    condition = (
      length(data.aws_iam_policy_document.security_alerts_key.statement) == 2 &&
      anytrue([
        for s in data.aws_iam_policy_document.security_alerts_key.statement : (
          s.actions == toset(["kms:*"]) &&
          one(s.principals).identifiers == toset(["arn:aws:iam::111122223333:root"]) &&
          anytrue([for c in s.condition : c.test == "ArnEquals" && c.variable == "aws:PrincipalArn" && c.values == tolist(["arn:aws:iam::111122223333:role/managed/OwnerAdmin"])])
        )
      ]) &&
      anytrue([
        for s in data.aws_iam_policy_document.security_alerts_key.statement : (
          s.actions == toset(["kms:Decrypt", "kms:GenerateDataKey*"]) &&
          one(s.principals).identifiers == toset(["events.amazonaws.com"])
        )
      ])
    )
    error_message = "the security alert key lets admin_role_arn administer it and EventBridge publish with it, and no one else"
  }
}

run "each_alert_email_subscribes_to_the_security_topic" {
  command = plan

  variables {
    alert_emails = ["owner@example.test", "second@example.test"]
  }

  assert {
    condition = (
      length(aws_sns_topic_subscription.security_alerts) == 2 &&
      toset([for s in values(aws_sns_topic_subscription.security_alerts) : s.endpoint]) == toset(["owner@example.test", "second@example.test"]) &&
      alltrue([for s in values(aws_sns_topic_subscription.security_alerts) :
        s.protocol == "email" && s.topic_arn == "arn:aws:sns:us-east-1:111122223333:fermix-owner-security-alerts"
      ])
    )
    error_message = "each address in bootstrap's alert_emails subscribes to the security alert topic"
  }
}

run "no_alert_emails_no_subscription" {
  command = plan

  assert {
    condition     = length(aws_sns_topic_subscription.security_alerts) == 0
    error_message = "without alert_emails the security topic has no subscription"
  }
}

run "a_bad_alert_email_is_refused" {
  command = plan

  variables {
    alert_emails = ["owner@example.test", "owner@example.test, second@example.test"]
  }

  expect_failures = [var.alert_emails]
}
