# The account's events that reach the owner, through bootstrap's own security
# alert topic. Not through server/'s alert topic: the deploy role manages
# that one and could unsubscribe the owner or delete it, silencing the
# alerts that watch it. This topic is named outside the
# deploy role's fermix-server-* scope and encrypted with its own key, tagged
# bootstrap, which the role's tag-held KMS rights never reach; both stacks'
# tests hold that. Each address in alert_emails subscribes to it.
#
# The rules are bootstrap's, made with the owner's sign-in, because the
# deploy role's boundary has no room for EventBridge and the events are the
# account's: bootstrap does not know the instance id, so the session rule
# matches every session in this account and region, and the email names the
# instance. The deploy role reaches no EventBridge action.

locals {
  security_topic = "fermix-owner-security-alerts"
  security_rules = [for rule in ["sessions", "commands", "guardduty", "instance-attributes"] : "arn:${local.partition}:events:${var.region}:${local.account_id}:rule/${local.name_prefix}-${rule}"]
}

resource "aws_kms_key" "security_alerts" {
  description             = "fermix-owner-security-alerts: the account's security alerts topic"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.security_alerts_key.json
}

resource "aws_kms_alias" "security_alerts" {
  name          = "alias/${local.security_topic}"
  target_key_id = aws_kms_key.security_alerts.key_id
}

data "aws_iam_policy_document" "security_alerts_key" {
  # admin_role_arn alone, by its ARN: a role deleted and made again under
  # the same ARN keeps the key, so the rotation in RUNBOOK.md never locks it.
  statement {
    sid       = "TheOwnersSignInAdministers"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [var.admin_role_arn]
    }
  }

  statement {
    sid       = "EventBridgePublishesToTheTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic" "security_alerts" {
  name              = local.security_topic
  kms_master_key_id = aws_kms_key.security_alerts.arn
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts_topic.json
}

data "aws_iam_policy_document" "security_alerts_topic" {
  statement {
    sid       = "TheRulesPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = local.security_rules
    }
  }
}

# Terraform creates an email subscription as pending; the owner confirms it
# from the email AWS sends.
resource "aws_sns_topic_subscription" "security_alerts" {
  for_each = toset(var.alert_emails)

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# A Session Manager session starts or resumes: who, the request (a start
# names the instance, a resume the session), the session, when and from
# where. Seen through the trail (trail.tf) or any other that logs this
# region's management events.
resource "aws_cloudwatch_event_rule" "sessions" {
  name        = "${local.name_prefix}-sessions"
  description = "fermix-server: a Session Manager session starts or resumes in this account and region."

  event_pattern = jsonencode({
    source        = ["aws.ssm"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ssm.amazonaws.com"]
      eventName   = ["StartSession", "ResumeSession"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sessions" {
  rule      = aws_cloudwatch_event_rule.sessions.name
  target_id = "alert-topic"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      call    = "$.detail.eventName"
      who     = "$.detail.userIdentity.arn"
      request = "$.detail.requestParameters"
      session = "$.detail.responseElements.sessionId"
      when    = "$.detail.eventTime"
      from    = "$.detail.sourceIPAddress"
    }

    # One quoted string per line: EventBridge sends the lines as text.
    input_template = <<-EOT
      "fermix-server: a Session Manager <call>."
      "Who: <who>"
      "Request: <request>"
      "Session: <session>"
      "When: <when>, from <from>"
    EOT
  }
}

# A Run Command command, which runs as root on its instances and is no
# session: who, the request (the instances or targets and the document; the
# commands themselves CloudTrail hides), the command id, when and from where.
resource "aws_cloudwatch_event_rule" "commands" {
  name        = "${local.name_prefix}-commands"
  description = "fermix-server: a Run Command command is sent in this account and region."

  event_pattern = jsonencode({
    source        = ["aws.ssm"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ssm.amazonaws.com"]
      eventName   = ["SendCommand"]
    }
  })
}

resource "aws_cloudwatch_event_target" "commands" {
  rule      = aws_cloudwatch_event_rule.commands.name
  target_id = "alert-topic"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      call    = "$.detail.eventName"
      who     = "$.detail.userIdentity.arn"
      request = "$.detail.requestParameters"
      command = "$.detail.responseElements.command.commandId"
      when    = "$.detail.eventTime"
      from    = "$.detail.sourceIPAddress"
    }

    input_template = <<-EOT
      "fermix-server: a Run Command <call>."
      "Who: <who>"
      "Request: <request>"
      "Command: <command>"
      "When: <when>, from <from>"
    EOT
  }
}

# An instance attribute changes, or a change is refused: the user data is code
# the instance runs at its next boot, with no session or command to email,
# and the deploy role is denied it (denies.tf); termination protection and
# the type are what server/'s own applies change. Who, the request (the
# instance and the attribute; CloudTrail hides user data), the error code
# when refused, when and from where. bootstrap does not know the instance id,
# so every instance in this account and region; the email names it.
resource "aws_cloudwatch_event_rule" "instance_attributes" {
  name        = "${local.name_prefix}-instance-attributes"
  description = "fermix-server: an EC2 instance attribute is changed, or a change refused, in this account and region."

  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["ModifyInstanceAttribute"]
    }
  })
}

resource "aws_cloudwatch_event_target" "instance_attributes" {
  rule      = aws_cloudwatch_event_rule.instance_attributes.name
  target_id = "alert-topic"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      call    = "$.detail.eventName"
      who     = "$.detail.userIdentity.arn"
      request = "$.detail.requestParameters"
      error   = "$.detail.errorCode"
      when    = "$.detail.eventTime"
      from    = "$.detail.sourceIPAddress"
    }

    input_template = <<-EOT
      "fermix-server: an EC2 <call>."
      "Who: <who>"
      "Request: <request>"
      "If refused: <error>"
      "When: <when>, from <from>"
    EOT
  }
}
